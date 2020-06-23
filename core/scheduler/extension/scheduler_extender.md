Kubernetes Scheduler Extensibility - Scheduler extender
=======================================================

目前Kubernetes支持四种方式实现客户自定义的调度算法(预选&优选)，如下：

* default-scheduler recoding: 直接在Kubernetes默认scheduler基础上进行添加，然后重新编译kube-scheduler
* standalone: 实现一个与kube-scheduler平行的custom scheduler，和默认kube-scheduler一起运行在集群中
* scheduler extender: 实现一个"scheduler extender"，kube-scheduler会调用它(http/https)作为默认调度算法(预选&优选&bind)的补充
* scheduler framework: 实现scheduler framework plugins，重新编译kube-scheduler，类似于第一种方案，但是更加标准化，插件化

本文介绍前面三种方法，对于scheduler framework，也就是目前Kubernetes推荐扩展的方式，单独分一章进行讲解

#### default-scheduler recoding

这里我们先分析一下kube-scheduler调度相关入口：

* 设置默认预选&优选策略

见defaultPredicates以及defaultPriorities(k8s.io/kubernetes/pkg/scheduler/algorithmprovider/defaults/defaults.go)：

```go
func init() {
	registerAlgorithmProvider(defaultPredicates(), defaultPriorities())
}

func defaultPredicates() sets.String {
	return sets.NewString(
		predicates.NoVolumeZoneConflictPred,
		predicates.MaxEBSVolumeCountPred,
		predicates.MaxGCEPDVolumeCountPred,
		predicates.MaxAzureDiskVolumeCountPred,
		predicates.MaxCSIVolumeCountPred,
		predicates.MatchInterPodAffinityPred,
		predicates.NoDiskConflictPred,
		predicates.GeneralPred,
		predicates.PodToleratesNodeTaintsPred,
		predicates.CheckVolumeBindingPred,
		predicates.CheckNodeUnschedulablePred,
	)
}

func defaultPriorities() sets.String {
	return sets.NewString(
		priorities.SelectorSpreadPriority,
		priorities.InterPodAffinityPriority,
		priorities.LeastRequestedPriority,
		priorities.BalancedResourceAllocation,
		priorities.NodePreferAvoidPodsPriority,
		priorities.NodeAffinityPriority,
		priorities.TaintTolerationPriority,
		priorities.ImageLocalityPriority,
	)
}

func registerAlgorithmProvider(predSet, priSet sets.String) {
	// Registers algorithm providers. By default we use 'DefaultProvider', but user can specify one to be used
	// by specifying flag.
	scheduler.RegisterAlgorithmProvider(scheduler.DefaultProvider, predSet, priSet)
	// Cluster autoscaler friendly scheduling algorithm.
	scheduler.RegisterAlgorithmProvider(ClusterAutoscalerProvider, predSet,
		copyAndReplace(priSet, priorities.LeastRequestedPriority, priorities.MostRequestedPriority))
}

const (
	// DefaultProvider defines the default algorithm provider name.
	DefaultProvider = "DefaultProvider"
)
```

* 注册预选和优选相关处理函数

注册预选函数(k8s.io/kubernetes/pkg/scheduler/algorithmprovider/defaults/register_predicates.go)：

```go
func init() {
    ...
	// Fit is determined by resource availability.
	// This predicate is actually a default predicate, because it is invoked from
	// predicates.GeneralPredicates()
	scheduler.RegisterFitPredicate(predicates.PodFitsResourcesPred, predicates.PodFitsResources)
}
```

注册优选函数(k8s.io/kubernetes/pkg/scheduler/algorithmprovider/defaults/register_priorities.go)：

```go
func init() {
    ...
	// Prioritizes nodes that have labels matching NodeAffinity
	scheduler.RegisterPriorityMapReduceFunction(priorities.NodeAffinityPriority, priorities.CalculateNodeAffinityPriorityMap, priorities.CalculateNodeAffinityPriorityReduce, 1)
}
```

* 编写预选和优选处理函数

PodFitsResourcesPred对应的预选函数如下(k8s.io/kubernetes/pkg/scheduler/algorithm/predicates/predicates.go)：

```go
// PodFitsResources checks if a node has sufficient resources, such as cpu, memory, gpu, opaque int resources etc to run a pod.
// First return value indicates whether a node has sufficient resources to run a pod while the second return value indicates the
// predicate failure reasons if the node has insufficient resources to run the pod.
func PodFitsResources(pod *v1.Pod, meta Metadata, nodeInfo *schedulernodeinfo.NodeInfo) (bool, []PredicateFailureReason, error) {
	node := nodeInfo.Node()
	if node == nil {
		return false, nil, fmt.Errorf("node not found")
	}

	var predicateFails []PredicateFailureReason
	allowedPodNumber := nodeInfo.AllowedPodNumber()
	if len(nodeInfo.Pods())+1 > allowedPodNumber {
		predicateFails = append(predicateFails, NewInsufficientResourceError(v1.ResourcePods, 1, int64(len(nodeInfo.Pods())), int64(allowedPodNumber)))
	}

	// No extended resources should be ignored by default.
	ignoredExtendedResources := sets.NewString()

	var podRequest *schedulernodeinfo.Resource
	if predicateMeta, ok := meta.(*predicateMetadata); ok && predicateMeta.podFitsResourcesMetadata != nil {
		podRequest = predicateMeta.podFitsResourcesMetadata.podRequest
		if predicateMeta.podFitsResourcesMetadata.ignoredExtendedResources != nil {
			ignoredExtendedResources = predicateMeta.podFitsResourcesMetadata.ignoredExtendedResources
		}
	} else {
		// We couldn't parse metadata - fallback to computing it.
		podRequest = GetResourceRequest(pod)
	}
	if podRequest.MilliCPU == 0 &&
		podRequest.Memory == 0 &&
		podRequest.EphemeralStorage == 0 &&
		len(podRequest.ScalarResources) == 0 {
		return len(predicateFails) == 0, predicateFails, nil
	}

	allocatable := nodeInfo.AllocatableResource()
	if allocatable.MilliCPU < podRequest.MilliCPU+nodeInfo.RequestedResource().MilliCPU {
		predicateFails = append(predicateFails, NewInsufficientResourceError(v1.ResourceCPU, podRequest.MilliCPU, nodeInfo.RequestedResource().MilliCPU, allocatable.MilliCPU))
	}
	if allocatable.Memory < podRequest.Memory+nodeInfo.RequestedResource().Memory {
		predicateFails = append(predicateFails, NewInsufficientResourceError(v1.ResourceMemory, podRequest.Memory, nodeInfo.RequestedResource().Memory, allocatable.Memory))
	}
	if allocatable.EphemeralStorage < podRequest.EphemeralStorage+nodeInfo.RequestedResource().EphemeralStorage {
		predicateFails = append(predicateFails, NewInsufficientResourceError(v1.ResourceEphemeralStorage, podRequest.EphemeralStorage, nodeInfo.RequestedResource().EphemeralStorage, allocatable.EphemeralStorage))
	}

	for rName, rQuant := range podRequest.ScalarResources {
		if v1helper.IsExtendedResourceName(rName) {
			// If this resource is one of the extended resources that should be
			// ignored, we will skip checking it.
			if ignoredExtendedResources.Has(string(rName)) {
				continue
			}
		}
		if allocatable.ScalarResources[rName] < rQuant+nodeInfo.RequestedResource().ScalarResources[rName] {
			predicateFails = append(predicateFails, NewInsufficientResourceError(rName, podRequest.ScalarResources[rName], nodeInfo.RequestedResource().ScalarResources[rName], allocatable.ScalarResources[rName]))
		}
	}

	if klog.V(10) {
		if len(predicateFails) == 0 {
			// We explicitly don't do klog.V(10).Infof() to avoid computing all the parameters if this is
			// not logged. There is visible performance gain from it.
			klog.Infof("Schedule Pod %+v on Node %+v is allowed, Node is running only %v out of %v Pods.",
				podName(pod), node.Name, len(nodeInfo.Pods()), allowedPodNumber)
		}
	}
	return len(predicateFails) == 0, predicateFails, nil
}
```

优选NodeAffinityPriority对应的Map与Reduce函数(k8s.io/kubernetes/pkg/scheduler/algorithm/priorities/node_affinity.go)如下：

```go
// CalculateNodeAffinityPriorityMap prioritizes nodes according to node affinity scheduling preferences
// indicated in PreferredDuringSchedulingIgnoredDuringExecution. Each time a node matches a preferredSchedulingTerm,
// it will get an add of preferredSchedulingTerm.Weight. Thus, the more preferredSchedulingTerms
// the node satisfies and the more the preferredSchedulingTerm that is satisfied weights, the higher
// score the node gets.
func CalculateNodeAffinityPriorityMap(pod *v1.Pod, meta interface{}, nodeInfo *schedulernodeinfo.NodeInfo) (framework.NodeScore, error) {
	node := nodeInfo.Node()
	if node == nil {
		return framework.NodeScore{}, fmt.Errorf("node not found")
	}

	// default is the podspec.
	affinity := pod.Spec.Affinity
	if priorityMeta, ok := meta.(*priorityMetadata); ok {
		// We were able to parse metadata, use affinity from there.
		affinity = priorityMeta.affinity
	}

	var count int32
	// A nil element of PreferredDuringSchedulingIgnoredDuringExecution matches no objects.
	// An element of PreferredDuringSchedulingIgnoredDuringExecution that refers to an
	// empty PreferredSchedulingTerm matches all objects.
	if affinity != nil && affinity.NodeAffinity != nil && affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution != nil {
		// Match PreferredDuringSchedulingIgnoredDuringExecution term by term.
		for i := range affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution {
			preferredSchedulingTerm := &affinity.NodeAffinity.PreferredDuringSchedulingIgnoredDuringExecution[i]
			if preferredSchedulingTerm.Weight == 0 {
				continue
			}

			// TODO: Avoid computing it for all nodes if this becomes a performance problem.
			nodeSelector, err := v1helper.NodeSelectorRequirementsAsSelector(preferredSchedulingTerm.Preference.MatchExpressions)
			if err != nil {
				return framework.NodeScore{}, err
			}
			if nodeSelector.Matches(labels.Set(node.Labels)) {
				count += preferredSchedulingTerm.Weight
			}
		}
	}

	return framework.NodeScore{
		Name:  node.Name,
		Score: int64(count),
	}, nil
}

// CalculateNodeAffinityPriorityReduce is a reduce function for node affinity priority calculation.
var CalculateNodeAffinityPriorityReduce = NormalizeReduce(framework.MaxNodeScore, false)
```

* 相关使用

接下来我们看一下kube-scheduler是如何与上述这些代码结合起来的：

```go
// k8s.io/kubernetes/pkg/scheduler/scheduler.go
// New returns a Scheduler
func New(client clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	podInformer coreinformers.PodInformer,
	recorder events.EventRecorder,
	stopCh <-chan struct{},
	opts ...Option) (*Scheduler, error) {

	configurator := &Configurator{
		client:                         client,
		informerFactory:                informerFactory,
		podInformer:                    podInformer,
		volumeBinder:                   volumeBinder,
		schedulerCache:                 schedulerCache,
		StopEverything:                 stopEverything,
		hardPodAffinitySymmetricWeight: options.hardPodAffinitySymmetricWeight,
		disablePreemption:              options.disablePreemption,
		percentageOfNodesToScore:       options.percentageOfNodesToScore,
		bindTimeoutSeconds:             options.bindTimeoutSeconds,
		podInitialBackoffSeconds:       options.podInitialBackoffSeconds,
		podMaxBackoffSeconds:           options.podMaxBackoffSeconds,
		enableNonPreempting:            utilfeature.DefaultFeatureGate.Enabled(kubefeatures.NonPreemptingPriority),
		registry:                       registry,
		plugins:                        options.frameworkPlugins,
		pluginConfig:                   options.frameworkPluginConfig,
		pluginConfigProducerRegistry:   options.frameworkConfigProducerRegistry,
		nodeInfoSnapshot:               snapshot,
		algorithmFactoryArgs: AlgorithmFactoryArgs{
			SharedLister:                   snapshot,
			InformerFactory:                informerFactory,
			VolumeBinder:                   volumeBinder,
			HardPodAffinitySymmetricWeight: options.hardPodAffinitySymmetricWeight,
		},
		configProducerArgs: &frameworkplugins.ConfigProducerArgs{},
	}

	var sched *Scheduler
	source := options.schedulerAlgorithmSource
	switch {
	case source.Provider != nil:
		// Create the config from a named algorithm provider.
		sc, err := configurator.CreateFromProvider(*source.Provider)
		if err != nil {
			return nil, fmt.Errorf("couldn't create scheduler using provider %q: %v", *source.Provider, err)
		}
		sched = sc
	case source.Policy != nil:
		// Create the config from a user specified policy source.
		policy := &schedulerapi.Policy{}
		switch {
		case source.Policy.File != nil:
			if err := initPolicyFromFile(source.Policy.File.Path, policy); err != nil {
				return nil, err
			}
		case source.Policy.ConfigMap != nil:
			if err := initPolicyFromConfigMap(client, source.Policy.ConfigMap, policy); err != nil {
				return nil, err
			}
		}
		sc, err := configurator.CreateFromConfig(*policy)
		if err != nil {
			return nil, fmt.Errorf("couldn't create scheduler from policy: %v", err)
		}
		sched = sc
	default:
		return nil, fmt.Errorf("unsupported algorithm source: %v", source)
	}
	// Additional tweaks to the config produced by the configurator.
	sched.Recorder = recorder
	sched.DisablePreemption = options.disablePreemption
	sched.StopEverything = stopEverything
	sched.podConditionUpdater = &podConditionUpdaterImpl{client}
	sched.podPreemptor = &podPreemptorImpl{client}
	sched.scheduledPodsHasSynced = podInformer.Informer().HasSynced

	AddAllEventHandlers(sched, options.schedulerName, informerFactory, podInformer)
	return sched, nil
}

...
// k8s.io/kubernetes/pkg/scheduler/factory.go
// CreateFromConfig creates a scheduler from the configuration file
func (c *Configurator) CreateFromConfig(policy schedulerapi.Policy) (*Scheduler, error) {
	klog.V(2).Infof("Creating scheduler from configuration: %v", policy)

	// validate the policy configuration
	if err := validation.ValidatePolicy(policy); err != nil {
		return nil, err
	}

	predicateKeys := sets.NewString()
	if policy.Predicates == nil {
		klog.V(2).Infof("Using predicates from algorithm provider '%v'", DefaultProvider)
		provider, err := GetAlgorithmProvider(DefaultProvider)
		if err != nil {
			return nil, err
		}
		predicateKeys = provider.FitPredicateKeys
	} else {
		for _, predicate := range policy.Predicates {
			klog.V(2).Infof("Registering predicate: %s", predicate.Name)
			predicateKeys.Insert(RegisterCustomFitPredicate(predicate, c.configProducerArgs))
		}
	}

	priorityKeys := sets.NewString()
	if policy.Priorities == nil {
		klog.V(2).Infof("Using priorities from algorithm provider '%v'", DefaultProvider)
		provider, err := GetAlgorithmProvider(DefaultProvider)
		if err != nil {
			return nil, err
		}
		priorityKeys = provider.PriorityFunctionKeys
	} else {
		for _, priority := range policy.Priorities {
			if priority.Name == priorities.EqualPriority {
				klog.V(2).Infof("Skip registering priority: %s", priority.Name)
				continue
			}
			klog.V(2).Infof("Registering priority: %s", priority.Name)
			priorityKeys.Insert(RegisterCustomPriorityFunction(priority, c.configProducerArgs))
		}
	}
    ...
	// When AlwaysCheckAllPredicates is set to true, scheduler checks all the configured
	// predicates even after one or more of them fails.
	if policy.AlwaysCheckAllPredicates {
		c.alwaysCheckAllPredicates = policy.AlwaysCheckAllPredicates
	}

	return c.CreateFromKeys(predicateKeys, priorityKeys, extenders)
}

...
// CreateFromKeys creates a scheduler from a set of registered fit predicate keys and priority keys.
func (c *Configurator) CreateFromKeys(predicateKeys, priorityKeys sets.String, extenders []algorithm.SchedulerExtender) (*Scheduler, error) {
	klog.V(2).Infof("Creating scheduler with fit predicates '%v' and priority functions '%v'", predicateKeys, priorityKeys)

	predicateFuncs, pluginsForPredicates, pluginConfigForPredicates, err := c.getPredicateConfigs(predicateKeys)
	if err != nil {
		return nil, err
	}

	priorityConfigs, pluginsForPriorities, pluginConfigForPriorities, err := c.getPriorityConfigs(priorityKeys)
	if err != nil {
		return nil, err
	}
    ...

	algo := core.NewGenericScheduler(
		c.schedulerCache,
		podQueue,
		predicateFuncs,
		predicateMetaProducer,
		priorityConfigs,
		priorityMetaProducer,
		c.nodeInfoSnapshot,
		framework,
		extenders,
		c.volumeBinder,
		c.informerFactory.Core().V1().PersistentVolumeClaims().Lister(),
		GetPodDisruptionBudgetLister(c.informerFactory),
		c.alwaysCheckAllPredicates,
		c.disablePreemption,
		c.percentageOfNodesToScore,
		c.enableNonPreempting,
	)

	return &Scheduler{
		SchedulerCache:  c.schedulerCache,
		Algorithm:       algo,
		GetBinder:       getBinderFunc(c.client, extenders),
		Framework:       framework,
		NextPod:         internalqueue.MakeNextPodFunc(podQueue),
		Error:           MakeDefaultErrorFunc(c.client, podQueue, c.schedulerCache),
		StopEverything:  c.StopEverything,
		VolumeBinder:    c.volumeBinder,
		SchedulingQueue: podQueue,
		Plugins:         plugins,
		PluginConfig:    pluginConfig,
	}, nil
}

...
// getPredicateConfigs returns predicates configuration: ones that will run as fitPredicates and ones that will run
// as framework plugins. Specifically, a predicate will run as a framework plugin if a plugin config producer was
// registered for that predicate.
// Note that the framework executes plugins according to their order in the Plugins list, and so predicates run as plugins
// are added to the Plugins list according to the order specified in predicates.Ordering().
func (c *Configurator) getPredicateConfigs(predicateKeys sets.String) (map[string]predicates.FitPredicate, *schedulerapi.Plugins, []schedulerapi.PluginConfig, error) {
	allFitPredicates, err := getFitPredicateFunctions(predicateKeys, c.algorithmFactoryArgs)
	if err != nil {
		return nil, nil, nil, err
	}
    ...

	return asFitPredicates, &plugins, pluginConfig, nil
}

func getFitPredicateFunctions(names sets.String, args AlgorithmFactoryArgs) (map[string]predicates.FitPredicate, error) {
	schedulerFactoryMutex.RLock()
	defer schedulerFactoryMutex.RUnlock()

	fitPredicates := map[string]predicates.FitPredicate{}
	for _, name := range names.List() {
		factory, ok := fitPredicateMap[name]
		if !ok {
			return nil, fmt.Errorf("invalid predicate name %q specified - no corresponding function found", name)
		}
		fitPredicates[name] = factory(args)
	}

	// Always include mandatory fit predicates.
	for name := range mandatoryFitPredicates {
		if factory, found := fitPredicateMap[name]; found {
			fitPredicates[name] = factory(args)
		}
	}

	return fitPredicates, nil
}

...
// Fit is determined by resource availability.
// This predicate is actually a default predicate, because it is invoked from
// predicates.GeneralPredicates()
scheduler.RegisterFitPredicate(predicates.PodFitsResourcesPred, predicates.PodFitsResources)

...
// RegisterFitPredicate registers a fit predicate with the algorithm
// registry. Returns the name with which the predicate was registered.
func RegisterFitPredicate(name string, predicate predicates.FitPredicate) string {
	return RegisterFitPredicateFactory(name, func(AlgorithmFactoryArgs) predicates.FitPredicate { return predicate })
}

...
// RegisterFitPredicateFactory registers a fit predicate factory with the
// algorithm registry. Returns the name with which the predicate was registered.
func RegisterFitPredicateFactory(name string, predicateFactory FitPredicateFactory) string {
	schedulerFactoryMutex.Lock()
	defer schedulerFactoryMutex.Unlock()
	validateAlgorithmNameOrDie(name)
	fitPredicateMap[name] = predicateFactory
	return name
}

...
// getPriorityConfigs returns priorities configuration: ones that will run as priorities and ones that will run
// as framework plugins. Specifically, a priority will run as a framework plugin if a plugin config producer was
// registered for that priority.
func (c *Configurator) getPriorityConfigs(priorityKeys sets.String) ([]priorities.PriorityConfig, *schedulerapi.Plugins, []schedulerapi.PluginConfig, error) {
	allPriorityConfigs, err := getPriorityFunctionConfigs(priorityKeys, c.algorithmFactoryArgs)
	if err != nil {
		return nil, nil, nil, err
	}
    ...
	return priorityConfigs, &plugins, pluginConfig, nil
}

...
func getPriorityFunctionConfigs(names sets.String, args AlgorithmFactoryArgs) ([]priorities.PriorityConfig, error) {
	schedulerFactoryMutex.RLock()
	defer schedulerFactoryMutex.RUnlock()

	var configs []priorities.PriorityConfig
	for _, name := range names.List() {
		factory, ok := priorityFunctionMap[name]
		if !ok {
			return nil, fmt.Errorf("invalid priority name %s specified - no corresponding function found", name)
		}
		mapFunction, reduceFunction := factory.MapReduceFunction(args)
		configs = append(configs, priorities.PriorityConfig{
			Name:   name,
			Map:    mapFunction,
			Reduce: reduceFunction,
			Weight: factory.Weight,
		})
	}
	if err := validateSelectedConfigs(configs); err != nil {
		return nil, err
	}
	return configs, nil
}

...
// Prioritizes nodes that have labels matching NodeAffinity
scheduler.RegisterPriorityMapReduceFunction(priorities.NodeAffinityPriority, priorities.CalculateNodeAffinityPriorityMap, priorities.CalculateNodeAffinityPriorityReduce, 1)

...
// RegisterPriorityMapReduceFunction registers a priority function with the algorithm registry. Returns the name,
// with which the function was registered.
func RegisterPriorityMapReduceFunction(
	name string,
	mapFunction priorities.PriorityMapFunction,
	reduceFunction priorities.PriorityReduceFunction,
	weight int) string {
	return RegisterPriorityConfigFactory(name, PriorityConfigFactory{
		MapReduceFunction: func(AlgorithmFactoryArgs) (priorities.PriorityMapFunction, priorities.PriorityReduceFunction) {
			return mapFunction, reduceFunction
		},
		Weight: int64(weight),
	})
}

...
// RegisterPriorityConfigFactory registers a priority config factory with its name.
func RegisterPriorityConfigFactory(name string, pcf PriorityConfigFactory) string {
	schedulerFactoryMutex.Lock()
	defer schedulerFactoryMutex.Unlock()
	validateAlgorithmNameOrDie(name)
	priorityFunctionMap[name] = pcf
	return name
}

...
// podFitsOnNode checks whether a node given by NodeInfo satisfies the given predicate functions.
// For given pod, podFitsOnNode will check if any equivalent pod exists and try to reuse its cached
// predicate results as possible.
// This function is called from two different places: Schedule and Preempt.
// When it is called from Schedule, we want to test whether the pod is schedulable
// on the node with all the existing pods on the node plus higher and equal priority
// pods nominated to run on the node.
// When it is called from Preempt, we should remove the victims of preemption and
// add the nominated pods. Removal of the victims is done by SelectVictimsOnNode().
// It removes victims from meta and NodeInfo before calling this function.
func (g *genericScheduler) podFitsOnNode(
	ctx context.Context,
	state *framework.CycleState,
	pod *v1.Pod,
	meta predicates.Metadata,
	info *schedulernodeinfo.NodeInfo,
	alwaysCheckAllPredicates bool,
) (bool, []predicates.PredicateFailureReason, *framework.Status, error) {
	var failedPredicates []predicates.PredicateFailureReason
	var status *framework.Status

	podsAdded := false
	// We run predicates twice in some cases. If the node has greater or equal priority
	// nominated pods, we run them when those pods are added to meta and nodeInfo.
	// If all predicates succeed in this pass, we run them again when these
	// nominated pods are not added. This second pass is necessary because some
	// predicates such as inter-pod affinity may not pass without the nominated pods.
	// If there are no nominated pods for the node or if the first run of the
	// predicates fail, we don't run the second pass.
	// We consider only equal or higher priority pods in the first pass, because
	// those are the current "pod" must yield to them and not take a space opened
	// for running them. It is ok if the current "pod" take resources freed for
	// lower priority pods.
	// Requiring that the new pod is schedulable in both circumstances ensures that
	// we are making a conservative decision: predicates like resources and inter-pod
	// anti-affinity are more likely to fail when the nominated pods are treated
	// as running, while predicates like pod affinity are more likely to fail when
	// the nominated pods are treated as not running. We can't just assume the
	// nominated pods are running because they are not running right now and in fact,
	// they may end up getting scheduled to a different node.
	for i := 0; i < 2; i++ {
		metaToUse := meta
		stateToUse := state
		nodeInfoToUse := info
		if i == 0 {
			var err error
			podsAdded, metaToUse, stateToUse, nodeInfoToUse, err = g.addNominatedPods(ctx, pod, meta, state, info)
			if err != nil {
				return false, []predicates.PredicateFailureReason{}, nil, err
			}
		} else if !podsAdded || len(failedPredicates) != 0 || !status.IsSuccess() {
			break
		}

		for _, predicateKey := range predicates.Ordering() {
			var (
				fit     bool
				reasons []predicates.PredicateFailureReason
				err     error
			)

			if predicate, exist := g.predicates[predicateKey]; exist {
				fit, reasons, err = predicate(pod, metaToUse, nodeInfoToUse)
				if err != nil {
					return false, []predicates.PredicateFailureReason{}, nil, err
				}

				if !fit {
					// eCache is available and valid, and predicates result is unfit, record the fail reasons
					failedPredicates = append(failedPredicates, reasons...)
					// if alwaysCheckAllPredicates is false, short circuit all predicates when one predicate fails.
					if !alwaysCheckAllPredicates {
						klog.V(5).Infoln("since alwaysCheckAllPredicates has not been set, the predicate " +
							"evaluation is short circuited and there are chances " +
							"of other predicates failing as well.")
						break
					}
				}
			}
		}

		status = g.framework.RunFilterPlugins(ctx, stateToUse, pod, nodeInfoToUse)
		if !status.IsSuccess() && !status.IsUnschedulable() {
			return false, failedPredicates, status, status.AsError()
		}
	}

	return len(failedPredicates) == 0 && status.IsSuccess(), failedPredicates, status, nil
}

...
// prioritizeNodes prioritizes the nodes by running the individual priority functions in parallel.
// Each priority function is expected to set a score of 0-10
// 0 is the lowest priority score (least preferred node) and 10 is the highest
// Each priority function can also have its own weight
// The node scores returned by the priority function are multiplied by the weights to get weighted scores
// All scores are finally combined (added) to get the total weighted scores of all nodes
func (g *genericScheduler) prioritizeNodes(
	ctx context.Context,
	state *framework.CycleState,
	pod *v1.Pod,
	meta interface{},
	nodes []*v1.Node,
) (framework.NodeScoreList, error) {
	// If no priority configs are provided, then all nodes will have a score of one.
	// This is required to generate the priority list in the required format
	if len(g.prioritizers) == 0 && len(g.extenders) == 0 && !g.framework.HasScorePlugins() {
		result := make(framework.NodeScoreList, 0, len(nodes))
		for i := range nodes {
			result = append(result, framework.NodeScore{
				Name:  nodes[i].Name,
				Score: 1,
			})
		}
		return result, nil
	}

	var (
		mu   = sync.Mutex{}
		wg   = sync.WaitGroup{}
		errs []error
	)
	appendError := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		errs = append(errs, err)
	}

	results := make([]framework.NodeScoreList, len(g.prioritizers))

	for i := range g.prioritizers {
		results[i] = make(framework.NodeScoreList, len(nodes))
	}

	workqueue.ParallelizeUntil(context.TODO(), 16, len(nodes), func(index int) {
		nodeInfo := g.nodeInfoSnapshot.NodeInfoMap[nodes[index].Name]
		for i := range g.prioritizers {
			var err error
			results[i][index], err = g.prioritizers[i].Map(pod, meta, nodeInfo)
			if err != nil {
				appendError(err)
				results[i][index].Name = nodes[index].Name
			}
		}
	})

	for i := range g.prioritizers {
		if g.prioritizers[i].Reduce == nil {
			continue
		}
		wg.Add(1)
		go func(index int) {
			metrics.SchedulerGoroutines.WithLabelValues("prioritizing_mapreduce").Inc()
			defer func() {
				metrics.SchedulerGoroutines.WithLabelValues("prioritizing_mapreduce").Dec()
				wg.Done()
			}()
			if err := g.prioritizers[index].Reduce(pod, meta, g.nodeInfoSnapshot, results[index]); err != nil {
				appendError(err)
			}
			if klog.V(10) {
				for _, hostPriority := range results[index] {
					klog.Infof("%v -> %v: %v, Score: (%d)", util.GetPodFullName(pod), hostPriority.Name, g.prioritizers[index].Name, hostPriority.Score)
				}
			}
		}(i)
	}
	// Wait for all computations to be finished.
	wg.Wait()
	if len(errs) != 0 {
		return framework.NodeScoreList{}, errors.NewAggregate(errs)
	}

	// Run the Score plugins.
	state.Write(migration.PrioritiesStateKey, &migration.PrioritiesStateData{Reference: meta})
	scoresMap, scoreStatus := g.framework.RunScorePlugins(ctx, state, pod, nodes)
	if !scoreStatus.IsSuccess() {
		return framework.NodeScoreList{}, scoreStatus.AsError()
	}

	// Summarize all scores.
	result := make(framework.NodeScoreList, 0, len(nodes))

	for i := range nodes {
		result = append(result, framework.NodeScore{Name: nodes[i].Name, Score: 0})
		for j := range g.prioritizers {
			result[i].Score += results[j][i].Score * g.prioritizers[j].Weight
		}

		for j := range scoresMap {
			result[i].Score += scoresMap[j][i].Score
		}
	}

	if len(g.extenders) != 0 && nodes != nil {
		combinedScores := make(map[string]int64, len(g.nodeInfoSnapshot.NodeInfoList))
		for i := range g.extenders {
			if !g.extenders[i].IsInterested(pod) {
				continue
			}
			wg.Add(1)
			go func(extIndex int) {
				metrics.SchedulerGoroutines.WithLabelValues("prioritizing_extender").Inc()
				defer func() {
					metrics.SchedulerGoroutines.WithLabelValues("prioritizing_extender").Dec()
					wg.Done()
				}()
				prioritizedList, weight, err := g.extenders[extIndex].Prioritize(pod, nodes)
				if err != nil {
					// Prioritization errors from extender can be ignored, let k8s/other extenders determine the priorities
					return
				}
				mu.Lock()
				for i := range *prioritizedList {
					host, score := (*prioritizedList)[i].Host, (*prioritizedList)[i].Score
					if klog.V(10) {
						klog.Infof("%v -> %v: %v, Score: (%d)", util.GetPodFullName(pod), host, g.extenders[extIndex].Name(), score)
					}
					combinedScores[host] += score * weight
				}
				mu.Unlock()
			}(i)
		}
		// wait for all go routines to finish
		wg.Wait()
		for i := range result {
			// MaxExtenderPriority may diverge from the max priority used in the scheduler and defined by MaxNodeScore,
			// therefore we need to scale the score returned by extenders to the score range used by the scheduler.
			result[i].Score += combinedScores[result[i].Name] * (framework.MaxNodeScore / extenderv1.MaxExtenderPriority)
		}
	}

	if klog.V(10) {
		for i := range result {
			klog.Infof("Host %s => Score %d", result[i].Name, result[i].Score)
		}
	}
	return result, nil
}
```

综上，如果要在kube-scheduler基础上添加策略，则按照如下步骤进行添加：

* 设置默认预选&优选策略：defaultPredicates以及defaultPriorities(k8s.io/kubernetes/pkg/scheduler/algorithmprovider/defaults/defaults.go)
* 注册预选和优选相关处理函数：注册预选函数(k8s.io/kubernetes/pkg/scheduler/algorithmprovider/defaults/register_predicates.go)；注册优选函数(k8s.io/kubernetes/pkg/scheduler/algorithmprovider/defaults/register_priorities.go)
* 编写预选和优选处理函数：编写预选函数(k8s.io/kubernetes/pkg/scheduler/algorithm/predicates/predicates.go)；编写优选函数Map+Reduce(k8s.io/kubernetes/pkg/scheduler/algorithm/priorities/xxx.go)
* 除了默认设置预选&优选外，还可以手动通过命令行`--policy-config-file`指定调度策略(会覆盖默认策略)，例如[examples/scheduler-policy-config.json](https://github.com/kubernetes/examples/blob/master/staging/scheduler-policy/scheduler-policy-config.json) 

#### standalone



#### scheduler extender

## Refs

* [Scheduler extender](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/scheduler_extender.md)