Kubernetes Scheduler Extensibility - Scheduler extender
=======================================================

目前Kubernetes支持四种方式实现客户自定义的调度算法(预选&优选)，如下：

* default-scheduler recoding: 直接在Kubernetes默认scheduler基础上进行添加，然后重新编译kube-scheduler
* standalone: 实现一个与kube-scheduler平行的custom scheduler，单独或者和默认kube-scheduler一起运行在集群中
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

相比recoding只修改简单代码，standalone在kube-scheduler基础上进行重度二次定制，这种方式优缺点如下：

* Pros
  * 满足对scheduler最大程度的重构&定制
* Cons
  * 实际工程中如果只是想添加预选或者优选策略，则会切换到第一种方案，不会单独开发和部署一个scheduler
  * 二次定制scheduler开发难度较大(至少对scheduler代码非常熟悉)，且对Kubernetes集群影响较大(无论是单独部署，还是并列部署)，后续升级和维护成本较高
  * 可能会产生调度冲突问题，在同时部署两个scheduler时，可能会出现一个scheduler bind的时候实际资源已经被另一个scheduler分配了

因此建议在其它方案满足不了扩展需求时，才采用standalone方案，且生产环境仅部署一个scheduler

#### scheduler extender

对于Kubernetes项目来说，它很喜欢开发者使用并向它提bug或者PR，但是不建议开发者直接修改Kubernetes核心代码，因为这样做会影响Kubernetes本身的代码质量以及稳定性。因此Kubernetes希望尽可能通过外围的方式来解决客户自定义的需求

其实任何好的项目都应该这样思考：尽可能抽取核心代码，这部分代码不应该经常变动或者说只能由maintainer改动(提高代码质量，减小项目本身开发&运维成本)；将第三方客户需求尽可能提取到外围解决(满足客户自由)，例如：插件的形式(eg: CNI，CRI，CSI and scheduler framework etc)

上面介绍的`default-scheduler recoding`以及`standalone`方案都属于侵入式的方案，不太优雅；而scheduler extender以及scheduler framework属于非侵入式的方案，这里重点介绍scheduler extender

scheduler extender类似于webhook，kube-scheduler会在默认调度算法执行完成后以http/https的方式调用extender，extender server完成自定义的预选&优选逻辑，并返回规定字段给scheduler，scheduler结合这些信息进行最终的调度裁决，从而完成基于extender实现扩展的逻辑

scheduler extender适用于调度策略与非标准kube-scheduler管理资源相关的场景，当然你也可以使用extender完成与上述两种方式同样的功能

下面我们结合代码说明extender的使用原理：

* 定义scheduler extender

在使用extender之前，我们必须在scheduler policy配置文件中定义extender相关信息，如下：

```go
// k8s.io/kubernetes/pkg/scheduler/apis/config/legacy_types.go
// Extender holds the parameters used to communicate with the extender. If a verb is unspecified/empty,
// it is assumed that the extender chose not to provide that extension.
type Extender struct {
	// URLPrefix at which the extender is available
	URLPrefix string
	// Verb for the filter call, empty if not supported. This verb is appended to the URLPrefix when issuing the filter call to extender.
	FilterVerb string
	// Verb for the preempt call, empty if not supported. This verb is appended to the URLPrefix when issuing the preempt call to extender.
	PreemptVerb string
	// Verb for the prioritize call, empty if not supported. This verb is appended to the URLPrefix when issuing the prioritize call to extender.
	PrioritizeVerb string
	// The numeric multiplier for the node scores that the prioritize call generates.
	// The weight should be a positive integer
	Weight int64
	// Verb for the bind call, empty if not supported. This verb is appended to the URLPrefix when issuing the bind call to extender.
	// If this method is implemented by the extender, it is the extender's responsibility to bind the pod to apiserver. Only one extender
	// can implement this function.
	BindVerb string
	// EnableHTTPS specifies whether https should be used to communicate with the extender
	EnableHTTPS bool
	// TLSConfig specifies the transport layer security config
	TLSConfig *ExtenderTLSConfig
	// HTTPTimeout specifies the timeout duration for a call to the extender. Filter timeout fails the scheduling of the pod. Prioritize
	// timeout is ignored, k8s/other extenders priorities are used to select the node.
	HTTPTimeout time.Duration
	// NodeCacheCapable specifies that the extender is capable of caching node information,
	// so the scheduler should only send minimal information about the eligible nodes
	// assuming that the extender already cached full details of all nodes in the cluster
	NodeCacheCapable bool
	// ManagedResources is a list of extended resources that are managed by
	// this extender.
	// - A pod will be sent to the extender on the Filter, Prioritize and Bind
	//   (if the extender is the binder) phases iff the pod requests at least
	//   one of the extended resources in this list. If empty or unspecified,
	//   all pods will be sent to this extender.
	// - If IgnoredByScheduler is set to true for a resource, kube-scheduler
	//   will skip checking the resource in predicates.
	// +optional
	ManagedResources []ExtenderManagedResource
	// Ignorable specifies if the extender is ignorable, i.e. scheduling should not
	// fail when the extender returns an error or is not reachable.
	Ignorable bool
}
```

这里面主要关注如下几个字段：

* URLPrefix：extender访问地址
* FilterVerb：extender预选接口，scheduler在默认预选策略完成后会调用该接口完成自定义预选算法
* PrioritizeVerb：extender优选接口，scheduler在默认优选策略完成后会调用该接口完成自定义优选算法
* Weight：表示extender优选算法对应的权重

policy配置示例如下：

```go
{
  "predicates": [
    {
      "name": "HostName"
    },
    {
      "name": "MatchNodeSelector"
    },
    {
      "name": "PodFitsResources"
    }
  ],
  "priorities": [
    {
      "name": "LeastRequestedPriority",
      "weight": 1
    }
  ],
  "extenders": [
    {
      "urlPrefix": "http://127.0.0.1:12345/api/scheduler",
      "filterVerb": "filter",
      "enableHttps": false
    }
  ]
}
```

* extender预选接口

传递给extender预选接口的参数结构如下(k8s.io/kubernetes/pkg/scheduler/apis/extender/v1/types.go)：

```go
// ExtenderArgs represents the arguments needed by the extender to filter/prioritize
// nodes for a pod.
type ExtenderArgs struct {
	// Pod being scheduled
	Pod *v1.Pod
	// List of candidate nodes where the pod can be scheduled; to be populated
	// only if ExtenderConfig.NodeCacheCapable == false
	Nodes *v1.NodeList
	// List of candidate node names where the pod can be scheduled; to be
	// populated only if ExtenderConfig.NodeCacheCapable == true
	NodeNames *[]string
}
```

其中，Nodes结构体表示scheduler默认预选策略通过的节点列表，我们看相关调用代码(k8s.io/kubernetes/pkg/scheduler/core/generic_scheduler.go)：

```go
// CreateFromConfig creates a scheduler from the configuration file
func (c *Configurator) CreateFromConfig(policy schedulerapi.Policy) (*Scheduler, error) {
	klog.V(2).Infof("Creating scheduler from configuration: %v", policy)
    ...
	var extenders []algorithm.SchedulerExtender
	if len(policy.Extenders) != 0 {
		ignoredExtendedResources := sets.NewString()
		var ignorableExtenders []algorithm.SchedulerExtender
		for ii := range policy.Extenders {
			klog.V(2).Infof("Creating extender with config %+v", policy.Extenders[ii])
			extender, err := core.NewHTTPExtender(&policy.Extenders[ii])
			if err != nil {
				return nil, err
			}
			if !extender.IsIgnorable() {
				extenders = append(extenders, extender)
			} else {
				ignorableExtenders = append(ignorableExtenders, extender)
			}
			for _, r := range policy.Extenders[ii].ManagedResources {
				if r.IgnoredByScheduler {
					ignoredExtendedResources.Insert(string(r.Name))
				}
			}
		}
		// place ignorable extenders to the tail of extenders
		extenders = append(extenders, ignorableExtenders...)
		predicates.RegisterPredicateMetadataProducerWithExtendedResourceOptions(ignoredExtendedResources)
	}
    ...
	return c.CreateFromKeys(predicateKeys, priorityKeys, extenders)
}

...
// Filters the nodes to find the ones that fit based on the given predicate functions
// Each node is passed through the predicate functions to determine if it is a fit
func (g *genericScheduler) findNodesThatFit(ctx context.Context, state *framework.CycleState, pod *v1.Pod) ([]*v1.Node, FailedPredicateMap, framework.NodeToStatusMap, error) {
	var filtered []*v1.Node
	failedPredicateMap := FailedPredicateMap{}
	filteredNodesStatuses := framework.NodeToStatusMap{}

	if len(g.predicates) == 0 && !g.framework.HasFilterPlugins() {
		filtered = g.nodeInfoSnapshot.ListNodes()
	} else {
		allNodes := len(g.nodeInfoSnapshot.NodeInfoList)
		numNodesToFind := g.numFeasibleNodesToFind(int32(allNodes))

		// Create filtered list with enough space to avoid growing it
		// and allow assigning.
		filtered = make([]*v1.Node, numNodesToFind)
		errCh := util.NewErrorChannel()
		var (
			predicateResultLock sync.Mutex
			filteredLen         int32
		)

		ctx, cancel := context.WithCancel(ctx)

		// We can use the same metadata producer for all nodes.
		meta := g.predicateMetaProducer(pod, g.nodeInfoSnapshot)
		state.Write(migration.PredicatesStateKey, &migration.PredicatesStateData{Reference: meta})

		checkNode := func(i int) {
			// We check the nodes starting from where we left off in the previous scheduling cycle,
			// this is to make sure all nodes have the same chance of being examined across pods.
			nodeInfo := g.nodeInfoSnapshot.NodeInfoList[(g.nextStartNodeIndex+i)%allNodes]
			fits, failedPredicates, status, err := g.podFitsOnNode(
				ctx,
				state,
				pod,
				meta,
				nodeInfo,
				g.alwaysCheckAllPredicates,
			)
			if err != nil {
				errCh.SendErrorWithCancel(err, cancel)
				return
			}
			if fits {
				length := atomic.AddInt32(&filteredLen, 1)
				if length > numNodesToFind {
					cancel()
					atomic.AddInt32(&filteredLen, -1)
				} else {
					filtered[length-1] = nodeInfo.Node()
				}
			} else {
				predicateResultLock.Lock()
				if !status.IsSuccess() {
					filteredNodesStatuses[nodeInfo.Node().Name] = status
				}
				if len(failedPredicates) != 0 {
					failedPredicateMap[nodeInfo.Node().Name] = failedPredicates
				}
				predicateResultLock.Unlock()
			}
		}

		// Stops searching for more nodes once the configured number of feasible nodes
		// are found.
		workqueue.ParallelizeUntil(ctx, 16, allNodes, checkNode)
		processedNodes := int(filteredLen) + len(filteredNodesStatuses) + len(failedPredicateMap)
		g.nextStartNodeIndex = (g.nextStartNodeIndex + processedNodes) % allNodes

		filtered = filtered[:filteredLen]
		if err := errCh.ReceiveError(); err != nil {
			return []*v1.Node{}, FailedPredicateMap{}, framework.NodeToStatusMap{}, err
		}
	}

	if len(filtered) > 0 && len(g.extenders) != 0 {
		for _, extender := range g.extenders {
			if !extender.IsInterested(pod) {
				continue
			}
			filteredList, failedMap, err := extender.Filter(pod, filtered, g.nodeInfoSnapshot.NodeInfoMap)
			if err != nil {
				if extender.IsIgnorable() {
					klog.Warningf("Skipping extender %v as it returned error %v and has ignorable flag set",
						extender, err)
					continue
				}

				return []*v1.Node{}, FailedPredicateMap{}, framework.NodeToStatusMap{}, err
			}

			for failedNodeName, failedMsg := range failedMap {
				if _, found := failedPredicateMap[failedNodeName]; !found {
					failedPredicateMap[failedNodeName] = []predicates.PredicateFailureReason{}
				}
				failedPredicateMap[failedNodeName] = append(failedPredicateMap[failedNodeName], predicates.NewFailureReason(failedMsg))
			}
			filtered = filteredList
			if len(filtered) == 0 {
				break
			}
		}
	}
	return filtered, failedPredicateMap, filteredNodesStatuses, nil
}

...
// SchedulerExtender is an interface for external processes to influence scheduling
// decisions made by Kubernetes. This is typically needed for resources not directly
// managed by Kubernetes.
type SchedulerExtender interface {
	// Name returns a unique name that identifies the extender.
	Name() string

	// Filter based on extender-implemented predicate functions. The filtered list is
	// expected to be a subset of the supplied list. failedNodesMap optionally contains
	// the list of failed nodes and failure reasons.
	Filter(pod *v1.Pod,
		nodes []*v1.Node, nodeNameToInfo map[string]*schedulernodeinfo.NodeInfo,
	) (filteredNodes []*v1.Node, failedNodesMap extenderv1.FailedNodesMap, err error)

	// Prioritize based on extender-implemented priority functions. The returned scores & weight
	// are used to compute the weighted score for an extender. The weighted scores are added to
	// the scores computed by Kubernetes scheduler. The total scores are used to do the host selection.
	Prioritize(pod *v1.Pod, nodes []*v1.Node) (hostPriorities *extenderv1.HostPriorityList, weight int64, err error)

	// Bind delegates the action of binding a pod to a node to the extender.
	Bind(binding *v1.Binding) error

	// IsBinder returns whether this extender is configured for the Bind method.
	IsBinder() bool

	// IsInterested returns true if at least one extended resource requested by
	// this pod is managed by this extender.
	IsInterested(pod *v1.Pod) bool

	// ProcessPreemption returns nodes with their victim pods processed by extender based on
	// given:
	//   1. Pod to schedule
	//   2. Candidate nodes and victim pods (nodeToVictims) generated by previous scheduling process.
	//   3. nodeNameToInfo to restore v1.Node from node name if extender cache is enabled.
	// The possible changes made by extender may include:
	//   1. Subset of given candidate nodes after preemption phase of extender.
	//   2. A different set of victim pod for every given candidate node after preemption phase of extender.
	ProcessPreemption(
		pod *v1.Pod,
		nodeToVictims map[*v1.Node]*extenderv1.Victims,
		nodeNameToInfo map[string]*schedulernodeinfo.NodeInfo,
	) (map[*v1.Node]*extenderv1.Victims, error)

	// SupportsPreemption returns if the scheduler extender support preemption or not.
	SupportsPreemption() bool

	// IsIgnorable returns true indicates scheduling should not fail when this extender
	// is unavailable. This gives scheduler ability to fail fast and tolerate non-critical extenders as well.
	IsIgnorable() bool
}

...
// k8s.io/kubernetes/pkg/scheduler/core/extender.go
// Filter based on extender implemented predicate functions. The filtered list is
// expected to be a subset of the supplied list; otherwise the function returns an error.
// failedNodesMap optionally contains the list of failed nodes and failure reasons.
func (h *HTTPExtender) Filter(
	pod *v1.Pod,
	nodes []*v1.Node, nodeNameToInfo map[string]*schedulernodeinfo.NodeInfo,
) ([]*v1.Node, extenderv1.FailedNodesMap, error) {
	var (
		result     extenderv1.ExtenderFilterResult
		nodeList   *v1.NodeList
		nodeNames  *[]string
		nodeResult []*v1.Node
		args       *extenderv1.ExtenderArgs
	)

	if h.filterVerb == "" {
		return nodes, extenderv1.FailedNodesMap{}, nil
	}

	if h.nodeCacheCapable {
		nodeNameSlice := make([]string, 0, len(nodes))
		for _, node := range nodes {
			nodeNameSlice = append(nodeNameSlice, node.Name)
		}
		nodeNames = &nodeNameSlice
	} else {
		nodeList = &v1.NodeList{}
		for _, node := range nodes {
			nodeList.Items = append(nodeList.Items, *node)
		}
	}

	args = &extenderv1.ExtenderArgs{
		Pod:       pod,
		Nodes:     nodeList,
		NodeNames: nodeNames,
	}

	if err := h.send(h.filterVerb, args, &result); err != nil {
		return nil, nil, err
	}
	if result.Error != "" {
		return nil, nil, fmt.Errorf(result.Error)
	}

	if h.nodeCacheCapable && result.NodeNames != nil {
		nodeResult = make([]*v1.Node, len(*result.NodeNames))
		for i, nodeName := range *result.NodeNames {
			if node, ok := nodeNameToInfo[nodeName]; ok {
				nodeResult[i] = node.Node()
			} else {
				return nil, nil, fmt.Errorf(
					"extender %q claims a filtered node %q which is not found in nodeNameToInfo map",
					h.extenderURL, nodeName)
			}
		}
	} else if result.Nodes != nil {
		nodeResult = make([]*v1.Node, len(result.Nodes.Items))
		for i := range result.Nodes.Items {
			nodeResult[i] = &result.Nodes.Items[i]
		}
	}

	return nodeResult, result.FailedNodes, nil
}

...
// Helper function to send messages to the extender
func (h *HTTPExtender) send(action string, args interface{}, result interface{}) error {
	out, err := json.Marshal(args)
	if err != nil {
		return err
	}

	url := strings.TrimRight(h.extenderURL, "/") + "/" + action

	req, err := http.NewRequest("POST", url, bytes.NewReader(out))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed %v with extender at URL %v, code %v", action, url, resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(result)
}
```

scheduler会在默认预选算法执行完成后，遍历extender列表，依次发出http/https POST请求给extender，请求参数为extenderv1.ExtenderArgs，extender执行完预选算法后，返回extenderv1.ExtenderFilterResult(k8s.io/kubernetes/pkg/scheduler/apis/extender/v1/types.go)，如下：

```go
// ExtenderFilterResult represents the results of a filter call to an extender
type ExtenderFilterResult struct {
	// Filtered set of nodes where the pod can be scheduled; to be populated
	// only if ExtenderConfig.NodeCacheCapable == false
	Nodes *v1.NodeList
	// Filtered set of nodes where the pod can be scheduled; to be populated
	// only if ExtenderConfig.NodeCacheCapable == true
	NodeNames *[]string
	// Filtered out nodes where the pod can't be scheduled and the failure messages
	FailedNodes FailedNodesMap
	// Error message indicating failure
	Error string
}
```

并将上一次过滤后的node列表传递给下一个extender进行过滤

* extender优选接口

传递给extender优选接口的参数结构和预选相同(k8s.io/kubernetes/pkg/scheduler/apis/extender/v1/types.go)：

```go
// ExtenderArgs represents the arguments needed by the extender to filter/prioritize
// nodes for a pod.
type ExtenderArgs struct {
	// Pod being scheduled
	Pod *v1.Pod
	// List of candidate nodes where the pod can be scheduled; to be populated
	// only if ExtenderConfig.NodeCacheCapable == false
	Nodes *v1.NodeList
	// List of candidate node names where the pod can be scheduled; to be
	// populated only if ExtenderConfig.NodeCacheCapable == true
	NodeNames *[]string
}
```

其中，Nodes结构体表示scheduler预选策略(默认+extender算法)通过的节点列表，我们看相关调用代码(k8s.io/kubernetes/pkg/scheduler/core/generic_scheduler.go)：

```go
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

...
// Prioritize based on extender implemented priority functions. Weight*priority is added
// up for each such priority function. The returned score is added to the score computed
// by Kubernetes scheduler. The total score is used to do the host selection.
func (h *HTTPExtender) Prioritize(pod *v1.Pod, nodes []*v1.Node) (*extenderv1.HostPriorityList, int64, error) {
	var (
		result    extenderv1.HostPriorityList
		nodeList  *v1.NodeList
		nodeNames *[]string
		args      *extenderv1.ExtenderArgs
	)

	if h.prioritizeVerb == "" {
		result := extenderv1.HostPriorityList{}
		for _, node := range nodes {
			result = append(result, extenderv1.HostPriority{Host: node.Name, Score: 0})
		}
		return &result, 0, nil
	}

	if h.nodeCacheCapable {
		nodeNameSlice := make([]string, 0, len(nodes))
		for _, node := range nodes {
			nodeNameSlice = append(nodeNameSlice, node.Name)
		}
		nodeNames = &nodeNameSlice
	} else {
		nodeList = &v1.NodeList{}
		for _, node := range nodes {
			nodeList.Items = append(nodeList.Items, *node)
		}
	}

	args = &extenderv1.ExtenderArgs{
		Pod:       pod,
		Nodes:     nodeList,
		NodeNames: nodeNames,
	}

	if err := h.send(h.prioritizeVerb, args, &result); err != nil {
		return nil, 0, err
	}
	return &result, h.weight, nil
}
```

scheduler会在默认优选算法执行完成后，会并发(wg.Wait)执行extender优选算法(预选需要顺序执行，优选可以并发执行)，和预选一样请求参数为extenderv1.ExtenderArgs，extender返回extenderv1.HostPriorityList(k8s.io/kubernetes/pkg/scheduler/apis/extender/v1/types.go)，如下：

```go
// HostPriority represents the priority of scheduling to a particular host, higher priority is better.
type HostPriority struct {
	// Name of the host
	Host string
	// Score associated with the host
	Score int64
}

// HostPriorityList declares a []HostPriority type.
type HostPriorityList []HostPriority
```

这里返回了每个节点对应的extender优选算法分数，注意extender的优选算法实际上只是完成了Map过程(返回0-10分数)，所以需要scheduler对extender优选scores进行Reduce(替换成0-100分数)，如下：

```go
// MaxExtenderPriority may diverge from the max priority used in the scheduler and defined by MaxNodeScore,
// therefore we need to scale the score returned by extenders to the score range used by the scheduler.
result[i].Score += combinedScores[result[i].Name] * (framework.MaxNodeScore / extenderv1.MaxExtenderPriority)

...
const (
	// MaxNodeScore is the maximum score a Score plugin is expected to return.
	MaxNodeScore int64 = 100

	// MinNodeScore is the minimum score a Score plugin is expected to return.
	MinNodeScore int64 = 0

	// MaxTotalScore is the maximum total score.
	MaxTotalScore int64 = math.MaxInt64
)

...
const (
	// MinExtenderPriority defines the min priority value for extender.
	MinExtenderPriority int64 = 0

	// MaxExtenderPriority defines the max priority value for extender.
	MaxExtenderPriority int64 = 10
)
```

这里给一个scheduler extender扩展的[demo project](https://github.com/everpeace/k8s-scheduler-extender-example)，代码简单&无意义，不分析，只用于参考

至此，scheduler扩展的三种方式原理和实践指引都已经介绍完毕，下一章我们开始介绍scheduler framework……

## Refs

* [Scheduler extender](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/scheduler_extender.md)
* [The Kubernetes Scheduler](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-scheduling/scheduler.md)