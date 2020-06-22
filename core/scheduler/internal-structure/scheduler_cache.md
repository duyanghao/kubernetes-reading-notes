Kubernetes Scheduler Internal Structure - Cache
===============================================

在分析完SchedulerQueue和nominatedPodMap之后，我们最后分析一下SchedulerCache结构，看看这个结构是如何工作的

我们先看看定义(k8s.io/kubernetes/pkg/scheduler/scheduler.go)：

```go
// Scheduler watches for new unscheduled pods. It attempts to find
// nodes that they fit on and writes bindings back to the api server.
type Scheduler struct {
	// It is expected that changes made via SchedulerCache will be observed
	// by NodeLister and Algorithm.
	SchedulerCache internalcache.Cache

	Algorithm core.ScheduleAlgorithm
	GetBinder func(pod *v1.Pod) Binder
	// PodConditionUpdater is used only in case of scheduling errors. If we succeed
	// with scheduling, PodScheduled condition will be updated in apiserver in /bind
	// handler so that binding and setting PodCondition it is atomic.
	podConditionUpdater podConditionUpdater
	// PodPreemptor is used to evict pods and update 'NominatedNode' field of
	// the preemptor pod.
	podPreemptor podPreemptor
	// Framework runs scheduler plugins at configured extension points.
	Framework framework.Framework

	// NextPod should be a function that blocks until the next pod
	// is available. We don't use a channel for this, because scheduling
	// a pod may take some amount of time and we don't want pods to get
	// stale while they sit in a channel.
	NextPod func() *framework.PodInfo

	// Error is called if there is an error. It is passed the pod in
	// question, and the error
	Error func(*framework.PodInfo, error)

	// Recorder is the EventRecorder to use
	Recorder events.EventRecorder

	// Close this to shut down the scheduler.
	StopEverything <-chan struct{}

	// VolumeBinder handles PVC/PV binding for the pod.
	VolumeBinder *volumebinder.VolumeBinder

	// Disable pod preemption or not.
	DisablePreemption bool

	// SchedulingQueue holds pods to be scheduled
	SchedulingQueue internalqueue.SchedulingQueue

	scheduledPodsHasSynced func() bool

	// The final configuration of the framework.
	Plugins      schedulerapi.Plugins
	PluginConfig []schedulerapi.PluginConfig
}

...
// New returns a Scheduler
func New(client clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	podInformer coreinformers.PodInformer,
	recorder events.EventRecorder,
	stopCh <-chan struct{},
	opts ...Option) (*Scheduler, error) {

	schedulerCache := internalcache.New(30*time.Second, stopEverything)
	volumeBinder := volumebinder.NewVolumeBinder(
		client,
		informerFactory.Core().V1().Nodes(),
		informerFactory.Storage().V1().CSINodes(),
		informerFactory.Core().V1().PersistentVolumeClaims(),
		informerFactory.Core().V1().PersistentVolumes(),
		informerFactory.Storage().V1().StorageClasses(),
		time.Duration(options.bindTimeoutSeconds)*time.Second,
	)

	registry := options.frameworkDefaultRegistry
	if registry == nil {
		registry = frameworkplugins.NewDefaultRegistry(&frameworkplugins.RegistryArgs{
			VolumeBinder: volumeBinder,
		})
	}
	registry.Merge(options.frameworkOutOfTreeRegistry)

	snapshot := nodeinfosnapshot.NewEmptySnapshot()

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

	...
	return sched, nil
}

...
// New returns a Cache implementation.
// It automatically starts a go routine that manages expiration of assumed pods.
// "ttl" is how long the assumed pod will get expired.
// "stop" is the channel that would close the background goroutine.
func New(ttl time.Duration, stop <-chan struct{}) Cache {
	cache := newSchedulerCache(ttl, cleanAssumedPeriod, stop)
	cache.run()
	return cache
}

...
func newSchedulerCache(ttl, period time.Duration, stop <-chan struct{}) *schedulerCache {
	return &schedulerCache{
		ttl:    ttl,
		period: period,
		stop:   stop,

		nodes:       make(map[string]*nodeInfoListItem),
		nodeTree:    newNodeTree(nil),
		assumedPods: make(map[string]bool),
		podStates:   make(map[string]*podState),
		imageStates: make(map[string]*imageState),
	}
}

type schedulerCache struct {
	stop   <-chan struct{}
	ttl    time.Duration
	period time.Duration

	// This mutex guards all fields within this cache struct.
	mu sync.RWMutex
	// a set of assumed pod keys.
	// The key could further be used to get an entry in podStates.
	assumedPods map[string]bool
	// a map from pod key to podState.
	podStates map[string]*podState
	nodes     map[string]*nodeInfoListItem
	// headNode points to the most recently updated NodeInfo in "nodes". It is the
	// head of the linked list.
	headNode *nodeInfoListItem
	nodeTree *nodeTree
	// A map from image name to its imageState.
	imageStates map[string]*imageState
}
```

schedulerCache实现了Cache接口(k8s.io/kubernetes/pkg/scheduler/internal/cache/interface.go)，我们看看Cache接口各定义：

```go
// Cache collects pods' information and provides node-level aggregated information.
// It's intended for generic scheduler to do efficient lookup.
// Cache's operations are pod centric. It does incremental updates based on pod events.
// Pod events are sent via network. We don't have guaranteed delivery of all events:
// We use Reflector to list and watch from remote.
// Reflector might be slow and do a relist, which would lead to missing events.
//
// State Machine of a pod's events in scheduler's cache:
//
//
//   +-------------------------------------------+  +----+
//   |                            Add            |  |    |
//   |                                           |  |    | Update
//   +      Assume                Add            v  v    |
//Initial +--------> Assumed +------------+---> Added <--+
//   ^                +   +               |       +
//   |                |   |               |       |
//   |                |   |           Add |       | Remove
//   |                |   |               |       |
//   |                |   |               +       |
//   +----------------+   +-----------> Expired   +----> Deleted
//         Forget             Expire
//
//
// Note that an assumed pod can expire, because if we haven't received Add event notifying us
// for a while, there might be some problems and we shouldn't keep the pod in cache anymore.
//
// Note that "Initial", "Expired", and "Deleted" pods do not actually exist in cache.
// Based on existing use cases, we are making the following assumptions:
// - No pod would be assumed twice
// - A pod could be added without going through scheduler. In this case, we will see Add but not Assume event.
// - If a pod wasn't added, it wouldn't be removed or updated.
// - Both "Expired" and "Deleted" are valid end states. In case of some problems, e.g. network issue,
//   a pod might have changed its state (e.g. added and deleted) without delivering notification to the cache.
type Cache interface {
	schedulerlisters.PodLister

	// AssumePod assumes a pod scheduled and aggregates the pod's information into its node.
	// The implementation also decides the policy to expire pod before being confirmed (receiving Add event).
	// After expiration, its information would be subtracted.
	AssumePod(pod *v1.Pod) error

	// FinishBinding signals that cache for assumed pod can be expired
	FinishBinding(pod *v1.Pod) error

	// ForgetPod removes an assumed pod from cache.
	ForgetPod(pod *v1.Pod) error

	// AddPod either confirms a pod if it's assumed, or adds it back if it's expired.
	// If added back, the pod's information would be added again.
	AddPod(pod *v1.Pod) error

	// UpdatePod removes oldPod's information and adds newPod's information.
	UpdatePod(oldPod, newPod *v1.Pod) error

	// RemovePod removes a pod. The pod's information would be subtracted from assigned node.
	RemovePod(pod *v1.Pod) error

	// GetPod returns the pod from the cache with the same namespace and the
	// same name of the specified pod.
	GetPod(pod *v1.Pod) (*v1.Pod, error)

	// IsAssumedPod returns true if the pod is assumed and not expired.
	IsAssumedPod(pod *v1.Pod) (bool, error)

	// AddNode adds overall information about node.
	AddNode(node *v1.Node) error

	// UpdateNode updates overall information about node.
	UpdateNode(oldNode, newNode *v1.Node) error

	// RemoveNode removes overall information about node.
	RemoveNode(node *v1.Node) error

	// UpdateNodeInfoSnapshot updates the passed infoSnapshot to the current contents of Cache.
	// The node info contains aggregated information of pods scheduled (including assumed to be)
	// on this node.
	UpdateNodeInfoSnapshot(nodeSnapshot *nodeinfosnapshot.Snapshot) error

	// Snapshot takes a snapshot on current cache
	Snapshot() *Snapshot
}

// Snapshot is a snapshot of cache state
type Snapshot struct {
	AssumedPods map[string]bool
	Nodes       map[string]*schedulernodeinfo.NodeInfo
}
```

schedulerCache主要用于scheduler的快速查找，其中pod的状态转换图如下：

```
   +-------------------------------------------+  +----+
   |                            Add            |  |    |
   |                                           |  |    | Update
   +      Assume                Add            v  v    |
Initial +--------> Assumed +------------+---> Added <--+
   ^                +   +               |       +
   |                |   |               |       |
   |                |   |           Add |       | Remove
   |                |   |               |       |
   |                |   |               +       |
   +----------------+   +-----------> Expired   +----> Deleted
         Forget             Expire
```

这里我们主要分析Assume与Forget过程，对应[Scheduler Framework框架3，4步骤](https://github.com/duyanghao/kubernetes-reading-notes/blob/master/core/scheduler/scheduler_framework.md)

#### Assume

回到scheduler框架的第三步：

```go
// assume signals to the cache that a pod is already in the cache, so that binding can be asynchronous.
// assume modifies `assumed`.
func (sched *Scheduler) assume(assumed *v1.Pod, host string) error {
	// Optimistically assume that the binding will succeed and send it to apiserver
	// in the background.
	// If the binding fails, scheduler will release resources allocated to assumed pod
	// immediately.
	assumed.Spec.NodeName = host

	if err := sched.SchedulerCache.AssumePod(assumed); err != nil {
		klog.Errorf("scheduler cache AssumePod failed: %v", err)
		return err
	}
	// if "assumed" is a nominated pod, we should remove it from internal cache
	if sched.SchedulingQueue != nil {
		sched.SchedulingQueue.DeleteNominatedPodIfExists(assumed)
	}

	return nil
}

func (cache *schedulerCache) AssumePod(pod *v1.Pod) error {
	key, err := schedulernodeinfo.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()
	if _, ok := cache.podStates[key]; ok {
		return fmt.Errorf("pod %v is in the cache, so can't be assumed", key)
	}

	cache.addPod(pod)
	ps := &podState{
		pod: pod,
	}
	cache.podStates[key] = ps
	cache.assumedPods[key] = true
	return nil
}

// GetPodKey returns the string key of a pod.
func GetPodKey(pod *v1.Pod) (string, error) {
	uid := string(pod.UID)
	if len(uid) == 0 {
		return "", errors.New("Cannot get cache key for pod with empty UID")
	}
	return uid, nil
}

// Assumes that lock is already acquired.
func (cache *schedulerCache) addPod(pod *v1.Pod) {
	n, ok := cache.nodes[pod.Spec.NodeName]
	if !ok {
		n = newNodeInfoListItem(schedulernodeinfo.NewNodeInfo())
		cache.nodes[pod.Spec.NodeName] = n
	}
	n.info.AddPod(pod)
	cache.moveNodeInfoToHead(pod.Spec.NodeName)
}
```

在pod调度成功(预选&优选)后，将pod以及相关调度node信息添加到schedulerCache中，假设pod已经调度成功，在node上运行；同时如果发现pod发生过抢占，则删除pod抢占相关信息(因为已经成功调度了)

#### Forget

回到scheduler框架的第四步，pod与node进行绑定：

```go
// bind binds a pod to a given node defined in a binding object.  We expect this to run asynchronously, so we
// handle binding metrics internally.
func (sched *Scheduler) bind(ctx context.Context, assumed *v1.Pod, targetNode string, state *framework.CycleState) error {
	bindingStart := time.Now()
	bindStatus := sched.Framework.RunBindPlugins(ctx, state, assumed, targetNode)
	var err error
	if !bindStatus.IsSuccess() {
		if bindStatus.Code() == framework.Skip {
			// All bind plugins chose to skip binding of this pod, call original binding function.
			// If binding succeeds then PodScheduled condition will be updated in apiserver so that
			// it's atomic with setting host.
			err = sched.GetBinder(assumed).Bind(&v1.Binding{
				ObjectMeta: metav1.ObjectMeta{Namespace: assumed.Namespace, Name: assumed.Name, UID: assumed.UID},
				Target: v1.ObjectReference{
					Kind: "Node",
					Name: targetNode,
				},
			})
		} else {
			err = fmt.Errorf("Bind failure, code: %d: %v", bindStatus.Code(), bindStatus.Message())
		}
	}
	if finErr := sched.SchedulerCache.FinishBinding(assumed); finErr != nil {
		klog.Errorf("scheduler cache FinishBinding failed: %v", finErr)
	}
	if err != nil {
		klog.V(1).Infof("Failed to bind pod: %v/%v", assumed.Namespace, assumed.Name)
		if err := sched.SchedulerCache.ForgetPod(assumed); err != nil {
			klog.Errorf("scheduler cache ForgetPod failed: %v", err)
		}
		return err
	}

	metrics.BindingLatency.Observe(metrics.SinceInSeconds(bindingStart))
	metrics.DeprecatedBindingLatency.Observe(metrics.SinceInMicroseconds(bindingStart))
	metrics.SchedulingLatency.WithLabelValues(metrics.Binding).Observe(metrics.SinceInSeconds(bindingStart))
	metrics.DeprecatedSchedulingLatency.WithLabelValues(metrics.Binding).Observe(metrics.SinceInSeconds(bindingStart))
	sched.Recorder.Eventf(assumed, nil, v1.EventTypeNormal, "Scheduled", "Binding", "Successfully assigned %v/%v to %v", assumed.Namespace, assumed.Name, targetNode)
	return nil
}
```

首先向kube-apiserver发出bind请求，将pod与node进行绑定。如果失败则执行sched.SchedulerCache.ForgetPod操作：

```go
func (cache *schedulerCache) ForgetPod(pod *v1.Pod) error {
	key, err := schedulernodeinfo.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	currState, ok := cache.podStates[key]
	if ok && currState.pod.Spec.NodeName != pod.Spec.NodeName {
		return fmt.Errorf("pod %v was assumed on %v but assigned to %v", key, pod.Spec.NodeName, currState.pod.Spec.NodeName)
	}

	switch {
	// Only assumed pod can be forgotten.
	case ok && cache.assumedPods[key]:
		err := cache.removePod(pod)
		if err != nil {
			return err
		}
		delete(cache.assumedPods, key)
		delete(cache.podStates, key)
	default:
		return fmt.Errorf("pod %v wasn't assumed so cannot be forgotten", key)
	}
	return nil
}
```

将pod相关信息从schedulerCache中删除

之后执行`sched.recordSchedulingFailure(assumedPodInfo, err, SchedulerError, fmt.Sprintf("Binding rejected: %v", err))`将该pod添加到unschedulableQ队列中，以便后续被scheduler重新调度：

```go
...
err := sched.bind(bindingCycleCtx, assumedPod, scheduleResult.SuggestedHost, state)
metrics.E2eSchedulingLatency.Observe(metrics.SinceInSeconds(start))
metrics.DeprecatedE2eSchedulingLatency.Observe(metrics.SinceInMicroseconds(start))
if err != nil {
    metrics.PodScheduleErrors.Inc()
    // trigger un-reserve plugins to clean up state associated with the reserved Pod
    fwk.RunUnreservePlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
    sched.recordSchedulingFailure(assumedPodInfo, err, SchedulerError, fmt.Sprintf("Binding rejected: %v", err))
} else {
    // Calculating nodeResourceString can be heavy. Avoid it if klog verbosity is below 2.
    if klog.V(2) {
        klog.Infof("pod %v/%v is bound successfully on node %q, %d nodes evaluated, %d nodes were found feasible.", assumedPod.Namespace, assumedPod.Name, scheduleResult.SuggestedHost, scheduleResult.EvaluatedNodes, scheduleResult.FeasibleNodes)
    }

    metrics.PodScheduleSuccesses.Inc()
    metrics.PodSchedulingAttempts.Observe(float64(podInfo.Attempts))
    metrics.PodSchedulingDuration.Observe(metrics.SinceInSeconds(podInfo.InitialAttemptTimestamp))

    // Run "postbind" plugins.
    fwk.RunPostBindPlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
}
...
```

#### genericScheduler相关使用

前面说过，SchedulerCache主要用于genericScheduler(k8s.io/kubernetes/pkg/scheduler/core/generic_scheduler.go)的加速查询，这里我们分析一下genericScheduler是如何利用该cache进行查询的：

```go
type genericScheduler struct {
	cache                    internalcache.Cache
	schedulingQueue          internalqueue.SchedulingQueue
	predicates               map[string]predicates.FitPredicate
	priorityMetaProducer     priorities.MetadataProducer
	predicateMetaProducer    predicates.MetadataProducer
	prioritizers             []priorities.PriorityConfig
	framework                framework.Framework
	extenders                []algorithm.SchedulerExtender
	alwaysCheckAllPredicates bool
	nodeInfoSnapshot         *nodeinfosnapshot.Snapshot
	volumeBinder             *volumebinder.VolumeBinder
	pvcLister                corelisters.PersistentVolumeClaimLister
	pdbLister                policylisters.PodDisruptionBudgetLister
	disablePreemption        bool
	percentageOfNodesToScore int32
	enableNonPreempting      bool
	nextStartNodeIndex       int
}

// New returns a Scheduler
func New(client clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	podInformer coreinformers.PodInformer,
	recorder events.EventRecorder,
	stopCh <-chan struct{},
	opts ...Option) (*Scheduler, error) {

	schedulerCache := internalcache.New(30*time.Second, stopEverything)
	volumeBinder := volumebinder.NewVolumeBinder(
		client,
		informerFactory.Core().V1().Nodes(),
		informerFactory.Storage().V1().CSINodes(),
		informerFactory.Core().V1().PersistentVolumeClaims(),
		informerFactory.Core().V1().PersistentVolumes(),
		informerFactory.Storage().V1().StorageClasses(),
		time.Duration(options.bindTimeoutSeconds)*time.Second,
	)

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

	metrics.Register()

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
// CreateFromKeys creates a scheduler from a set of registered fit predicate keys and priority keys.
func (c *Configurator) CreateFromKeys(predicateKeys, priorityKeys sets.String, extenders []algorithm.SchedulerExtender) (*Scheduler, error) {
	klog.V(2).Infof("Creating scheduler with fit predicates '%v' and priority functions '%v'", predicateKeys, priorityKeys)
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
```

可以看到scheduler(k8s.io/kubernetes/pkg/scheduler/scheduler.go)与genericScheduler(k8s.io/kubernetes/pkg/scheduler/core/generic_scheduler.go)使用相同的cache——schedulerCache(k8s.io/kubernetes/pkg/scheduler/internal/cache/cache.go)：

```go
type genericScheduler struct {
	cache                    internalcache.Cache
	schedulingQueue          internalqueue.SchedulingQueue
	predicates               map[string]predicates.FitPredicate
	priorityMetaProducer     priorities.MetadataProducer
	predicateMetaProducer    predicates.MetadataProducer
	prioritizers             []priorities.PriorityConfig
	framework                framework.Framework
	extenders                []algorithm.SchedulerExtender
	alwaysCheckAllPredicates bool
	nodeInfoSnapshot         *nodeinfosnapshot.Snapshot
	volumeBinder             *volumebinder.VolumeBinder
	pvcLister                corelisters.PersistentVolumeClaimLister
	pdbLister                policylisters.PodDisruptionBudgetLister
	disablePreemption        bool
	percentageOfNodesToScore int32
	enableNonPreempting      bool
	nextStartNodeIndex       int
}

type schedulerCache struct {
	stop   <-chan struct{}
	ttl    time.Duration
	period time.Duration

	// This mutex guards all fields within this cache struct.
	mu sync.RWMutex
	// a set of assumed pod keys.
	// The key could further be used to get an entry in podStates.
	assumedPods map[string]bool
	// a map from pod key to podState.
	podStates map[string]*podState
	nodes     map[string]*nodeInfoListItem
	// headNode points to the most recently updated NodeInfo in "nodes". It is the
	// head of the linked list.
	headNode *nodeInfoListItem
	nodeTree *nodeTree
	// A map from image name to its imageState.
	imageStates map[string]*imageState
}
```

genericScheduler结构体中有一个nodeInfoSnapshot，它包含了所有node的相关信息，如下：

```go
// Snapshot is a snapshot of cache NodeInfo and NodeTree order. The scheduler takes a
// snapshot at the beginning of each scheduling cycle and uses it for its operations in that cycle.
type Snapshot struct {
	// NodeInfoMap a map of node name to a snapshot of its NodeInfo.
	NodeInfoMap map[string]*schedulernodeinfo.NodeInfo
	// NodeInfoList is the list of nodes as ordered in the cache's nodeTree.
	NodeInfoList []*schedulernodeinfo.NodeInfo
	// HavePodsWithAffinityNodeInfoList is the list of nodes with at least one pod declaring affinity terms.
	HavePodsWithAffinityNodeInfoList []*schedulernodeinfo.NodeInfo
	Generation                       int64
}
```

genericScheduler每次执行调度算法(预选&优选)前会利用schedulerCache更新该node快照信息，如下：

```go
// Schedule tries to schedule the given pod to one of the nodes in the node list.
// If it succeeds, it will return the name of the node.
// If it fails, it will return a FitError error with reasons.
func (g *genericScheduler) Schedule(ctx context.Context, state *framework.CycleState, pod *v1.Pod) (result ScheduleResult, err error) {
	trace := utiltrace.New("Scheduling", utiltrace.Field{Key: "namespace", Value: pod.Namespace}, utiltrace.Field{Key: "name", Value: pod.Name})
	defer trace.LogIfLong(100 * time.Millisecond)

	if err := podPassesBasicChecks(pod, g.pvcLister); err != nil {
		return result, err
	}
	trace.Step("Basic checks done")

	if err := g.snapshot(); err != nil {
		return result, err
	}
	trace.Step("Snapshoting scheduler cache and node infos done")
	...
}

...
// snapshot snapshots scheduler cache and node infos for all fit and priority
// functions.
func (g *genericScheduler) snapshot() error {
	// Used for all fit and priority funcs.
	return g.cache.UpdateNodeInfoSnapshot(g.nodeInfoSnapshot)
}

// UpdateNodeInfoSnapshot takes a snapshot of cached NodeInfo map. This is called at
// beginning of every scheduling cycle.
// This function tracks generation number of NodeInfo and updates only the
// entries of an existing snapshot that have changed after the snapshot was taken.
func (cache *schedulerCache) UpdateNodeInfoSnapshot(nodeSnapshot *nodeinfosnapshot.Snapshot) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	balancedVolumesEnabled := utilfeature.DefaultFeatureGate.Enabled(features.BalanceAttachedNodeVolumes)

	// Get the last generation of the snapshot.
	snapshotGeneration := nodeSnapshot.Generation

	// Start from the head of the NodeInfo doubly linked list and update snapshot
	// of NodeInfos updated after the last snapshot.
	for node := cache.headNode; node != nil; node = node.next {
		if node.info.GetGeneration() <= snapshotGeneration {
			// all the nodes are updated before the existing snapshot. We are done.
			break
		}
		if balancedVolumesEnabled && node.info.TransientInfo != nil {
			// Transient scheduler info is reset here.
			node.info.TransientInfo.ResetTransientSchedulerInfo()
		}
		if np := node.info.Node(); np != nil {
			nodeSnapshot.NodeInfoMap[np.Name] = node.info.Clone()
		}
	}
	// Update the snapshot generation with the latest NodeInfo generation.
	if cache.headNode != nil {
		nodeSnapshot.Generation = cache.headNode.info.GetGeneration()
	}

	if len(nodeSnapshot.NodeInfoMap) > len(cache.nodes) {
		for name := range nodeSnapshot.NodeInfoMap {
			if _, ok := cache.nodes[name]; !ok {
				delete(nodeSnapshot.NodeInfoMap, name)
			}
		}
	}

	// Take a snapshot of the nodes order in the tree
	nodeSnapshot.NodeInfoList = make([]*schedulernodeinfo.NodeInfo, 0, cache.nodeTree.numNodes)
	nodeSnapshot.HavePodsWithAffinityNodeInfoList = make([]*schedulernodeinfo.NodeInfo, 0, cache.nodeTree.numNodes)
	for i := 0; i < cache.nodeTree.numNodes; i++ {
		nodeName := cache.nodeTree.next()
		if n := nodeSnapshot.NodeInfoMap[nodeName]; n != nil {
			nodeSnapshot.NodeInfoList = append(nodeSnapshot.NodeInfoList, n)
			if len(n.PodsWithAffinity()) > 0 {
				nodeSnapshot.HavePodsWithAffinityNodeInfoList = append(nodeSnapshot.HavePodsWithAffinityNodeInfoList, n)
			}
		} else {
			klog.Errorf("node %q exist in nodeTree but not in NodeInfoMap, this should not happen.", nodeName)
		}
	}
	return nil
}
```

之后利用该快照信息进行预选与优选相关字段(node)查询

#### 相关事件

最后我们分析一下schedulerCache相关的事件，如下是cache pod状态转化图：

```
   +-------------------------------------------+  +----+
   |                            Add            |  |    |
   |                                           |  |    | Update
   +      Assume                Add            v  v    |
Initial +--------> Assumed +------------+---> Added <--+
   ^                +   +               |       +
   |                |   |               |       |
   |                |   |           Add |       | Remove
   |                |   |               |       |
   |                |   |               +       |
   +----------------+   +-----------> Expired   +----> Deleted
         Forget             Expire
```

相关代码：

```go
// AddAllEventHandlers is a helper function used in tests and in Scheduler
// to add event handlers for various informers.
func AddAllEventHandlers(
	sched *Scheduler,
	schedulerName string,
	informerFactory informers.SharedInformerFactory,
	podInformer coreinformers.PodInformer,
) {
	// scheduled pod cache
	podInformer.Informer().AddEventHandler(
		cache.FilteringResourceEventHandler{
			FilterFunc: func(obj interface{}) bool {
				switch t := obj.(type) {
				case *v1.Pod:
					return assignedPod(t)
				case cache.DeletedFinalStateUnknown:
					if pod, ok := t.Obj.(*v1.Pod); ok {
						return assignedPod(pod)
					}
					utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
					return false
				default:
					utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
					return false
				}
			},
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    sched.addPodToCache,
				UpdateFunc: sched.updatePodInCache,
				DeleteFunc: sched.deletePodFromCache,
			},
		},
	)
    ...
}

// assignedPod selects pods that are assigned (scheduled and running).
func assignedPod(pod *v1.Pod) bool {
	return len(pod.Spec.NodeName) != 0
}
```

这里给podInformer注册相关监听处理函数，注意只处理已经调度成功的pod，接下来我们分别看看相关的处理逻辑：

* Pod Add

```go
func (sched *Scheduler) addPodToCache(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		klog.Errorf("cannot convert to *v1.Pod: %v", obj)
		return
	}

	if err := sched.SchedulerCache.AddPod(pod); err != nil {
		klog.Errorf("scheduler cache AddPod failed: %v", err)
	}

	sched.SchedulingQueue.AssignedPodAdded(pod)
}

...
// AddPod either confirms a pod if it's assumed, or adds it back if it's expired.
// If added back, the pod's information would be added again.
AddPod(pod *v1.Pod) error

...
func (cache *schedulerCache) AddPod(pod *v1.Pod) error {
	key, err := schedulernodeinfo.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	currState, ok := cache.podStates[key]
	switch {
	case ok && cache.assumedPods[key]:
		if currState.pod.Spec.NodeName != pod.Spec.NodeName {
			// The pod was added to a different node than it was assumed to.
			klog.Warningf("Pod %v was assumed to be on %v but got added to %v", key, pod.Spec.NodeName, currState.pod.Spec.NodeName)
			// Clean this up.
			cache.removePod(currState.pod)
			cache.addPod(pod)
		}
		delete(cache.assumedPods, key)
		cache.podStates[key].deadline = nil
		cache.podStates[key].pod = pod
	case !ok:
		// Pod was expired. We should add it back.
		cache.addPod(pod)
		ps := &podState{
			pod: pod,
		}
		cache.podStates[key] = ps
	default:
		return fmt.Errorf("pod %v was already in added state", key)
	}
	return nil
}

// Assumes that lock is already acquired.
func (cache *schedulerCache) addPod(pod *v1.Pod) {
	n, ok := cache.nodes[pod.Spec.NodeName]
	if !ok {
		n = newNodeInfoListItem(schedulernodeinfo.NewNodeInfo())
		cache.nodes[pod.Spec.NodeName] = n
	}
	n.info.AddPod(pod)
	cache.moveNodeInfoToHead(pod.Spec.NodeName)
}
```

将pod从assume中移除，并添加到Add中，同时添加相关的node信息到schedulerCache

这里面涉及一个assume过期的问题：assume只是假设的pod成功调度到node上，实际真正成功是有对应的pod Add事件发生，顺序是先assume后Add Event，这里面就存在一个过期时间了，看代码：

```go
var (
	cleanAssumedPeriod = 1 * time.Second
)
// New returns a Cache implementation.
// It automatically starts a go routine that manages expiration of assumed pods.
// "ttl" is how long the assumed pod will get expired.
// "stop" is the channel that would close the background goroutine.
func New(ttl time.Duration, stop <-chan struct{}) Cache {
	cache := newSchedulerCache(ttl, cleanAssumedPeriod, stop)
	cache.run()
	return cache
}
func newSchedulerCache(ttl, period time.Duration, stop <-chan struct{}) *schedulerCache {
	return &schedulerCache{
		ttl:    ttl,
		period: period,
		stop:   stop,

		nodes:       make(map[string]*nodeInfoListItem),
		nodeTree:    newNodeTree(nil),
		assumedPods: make(map[string]bool),
		podStates:   make(map[string]*podState),
		imageStates: make(map[string]*imageState),
	}
}

...
func (cache *schedulerCache) run() {
	go wait.Until(cache.cleanupExpiredAssumedPods, cache.period, cache.stop)
}

// Until loops until stop channel is closed, running f every period.
//
// Until is syntactic sugar on top of JitterUntil with zero jitter factor and
// with sliding = true (which means the timer for period starts after the f
// completes).
func Until(f func(), period time.Duration, stopCh <-chan struct{}) {
	JitterUntil(f, period, 0.0, true, stopCh)
}

...
func (cache *schedulerCache) cleanupExpiredAssumedPods() {
	cache.cleanupAssumedPods(time.Now())
}

...
// cleanupAssumedPods exists for making test deterministic by taking time as input argument.
// It also reports metrics on the cache size for nodes, pods, and assumed pods.
func (cache *schedulerCache) cleanupAssumedPods(now time.Time) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	defer cache.updateMetrics()

	// The size of assumedPods should be small
	for key := range cache.assumedPods {
		ps, ok := cache.podStates[key]
		if !ok {
			panic("Key found in assumed set but not in podStates. Potentially a logical error.")
		}
		if !ps.bindingFinished {
			klog.V(3).Infof("Couldn't expire cache for pod %v/%v. Binding is still in progress.",
				ps.pod.Namespace, ps.pod.Name)
			continue
		}
		if now.After(*ps.deadline) {
			klog.Warningf("Pod %s/%s expired", ps.pod.Namespace, ps.pod.Name)
			if err := cache.expirePod(key, ps); err != nil {
				klog.Errorf("ExpirePod failed for %s: %v", key, err)
			}
		}
	}
}

func (cache *schedulerCache) expirePod(key string, ps *podState) error {
	if err := cache.removePod(ps.pod); err != nil {
		return err
	}
	delete(cache.assumedPods, key)
	delete(cache.podStates, key)
	return nil
}

// Assumes that lock is already acquired.
func (cache *schedulerCache) removePod(pod *v1.Pod) error {
	n, ok := cache.nodes[pod.Spec.NodeName]
	if !ok {
		return fmt.Errorf("node %v is not found", pod.Spec.NodeName)
	}
	if err := n.info.RemovePod(pod); err != nil {
		return err
	}
	if len(n.info.Pods()) == 0 && n.info.Node() == nil {
		cache.removeNodeInfoFromList(pod.Spec.NodeName)
	} else {
		cache.moveNodeInfoToHead(pod.Spec.NodeName)
	}
	return nil
}
```

在创建完schedulerCache后，会执行定期(1s)清理过期assume的逻辑，只要assume过期，则将相关pod和node信息从cache删除

这里会涉及到一个如何判断是否过期的逻辑：

```go
sched.SchedulerCache.FinishBinding(assumed)

func (cache *schedulerCache) FinishBinding(pod *v1.Pod) error {
	return cache.finishBinding(pod, time.Now())
}

// finishBinding exists to make tests determinitistic by injecting now as an argument
func (cache *schedulerCache) finishBinding(pod *v1.Pod, now time.Time) error {
	key, err := schedulernodeinfo.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()

	klog.V(5).Infof("Finished binding for pod %v. Can be expired.", key)
	currState, ok := cache.podStates[key]
	if ok && cache.assumedPods[key] {
		dl := now.Add(cache.ttl)
		currState.bindingFinished = true
		currState.deadline = &dl
	}
	return nil
}
```

在成功结束调度流程最后的bind步骤后，scheduler会执行finishBinding操作，该操作会设置podStates对应的bindingFinished标志为true，表示bind成功结束了；另外设置deadline为此时延后30s时间

也即在bind结束30s后，如果还没有收到Add Event，则将pod相关信息从assume移除(cache不会有任何该pod相关信息了)。之后如果收到该pod的Add Event，则重新添加相关信息到cache Add中

* Pod Update

再看看Pod Update事件处理逻辑：

```go
func (sched *Scheduler) updatePodInCache(oldObj, newObj interface{}) {
	oldPod, ok := oldObj.(*v1.Pod)
	if !ok {
		klog.Errorf("cannot convert oldObj to *v1.Pod: %v", oldObj)
		return
	}
	newPod, ok := newObj.(*v1.Pod)
	if !ok {
		klog.Errorf("cannot convert newObj to *v1.Pod: %v", newObj)
		return
	}

	// NOTE: Updates must be written to scheduler cache before invalidating
	// equivalence cache, because we could snapshot equivalence cache after the
	// invalidation and then snapshot the cache itself. If the cache is
	// snapshotted before updates are written, we would update equivalence
	// cache with stale information which is based on snapshot of old cache.
	if err := sched.SchedulerCache.UpdatePod(oldPod, newPod); err != nil {
		klog.Errorf("scheduler cache UpdatePod failed: %v", err)
	}

	sched.SchedulingQueue.AssignedPodUpdated(newPod)
}

...
// UpdatePod removes oldPod's information and adds newPod's information.
UpdatePod(oldPod, newPod *v1.Pod) error

...
func (cache *schedulerCache) UpdatePod(oldPod, newPod *v1.Pod) error {
	key, err := schedulernodeinfo.GetPodKey(oldPod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	currState, ok := cache.podStates[key]
	switch {
	// An assumed pod won't have Update/Remove event. It needs to have Add event
	// before Update event, in which case the state would change from Assumed to Added.
	case ok && !cache.assumedPods[key]:
		if currState.pod.Spec.NodeName != newPod.Spec.NodeName {
			klog.Errorf("Pod %v updated on a different node than previously added to.", key)
			klog.Fatalf("Schedulercache is corrupted and can badly affect scheduling decisions")
		}
		if err := cache.updatePod(oldPod, newPod); err != nil {
			return err
		}
		currState.pod = newPod
	default:
		return fmt.Errorf("pod %v is not added to scheduler cache, so cannot be updated", key)
	}
	return nil
}

// Assumes that lock is already acquired.
func (cache *schedulerCache) updatePod(oldPod, newPod *v1.Pod) error {
	if err := cache.removePod(oldPod); err != nil {
		return err
	}
	cache.addPod(newPod)
	return nil
}
```

更新逻辑：将旧pod从cache中删除，同时添加新pod到cache中并且更新podStates为新pod。由于Update事件只会发生在Add事件之后(Assumed => Added)，因此assumed pod不会存在Update事件

* Pod Delete

最后再来看看Pod Delete事件处理逻辑：

```go
func (sched *Scheduler) deletePodFromCache(obj interface{}) {
	var pod *v1.Pod
	switch t := obj.(type) {
	case *v1.Pod:
		pod = t
	case cache.DeletedFinalStateUnknown:
		var ok bool
		pod, ok = t.Obj.(*v1.Pod)
		if !ok {
			klog.Errorf("cannot convert to *v1.Pod: %v", t.Obj)
			return
		}
	default:
		klog.Errorf("cannot convert to *v1.Pod: %v", t)
		return
	}
	// NOTE: Updates must be written to scheduler cache before invalidating
	// equivalence cache, because we could snapshot equivalence cache after the
	// invalidation and then snapshot the cache itself. If the cache is
	// snapshotted before updates are written, we would update equivalence
	// cache with stale information which is based on snapshot of old cache.
	if err := sched.SchedulerCache.RemovePod(pod); err != nil {
		klog.Errorf("scheduler cache RemovePod failed: %v", err)
	}

	sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(queue.AssignedPodDelete)
}

// RemovePod removes a pod. The pod's information would be subtracted from assigned node.
RemovePod(pod *v1.Pod) error

...
func (cache *schedulerCache) RemovePod(pod *v1.Pod) error {
	key, err := schedulernodeinfo.GetPodKey(pod)
	if err != nil {
		return err
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	currState, ok := cache.podStates[key]
	switch {
	// An assumed pod won't have Delete/Remove event. It needs to have Add event
	// before Remove event, in which case the state would change from Assumed to Added.
	case ok && !cache.assumedPods[key]:
		if currState.pod.Spec.NodeName != pod.Spec.NodeName {
			klog.Errorf("Pod %v was assumed to be on %v but got added to %v", key, pod.Spec.NodeName, currState.pod.Spec.NodeName)
			klog.Fatalf("Schedulercache is corrupted and can badly affect scheduling decisions")
		}
		err := cache.removePod(currState.pod)
		if err != nil {
			return err
		}
		delete(cache.podStates, key)
	default:
		return fmt.Errorf("pod %v is not found in scheduler cache, so cannot be removed from it", key)
	}
	return nil
}
```

将pod从cache中删除。由于Update和Delete事件只会发生在Add事件之后(Assumed => Added)，因此assumed pod不会存在Delete事件

最后我们回过头，再来看看schedulerCache的这段注释：

```go
// Cache collects pods' information and provides node-level aggregated information.
// It's intended for generic scheduler to do efficient lookup.
// Cache's operations are pod centric. It does incremental updates based on pod events.
// Pod events are sent via network. We don't have guaranteed delivery of all events:
// We use Reflector to list and watch from remote.
// Reflector might be slow and do a relist, which would lead to missing events.
//
// State Machine of a pod's events in scheduler's cache:
//
//
//   +-------------------------------------------+  +----+
//   |                            Add            |  |    |
//   |                                           |  |    | Update
//   +      Assume                Add            v  v    |
//Initial +--------> Assumed +------------+---> Added <--+
//   ^                +   +               |       +
//   |                |   |               |       |
//   |                |   |           Add |       | Remove
//   |                |   |               |       |
//   |                |   |               +       |
//   +----------------+   +-----------> Expired   +----> Deleted
//         Forget             Expire
//
//
// Note that an assumed pod can expire, because if we haven't received Add event notifying us
// for a while, there might be some problems and we shouldn't keep the pod in cache anymore.
//
// Note that "Initial", "Expired", and "Deleted" pods do not actually exist in cache.
// Based on existing use cases, we are making the following assumptions:
// - No pod would be assumed twice
// - A pod could be added without going through scheduler. In this case, we will see Add but not Assume event.
// - If a pod wasn't added, it wouldn't be removed or updated.
// - Both "Expired" and "Deleted" are valid end states. In case of some problems, e.g. network issue,
//   a pod might have changed its state (e.g. added and deleted) without delivering notification to the cache.
```

1. 实际上"Initial", "Expired", and "Deleted"这些状态的pod并不存在于cache中，这些状态只是为了说明cache中pod的状态转移过程，只有"Assumed"和"Added"存在于cache中(assumedPods区分)
2. 状态转移解释：pod成功被调度(优选&预选)后，会执行Assume使其添加到cache中(Assumed)；之后执行bind操作触发过期时间(30s)，cache定期清理过期pod，发现如果30s后pod还是Assumed状态，也即过期了，则将其从cache中删除(Expired，其实也就是Deleted了)；如果没有过期，也即在过期前收到了Add Event，则执行`delete(cache.assumedPods, key)`(变成Added状态)；
如果bind操作失败，则执行Forget操作，将pod从cache中删除(Initial，其实也是Deleted了)；在收到pod Update事件后，更新cache中的pod相关信息(依旧是Added状态)；最后如果收到pod Delete事件，则从cache中删除该pod相关信息(Deleted)

通过schedulerCache维护Kubernetes集群的调度cache，其中包含node以及该node上成功(maybe assumed)调度的pod。genericScheduler通过该cache加速查找相关node以及pod信息，用于调度算法(预选&优选)