Kubernetes Scheduler Internal Structure - NominatedPods
=======================================================

本章分析PriorityQueue中另一个数据结构：nominatedPods，先看定义：

```go
// PriorityQueue implements a scheduling queue.
// The head of PriorityQueue is the highest priority pending pod. This structure
// has three sub queues. One sub-queue holds pods that are being considered for
// scheduling. This is called activeQ and is a Heap. Another queue holds
// pods that are already tried and are determined to be unschedulable. The latter
// is called unschedulableQ. The third queue holds pods that are moved from
// unschedulable queues and will be moved to active queue when backoff are completed.
type PriorityQueue struct {
	stop  <-chan struct{}
	clock util.Clock
	// podBackoff tracks backoff for pods attempting to be rescheduled
	podBackoff *PodBackoffMap

	lock sync.RWMutex
	cond sync.Cond

	// activeQ is heap structure that scheduler actively looks at to find pods to
	// schedule. Head of heap is the highest priority pod.
	activeQ *heap.Heap
	// podBackoffQ is a heap ordered by backoff expiry. Pods which have completed backoff
	// are popped from this heap before the scheduler looks at activeQ
	podBackoffQ *heap.Heap
	// unschedulableQ holds pods that have been tried and determined unschedulable.
	unschedulableQ *UnschedulablePodsMap
	// nominatedPods is a structures that stores pods which are nominated to run
	// on nodes.
	nominatedPods *nominatedPodMap
	// schedulingCycle represents sequence number of scheduling cycle and is incremented
	// when a pod is popped.
	schedulingCycle int64
	// moveRequestCycle caches the sequence number of scheduling cycle when we
	// received a move request. Unscheduable pods in and before this scheduling
	// cycle will be put back to activeQueue if we were trying to schedule them
	// when we received move request.
	moveRequestCycle int64

	// closed indicates that the queue is closed.
	// It is mainly used to let Pop() exit its control loop while waiting for an item.
	closed bool
}

// NewPriorityQueue creates a PriorityQueue object.
func NewPriorityQueue(
	stop <-chan struct{},
	fwk framework.Framework,
	opts ...Option,
) *PriorityQueue {
    ...
	pq := &PriorityQueue{
		clock:            options.clock,
		stop:             stop,
		podBackoff:       NewPodBackoffMap(options.podInitialBackoffDuration, options.podMaxBackoffDuration, options.clock),
		activeQ:          heap.NewWithRecorder(podInfoKeyFunc, comp, metrics.NewActivePodsRecorder()),
		unschedulableQ:   newUnschedulablePodsMap(metrics.NewUnschedulablePodsRecorder()),
		nominatedPods:    newNominatedPodMap(),
		moveRequestCycle: -1,
	}
    ...
	return pq
}

func newNominatedPodMap() *nominatedPodMap {
	return &nominatedPodMap{
		nominatedPods:      make(map[string][]*v1.Pod),
		nominatedPodToNode: make(map[ktypes.UID]string),
	}
}

// nominatedPodMap is a structure that stores pods nominated to run on nodes.
// It exists because nominatedNodeName of pod objects stored in the structure
// may be different than what scheduler has here. We should be able to find pods
// by their UID and update/delete them.
type nominatedPodMap struct {
	// nominatedPods is a map keyed by a node name and the value is a list of
	// pods which are nominated to run on the node. These are pods which can be in
	// the activeQ or unschedulableQ.
	nominatedPods map[string][]*v1.Pod
	// nominatedPodToNode is map keyed by a Pod UID to the node name where it is
	// nominated.
	nominatedPodToNode map[ktypes.UID]string
}
```

nominatedPods存储着抢占pod以及对应node信息，要弄懂nominatedPods，我们必须理解Scheduler的抢占特性

## Preempts(抢占)

>> Pods can have priority. Priority indicates the importance of a Pod relative to other Pods. If a Pod cannot be scheduled, the scheduler tries to preempt (evict) lower priority Pods to make scheduling of the pending Pod possible.

>> When Pod priority is enabled, the scheduler orders pending Pods by their priority and a pending Pod is placed ahead of other pending Pods with lower priority in the scheduling queue. As a result, the higher priority Pod may be scheduled sooner than Pods with lower priority if its scheduling requirements are met. If such Pod cannot be scheduled, scheduler will continue and tries to schedule other lower priority Pods.

>> When Pods are created, they go to a queue and wait to be scheduled. The scheduler picks a Pod from the queue and tries to schedule it on a Node. If no Node is found that satisfies all the specified requirements of the Pod, preemption logic is triggered for the pending Pod. Let's call the pending Pod P. Preemption logic tries to find a Node where removal of one or more Pods with lower priority than P would enable P to be scheduled on that Node. If such a Node is found, one or more lower priority Pods get evicted from the Node. After the Pods are gone, P can be scheduled on the Node.

pod有优先级的属性，代表其重要程度；schedulerQueue按照pod优先级对pod进行排序，高优先级的pod在队列前面，先出队列，也即先被调度

当scheduler调度pod P时，如果发现没有合适的节点可以调度，则会触发preemption逻辑：scheduler尝试寻找一个当驱逐掉上面若干低优先级(<=)pod后可以成功调度pod P的节点。在驱逐完这些低优先级的pod后，pod P就可以成功调度在该node上了

Preempts与nominatedPods的关系如下：

> When Pod P preempts one or more Pods on Node N, nominatedNodeName field of Pod P's status is set to the name of Node N. This field helps scheduler track resources reserved for Pod P and also gives users information about preemptions in their clusters.

> Please note that Pod P is not necessarily scheduled to the "nominated Node". After victim Pods are preempted, they get their graceful termination period. If another node becomes available while scheduler is waiting for the victim Pods to terminate, scheduler will use the other node to schedule Pod P. As a result nominatedNodeName and nodeName of Pod spec are not always the same. Also, if scheduler preempts Pods on Node N, but then a higher priority Pod than Pod P arrives, scheduler may give Node N to the new higher priority Pod. In such a case, scheduler clears nominatedNodeName of Pod P. By doing this, scheduler makes Pod P eligible to preempt Pods on another Node.

当pod P要抢占Node N上的pod时，Pod P's status的nominatedNodeName字段会被设置成node N的名字，最终被记录在PriorityQueue的nominatedPods中

这里要注意的是，虽然pod被scheduler设定抢占的节点为node N，但是pod不一定最终被调度到node N上(导致pod.status.nominatedNodeName != pod.spec.nodeName)。例如：在pod P发生抢占后，node N上一些低优先级的pod会被驱逐，并存在一个`graceful termination period`(pod退出时间，默认30s)，如果在这个时间内，集群中有资源变动，另外一个节点可以正常调度pod P，那么scheduler会将该pod调度该节点上；又比如：在victims退出的时间段内，出现了一个比pod P更高优先级的pod，scheduler会将node N分配给新出现的pod，最终导致pod P最终并不一定被分配在node N上

在基本理清抢占逻辑后，我们看代码进行深入分析，首先还是回到调度入口`scheduleOne`(k8s.io/kubernetes/pkg/scheduler/scheduler.go)：

```go
// scheduleOne does the entire scheduling workflow for a single pod.  It is serialized on the scheduling algorithm's host fitting.
func (sched *Scheduler) scheduleOne(ctx context.Context) {
	fwk := sched.Framework

	podInfo := sched.NextPod()
	// pod could be nil when schedulerQueue is closed
	if podInfo == nil || podInfo.Pod == nil {
		return
	}
	pod := podInfo.Pod
	if pod.DeletionTimestamp != nil {
		sched.Recorder.Eventf(pod, nil, v1.EventTypeWarning, "FailedScheduling", "Scheduling", "skip schedule deleting pod: %v/%v", pod.Namespace, pod.Name)
		klog.V(3).Infof("Skip schedule deleting pod: %v/%v", pod.Namespace, pod.Name)
		return
	}

	klog.V(3).Infof("Attempting to schedule pod: %v/%v", pod.Namespace, pod.Name)

	// Synchronously attempt to find a fit for the pod.
	start := time.Now()
	state := framework.NewCycleState()
	state.SetRecordFrameworkMetrics(rand.Intn(100) < frameworkMetricsSamplePercent)
	schedulingCycleCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	scheduleResult, err := sched.Algorithm.Schedule(schedulingCycleCtx, state, pod)
	if err != nil {
		sched.recordSchedulingFailure(podInfo.DeepCopy(), err, v1.PodReasonUnschedulable, err.Error())
		// Schedule() may have failed because the pod would not fit on any host, so we try to
		// preempt, with the expectation that the next time the pod is tried for scheduling it
		// will fit due to the preemption. It is also possible that a different pod will schedule
		// into the resources that were preempted, but this is harmless.
		if fitError, ok := err.(*core.FitError); ok {
			if sched.DisablePreemption {
				klog.V(3).Infof("Pod priority feature is not enabled or preemption is disabled by scheduler configuration." +
					" No preemption is performed.")
			} else {
				preemptionStartTime := time.Now()
				sched.preempt(schedulingCycleCtx, state, fwk, pod, fitError)
				metrics.PreemptionAttempts.Inc()
				metrics.SchedulingAlgorithmPreemptionEvaluationDuration.Observe(metrics.SinceInSeconds(preemptionStartTime))
				metrics.DeprecatedSchedulingAlgorithmPreemptionEvaluationDuration.Observe(metrics.SinceInMicroseconds(preemptionStartTime))
				metrics.SchedulingLatency.WithLabelValues(metrics.PreemptionEvaluation).Observe(metrics.SinceInSeconds(preemptionStartTime))
				metrics.DeprecatedSchedulingLatency.WithLabelValues(metrics.PreemptionEvaluation).Observe(metrics.SinceInSeconds(preemptionStartTime))
			}
			// Pod did not fit anywhere, so it is counted as a failure. If preemption
			// succeeds, the pod should get counted as a success the next time we try to
			// schedule it. (hopefully)
			metrics.PodScheduleFailures.Inc()
		} else {
			klog.Errorf("error selecting node for pod: %v", err)
			metrics.PodScheduleErrors.Inc()
		}
		return
	}
    ...
}
```

在调度失败(其实是预选失败)后，执行`recordSchedulingFailure`将pod放入unschedulableQ队列，之后如果抢占开启(默认行为)，则scheduler执行抢占逻辑(k8s.io/kubernetes/pkg/scheduler/scheduler.go)：

#### 1. 获取抢占pod 

```go
// preempt tries to create room for a pod that has failed to schedule, by preempting lower priority pods if possible.
// If it succeeds, it adds the name of the node where preemption has happened to the pod spec.
// It returns the node name and an error if any.
func (sched *Scheduler) preempt(ctx context.Context, state *framework.CycleState, fwk framework.Framework, preemptor *v1.Pod, scheduleErr error) (string, error) {
	preemptor, err := sched.podPreemptor.getUpdatedPod(preemptor)
	if err != nil {
		klog.Errorf("Error getting the updated preemptor pod object: %v", err)
		return "", err
	}
    ...
}

...
// Config return a scheduler config object
func (o *Options) Config() (*schedulerappconfig.Config, error) {
    ...
	// Prepare kube clients.
	client, leaderElectionClient, eventClient, err := createClients(c.ComponentConfig.ClientConnection, o.Master, c.ComponentConfig.LeaderElection.RenewDeadline.Duration)
	if err != nil {
		return nil, err
	}
    ...
	c.Client = client

	return c, nil
}

...
// runCommand runs the scheduler.
func runCommand(cmd *cobra.Command, args []string, opts *options.Options, registryOptions ...Option) error {
	c, err := opts.Config()
	if err != nil {
		return err
	}
    ...
	// Get the completed config
	cc := c.Complete()
    ...
	return Run(ctx, cc, registryOptions...)
}

...
// Run executes the scheduler based on the given configuration. It only returns on error or when context is done.
func Run(ctx context.Context, cc schedulerserverconfig.CompletedConfig, outOfTreeRegistryOptions ...Option) error {
	// To help debugging, immediately log version
	klog.V(1).Infof("Starting Kubernetes Scheduler version %+v", version.Get())

	// Create the scheduler.
	sched, err := scheduler.New(cc.Client,
		cc.InformerFactory,
		cc.PodInformer,
		cc.Recorder,
		ctx.Done(),
		scheduler.WithName(cc.ComponentConfig.SchedulerName),
		scheduler.WithAlgorithmSource(cc.ComponentConfig.AlgorithmSource),
		scheduler.WithHardPodAffinitySymmetricWeight(cc.ComponentConfig.HardPodAffinitySymmetricWeight),
		scheduler.WithPreemptionDisabled(cc.ComponentConfig.DisablePreemption),
		scheduler.WithPercentageOfNodesToScore(cc.ComponentConfig.PercentageOfNodesToScore),
		scheduler.WithBindTimeoutSeconds(cc.ComponentConfig.BindTimeoutSeconds),
		scheduler.WithFrameworkOutOfTreeRegistry(outOfTreeRegistry),
		scheduler.WithFrameworkPlugins(cc.ComponentConfig.Plugins),
		scheduler.WithFrameworkPluginConfig(cc.ComponentConfig.PluginConfig),
		scheduler.WithPodMaxBackoffSeconds(cc.ComponentConfig.PodMaxBackoffSeconds),
		scheduler.WithPodInitialBackoffSeconds(cc.ComponentConfig.PodInitialBackoffSeconds),
	)
    ...
	// Leader election is disabled, so runCommand inline until done.
	sched.Run(ctx)
	return fmt.Errorf("finished without leader elect")
}

...
// New returns a Scheduler
func New(client clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	podInformer coreinformers.PodInformer,
	recorder events.EventRecorder,
	stopCh <-chan struct{},
	opts ...Option) (*Scheduler, error) {
	
	...
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
func (p *podPreemptorImpl) getUpdatedPod(pod *v1.Pod) (*v1.Pod, error) {
	return p.Client.CoreV1().Pods(pod.Namespace).Get(pod.Name, metav1.GetOptions{})
}
```

调用kube-apiserver获取最新的抢占pod对象

#### 2. 选取抢占node以及victims

```go
node, victims, nominatedPodsToClear, err := sched.Algorithm.Preempt(ctx, state, preemptor, scheduleErr)
if err != nil {
    klog.Errorf("Error preempting victims to make room for %v/%v: %v", preemptor.Namespace, preemptor.Name, err)
    return "", err
}

...
// preempt finds nodes with pods that can be preempted to make room for "pod" to
// schedule. It chooses one of the nodes and preempts the pods on the node and
// returns 1) the node, 2) the list of preempted pods if such a node is found,
// 3) A list of pods whose nominated node name should be cleared, and 4) any
// possible error.
// Preempt does not update its snapshot. It uses the same snapshot used in the
// scheduling cycle. This is to avoid a scenario where preempt finds feasible
// nodes without preempting any pod. When there are many pending pods in the
// scheduling queue a nominated pod will go back to the queue and behind
// other pods with the same priority. The nominated pod prevents other pods from
// using the nominated resources and the nominated pod could take a long time
// before it is retried after many other pending pods.
func (g *genericScheduler) Preempt(ctx context.Context, state *framework.CycleState, pod *v1.Pod, scheduleErr error) (*v1.Node, []*v1.Pod, []*v1.Pod, error) {
    ...
}
```

这里通过genericScheduler的Preempt(k8s.io/kubernetes/pkg/scheduler/core/generic_scheduler.go)进行抢占逻辑

preempt为pod P寻找一个合适的node，通过剔除掉若干该节点上的pod最终使pod P可以成功调度在node上。该函数返回

* 1.剔除节点
* 2.节点上剔除的pod列表
* 3.pod.status.nominatedNodeName需要被清除的pod列表
* 4.任何错误

下面我们分析该函数具体逻辑

* step1 - 判断pod抢占是否合理

```go
...
if !podEligibleToPreemptOthers(pod, g.nodeInfoSnapshot.NodeInfoMap, g.enableNonPreempting) {
    klog.V(5).Infof("Pod %v/%v is not eligible for more preemption.", pod.Namespace, pod.Name)
    return nil, nil, nil, nil
}

// podEligibleToPreemptOthers determines whether this pod should be considered
// for preempting other pods or not. If this pod has already preempted other
// pods and those are in their graceful termination period, it shouldn't be
// considered for preemption.
// We look at the node that is nominated for this pod and as long as there are
// terminating pods on the node, we don't consider this for preempting more pods.
func podEligibleToPreemptOthers(pod *v1.Pod, nodeNameToInfo map[string]*schedulernodeinfo.NodeInfo, enableNonPreempting bool) bool {
	if enableNonPreempting && pod.Spec.PreemptionPolicy != nil && *pod.Spec.PreemptionPolicy == v1.PreemptNever {
		klog.V(5).Infof("Pod %v/%v is not eligible for preemption because it has a preemptionPolicy of %v", pod.Namespace, pod.Name, v1.PreemptNever)
		return false
	}
	nomNodeName := pod.Status.NominatedNodeName
	if len(nomNodeName) > 0 {
		if nodeInfo, found := nodeNameToInfo[nomNodeName]; found {
			podPriority := podutil.GetPodPriority(pod)
			for _, p := range nodeInfo.Pods() {
				if p.DeletionTimestamp != nil && podutil.GetPodPriority(p) < podPriority {
					// There is a terminating pod on the nominated node.
					return false
				}
			}
		}
	}
	return true
}
```

如果pod已经发生过抢占，并且被抢占的pod依然有处于`graceful termination period`状态，则认为pod目前抢占不合理；否则认为合理

* step2 - 查找用于抢占的node列表 

```go
potentialNodes := nodesWherePreemptionMightHelp(g.nodeInfoSnapshot.NodeInfoMap, fitError)
if len(potentialNodes) == 0 {
    klog.V(3).Infof("Preemption will not help schedule pod %v/%v on any node.", pod.Namespace, pod.Name)
    // In this case, we should clean-up any existing nominated node name of the pod.
    return nil, nil, []*v1.Pod{pod}, nil
}

...
// nodesWherePreemptionMightHelp returns a list of nodes with failed predicates
// that may be satisfied by removing pods from the node.
func nodesWherePreemptionMightHelp(nodeNameToInfo map[string]*schedulernodeinfo.NodeInfo, fitErr *FitError) []*v1.Node {
	potentialNodes := []*v1.Node{}
	for name, node := range nodeNameToInfo {
		if fitErr.FilteredNodesStatuses[name].Code() == framework.UnschedulableAndUnresolvable {
			continue
		}
		failedPredicates := fitErr.FailedPredicates[name]

		// If we assume that scheduler looks at all nodes and populates the failedPredicateMap
		// (which is the case today), the !found case should never happen, but we'd prefer
		// to rely less on such assumptions in the code when checking does not impose
		// significant overhead.
		// Also, we currently assume all failures returned by extender as resolvable.
		if predicates.UnresolvablePredicateExists(failedPredicates) == nil {
			klog.V(3).Infof("Node %v is a potential node for preemption.", name)
			potentialNodes = append(potentialNodes, node.Node())
		}
	}
	return potentialNodes
}
```

从预选失败的节点中选择出可以用于抢占的node列表

* step3 - 枚举每个node上被抢占的最小pod列表

```go
var (
    pdbs []*policy.PodDisruptionBudget
    err  error
)
if g.pdbLister != nil {
    pdbs, err = g.pdbLister.List(labels.Everything())
    if err != nil {
        return nil, nil, nil, err
    }
}
nodeToVictims, err := g.selectNodesForPreemption(ctx, state, pod, potentialNodes, pdbs)
if err != nil {
    return nil, nil, nil, err
}
...

// selectNodesForPreemption finds all the nodes with possible victims for
// preemption in parallel.
func (g *genericScheduler) selectNodesForPreemption(
	ctx context.Context,
	state *framework.CycleState,
	pod *v1.Pod,
	potentialNodes []*v1.Node,
	pdbs []*policy.PodDisruptionBudget,
) (map[*v1.Node]*extenderv1.Victims, error) {
	nodeToVictims := map[*v1.Node]*extenderv1.Victims{}
	var resultLock sync.Mutex

	// We can use the same metadata producer for all nodes.
	meta := g.predicateMetaProducer(pod, g.nodeInfoSnapshot)
	checkNode := func(i int) {
		nodeName := potentialNodes[i].Name
		if g.nodeInfoSnapshot.NodeInfoMap[nodeName] == nil {
			return
		}
		nodeInfoCopy := g.nodeInfoSnapshot.NodeInfoMap[nodeName].Clone()
		var metaCopy predicates.Metadata
		if meta != nil {
			metaCopy = meta.ShallowCopy()
		}
		stateCopy := state.Clone()
		stateCopy.Write(migration.PredicatesStateKey, &migration.PredicatesStateData{Reference: metaCopy})
		pods, numPDBViolations, fits := g.selectVictimsOnNode(ctx, stateCopy, pod, metaCopy, nodeInfoCopy, pdbs)
		if fits {
			resultLock.Lock()
			victims := extenderv1.Victims{
				Pods:             pods,
				NumPDBViolations: int64(numPDBViolations),
			}
			nodeToVictims[potentialNodes[i]] = &victims
			resultLock.Unlock()
		}
	}
	workqueue.ParallelizeUntil(context.TODO(), 16, len(potentialNodes), checkNode)
	return nodeToVictims, nil
}
```

这里看到了我们熟悉的函数：ParallelizeUntil，依旧是起了16个goroutine对所有候选node并发执行checkNode func，如下：

```go
// selectVictimsOnNode finds minimum set of pods on the given node that should
// be preempted in order to make enough room for "pod" to be scheduled. The
// minimum set selected is subject to the constraint that a higher-priority pod
// is never preempted when a lower-priority pod could be (higher/lower relative
// to one another, not relative to the preemptor "pod").
// The algorithm first checks if the pod can be scheduled on the node when all the
// lower priority pods are gone. If so, it sorts all the lower priority pods by
// their priority and then puts them into two groups of those whose PodDisruptionBudget
// will be violated if preempted and other non-violating pods. Both groups are
// sorted by priority. It first tries to reprieve as many PDB violating pods as
// possible and then does them same for non-PDB-violating pods while checking
// that the "pod" can still fit on the node.
// NOTE: This function assumes that it is never called if "pod" cannot be scheduled
// due to pod affinity, node affinity, or node anti-affinity reasons. None of
// these predicates can be satisfied by removing more pods from the node.
func (g *genericScheduler) selectVictimsOnNode(
	ctx context.Context,
	state *framework.CycleState,
	pod *v1.Pod,
	meta predicates.Metadata,
	nodeInfo *schedulernodeinfo.NodeInfo,
	pdbs []*policy.PodDisruptionBudget,
) ([]*v1.Pod, int, bool) {
    ...
}
```

selectVictimsOnNode用于发现node上最小的抢占pod集，另外满足一个原则：低优先级永远先于高优先级pod(相互比较，不是与pod P比较)被抢占(但是最后有可能低优先级pod被保留，高优先级pod被抢占，这个不矛盾，需要好好理解)

该函数首先检查如果抢占node上所有低优先级(低于pod P)的pod被删除后，pod P是否可以被调度在该节点上：

```go
// As the first step, remove all the lower priority pods from the node and
// check if the given pod can be scheduled.
podPriority := podutil.GetPodPriority(pod)
for _, p := range nodeInfo.Pods() {
    if podutil.GetPodPriority(p) < podPriority {
        potentialVictims = append(potentialVictims, p)
        if err := removePod(p); err != nil {
            return nil, 0, false
        }
    }
}
// If the new pod does not fit after removing all the lower priority pods,
// we are almost done and this node is not suitable for preemption. The only
// condition that we could check is if the "pod" is failing to schedule due to
// inter-pod affinity to one or more victims, but we have decided not to
// support this case for performance reasons. Having affinity to lower
// priority pods is not a recommended configuration anyway.
if fits, _, _, err := g.podFitsOnNode(ctx, state, pod, meta, nodeInfo, false); !fits {
    if err != nil {
        klog.Warningf("Encountered error while selecting victims on node %v: %v", nodeInfo.Node().Name, err)
    }

    return nil, 0, false
}
```

如果去掉所有低优先级pod，还是无法通过预选策略，则认为该节点不适合抢占，直接返回

如果通过预选，则会将抢占pod按照优先级排序，并将它们分为两个队列(同样按照优先级排序)：PodDisruptionBudget被破坏，PodDisruptionBudget没有被破坏。之后，在保障pod P依旧可以被调度在node条件下，按照PDB被破坏 => PDB不被破坏顺序，从列表中尽可能赦免一些pod，使得他们可以继续运行在node上，不被抢占，从而达到选择最小抢占pod集

```go
var victims []*v1.Pod
numViolatingVictim := 0
sort.Slice(potentialVictims, func(i, j int) bool { return util.MoreImportantPod(potentialVictims[i], potentialVictims[j]) })
// Try to reprieve as many pods as possible. We first try to reprieve the PDB
// violating victims and then other non-violating ones. In both cases, we start
// from the highest priority victims.
violatingVictims, nonViolatingVictims := filterPodsWithPDBViolation(potentialVictims, pdbs)
reprievePod := func(p *v1.Pod) (bool, error) {
    if err := addPod(p); err != nil {
        return false, err
    }
    fits, _, _, _ := g.podFitsOnNode(ctx, state, pod, meta, nodeInfo, false)
    if !fits {
        if err := removePod(p); err != nil {
            return false, err
        }
        victims = append(victims, p)
        klog.V(5).Infof("Pod %v/%v is a potential preemption victim on node %v.", p.Namespace, p.Name, nodeInfo.Node().Name)
    }
    return fits, nil
}
for _, p := range violatingVictims {
    if fits, err := reprievePod(p); err != nil {
        klog.Warningf("Failed to reprieve pod %q: %v", p.Name, err)
        return nil, 0, false
    } else if !fits {
        numViolatingVictim++
    }
}
// Now we try to reprieve non-violating victims.
for _, p := range nonViolatingVictims {
    if _, err := reprievePod(p); err != nil {
        klog.Warningf("Failed to reprieve pod %q: %v", p.Name, err)
        return nil, 0, false
    }
}
return victims, numViolatingVictim, true

...
// MoreImportantPod return true when priority of the first pod is higher than
// the second one. If two pods' priorities are equal, compare their StartTime.
// It takes arguments of the type "interface{}" to be used with SortableList,
// but expects those arguments to be *v1.Pod.
func MoreImportantPod(pod1, pod2 *v1.Pod) bool {
	p1 := podutil.GetPodPriority(pod1)
	p2 := podutil.GetPodPriority(pod2)
	if p1 != p2 {
		return p1 > p2
	}
	return GetPodStartTime(pod1).Before(GetPodStartTime(pod2))
}
```

最后成功返回抢占victims，对应的selectNodesForPreemption返回nodeToVictims： 

```go
pods, numPDBViolations, fits := g.selectVictimsOnNode(ctx, stateCopy, pod, metaCopy, nodeInfoCopy, pdbs)
if fits {
    resultLock.Lock()
    victims := extenderv1.Victims{
        Pods:             pods,
        NumPDBViolations: int64(numPDBViolations),
    }
    nodeToVictims[potentialNodes[i]] = &victims
    resultLock.Unlock()
}
```

* step4 - 选出一个候选节点

```go
// pickOneNodeForPreemption chooses one node among the given nodes. It assumes
// pods in each map entry are ordered by decreasing priority.
// It picks a node based on the following criteria:
// 1. A node with minimum number of PDB violations.
// 2. A node with minimum highest priority victim is picked.
// 3. Ties are broken by sum of priorities of all victims.
// 4. If there are still ties, node with the minimum number of victims is picked.
// 5. If there are still ties, node with the latest start time of all highest priority victims is picked.
// 6. If there are still ties, the first such node is picked (sort of randomly).
// The 'minNodes1' and 'minNodes2' are being reused here to save the memory
// allocation and garbage collection time.
func pickOneNodeForPreemption(nodesToVictims map[*v1.Node]*extenderv1.Victims) *v1.Node {
    ...
}
```

这里按照如下规则顺序从候选node列表中选择出最合适的节点：

1. 选取具有最小PDB violations数目的node
2. 选取具有最小的最高优先级的victims的node
3. 选取victim优先级之和最小的node
4. 选取具有最小victim数目的node
5. 选取victim中最高优先级启动时间最早的那个节点
6. 随机选取(第一个)

* step5 - 选出需要清理pod.status.nominatedNodeName的pod

由于pod P对node进行了抢占，可能会导致以前抢占该node的低优先级(< pod P)pod后面无法成功调度到该node上，需要清除掉这部分pod的pod.status.nominatedNodeName使得它们可以移动到activeQ队列中，并让scheduler重新对它们进行调度：

```go
// Lower priority pods nominated to run on this node, may no longer fit on
// this node. So, we should remove their nomination. Removing their
// nomination updates these pods and moves them to the active queue. It
// lets scheduler find another place for them.
nominatedPods := g.getLowerPriorityNominatedPods(pod, candidateNode.Name)
if nodeInfo, ok := g.nodeInfoSnapshot.NodeInfoMap[candidateNode.Name]; ok {
    return nodeInfo.Node(), nodeToVictims[candidateNode].Pods, nominatedPods, nil
}

// getLowerPriorityNominatedPods returns pods whose priority is smaller than the
// priority of the given "pod" and are nominated to run on the given node.
// Note: We could possibly check if the nominated lower priority pods still fit
// and return those that no longer fit, but that would require lots of
// manipulation of NodeInfo and PredicateMeta per nominated pod. It may not be
// worth the complexity, especially because we generally expect to have a very
// small number of nominated pods per node.
func (g *genericScheduler) getLowerPriorityNominatedPods(pod *v1.Pod, nodeName string) []*v1.Pod {
	pods := g.schedulingQueue.NominatedPodsForNode(nodeName)

	if len(pods) == 0 {
		return nil
	}

	var lowerPriorityPods []*v1.Pod
	podPriority := podutil.GetPodPriority(pod)
	for _, p := range pods {
		if podutil.GetPodPriority(p) < podPriority {
			lowerPriorityPods = append(lowerPriorityPods, p)
		}
	}
	return lowerPriorityPods
}

// NominatedPodsForNode returns pods that are nominated to run on the given node,
// but they are waiting for other pods to be removed from the node before they
// can be actually scheduled.
func (p *PriorityQueue) NominatedPodsForNode(nodeName string) []*v1.Pod {
	p.lock.RLock()
	defer p.lock.RUnlock()
	return p.nominatedPods.podsForNode(nodeName)
}

func (npm *nominatedPodMap) podsForNode(nodeName string) []*v1.Pod {
	if list, ok := npm.nominatedPods[nodeName]; ok {
		return list
	}
	return nil
}
```

这里就用到了nominatedPodMap，返回该Map中同样node下，优先级低于pod P的pod列表

#### 3. 对抢占node以及victims进行处理

回到scheduler.preempt(k8s.io/kubernetes/pkg/scheduler/scheduler.go)：

```go
node, victims, nominatedPodsToClear, err := sched.Algorithm.Preempt(ctx, state, preemptor, scheduleErr)
if err != nil {
    klog.Errorf("Error preempting victims to make room for %v/%v: %v", preemptor.Namespace, preemptor.Name, err)
    return "", err
}
var nodeName = ""
if node != nil {
    nodeName = node.Name
    // Update the scheduling queue with the nominated pod information. Without
    // this, there would be a race condition between the next scheduling cycle
    // and the time the scheduler receives a Pod Update for the nominated pod.
    sched.SchedulingQueue.UpdateNominatedPodForNode(preemptor, nodeName)

    // Make a call to update nominated node name of the pod on the API server.
    err = sched.podPreemptor.setNominatedNodeName(preemptor, nodeName)
    if err != nil {
        klog.Errorf("Error in preemption process. Cannot set 'NominatedPod' on pod %v/%v: %v", preemptor.Namespace, preemptor.Name, err)
        sched.SchedulingQueue.DeleteNominatedPodIfExists(preemptor)
        return "", err
    }

    for _, victim := range victims {
        if err := sched.podPreemptor.deletePod(victim); err != nil {
            klog.Errorf("Error preempting pod %v/%v: %v", victim.Namespace, victim.Name, err)
            return "", err
        }
        // If the victim is a WaitingPod, send a reject message to the PermitPlugin
        if waitingPod := fwk.GetWaitingPod(victim.UID); waitingPod != nil {
            waitingPod.Reject("preempted")
        }
        sched.Recorder.Eventf(victim, preemptor, v1.EventTypeNormal, "Preempted", "Preempting", "Preempted by %v/%v on node %v", preemptor.Namespace, preemptor.Name, nodeName)

    }
    metrics.PreemptionVictims.Observe(float64(len(victims)))
}
```

在获取抢占节点和victims后，首先更新pod P相关的nominated信息，将pod P对应的抢占node添加到nominatedPodMap中，如下：

```go
// Update the scheduling queue with the nominated pod information. Without
// this, there would be a race condition between the next scheduling cycle
// and the time the scheduler receives a Pod Update for the nominated pod.
sched.SchedulingQueue.UpdateNominatedPodForNode(preemptor, nodeName)

...
// UpdateNominatedPodForNode adds a pod to the nominated pods of the given node.
// This is called during the preemption process after a node is nominated to run
// the pod. We update the structure before sending a request to update the pod
// object to avoid races with the following scheduling cycles.
func (p *PriorityQueue) UpdateNominatedPodForNode(pod *v1.Pod, nodeName string) {
	p.lock.Lock()
	p.nominatedPods.add(pod, nodeName)
	p.lock.Unlock()
}
```

接着调用kube-apiserver更新pod P的`pod.status.nominatedNodeName`，如下：

```go
// Make a call to update nominated node name of the pod on the API server.
err = sched.podPreemptor.setNominatedNodeName(preemptor, nodeName)
if err != nil {
    klog.Errorf("Error in preemption process. Cannot set 'NominatedPod' on pod %v/%v: %v", preemptor.Namespace, preemptor.Name, err)
    sched.SchedulingQueue.DeleteNominatedPodIfExists(preemptor)
    return "", err
}

...
func (p *podPreemptorImpl) setNominatedNodeName(pod *v1.Pod, nominatedNodeName string) error {
	podCopy := pod.DeepCopy()
	podCopy.Status.NominatedNodeName = nominatedNodeName
	_, err := p.Client.CoreV1().Pods(pod.Namespace).UpdateStatus(podCopy)
	return err
}
```

之后，调用kube-apiserver删除抢占victims，如下：

```go
for _, victim := range victims {
    if err := sched.podPreemptor.deletePod(victim); err != nil {
        klog.Errorf("Error preempting pod %v/%v: %v", victim.Namespace, victim.Name, err)
        return "", err
    }
    // If the victim is a WaitingPod, send a reject message to the PermitPlugin
    if waitingPod := fwk.GetWaitingPod(victim.UID); waitingPod != nil {
        waitingPod.Reject("preempted")
    }
    sched.Recorder.Eventf(victim, preemptor, v1.EventTypeNormal, "Preempted", "Preempting", "Preempted by %v/%v on node %v", preemptor.Namespace, preemptor.Name, nodeName)

}

...
func (p *podPreemptorImpl) deletePod(pod *v1.Pod) error {
	return p.Client.CoreV1().Pods(pod.Namespace).Delete(pod.Name, &metav1.DeleteOptions{})
}

...
// unscheduled pod queue
podInformer.Informer().AddEventHandler(
    cache.FilteringResourceEventHandler{
        FilterFunc: func(obj interface{}) bool {
            switch t := obj.(type) {
            case *v1.Pod:
                return !assignedPod(t) && responsibleForPod(t, schedulerName)
            case cache.DeletedFinalStateUnknown:
                if pod, ok := t.Obj.(*v1.Pod); ok {
                    return !assignedPod(pod) && responsibleForPod(pod, schedulerName)
                }
                utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
                return false
            default:
                utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
                return false
            }
        },
        Handler: cache.ResourceEventHandlerFuncs{
            AddFunc:    sched.addPodToSchedulingQueue,
            UpdateFunc: sched.updatePodInSchedulingQueue,
            DeleteFunc: sched.deletePodFromSchedulingQueue,
        },
    },
)

...
func (sched *Scheduler) deletePodFromSchedulingQueue(obj interface{}) {
	var pod *v1.Pod
	switch t := obj.(type) {
	case *v1.Pod:
		pod = obj.(*v1.Pod)
	case cache.DeletedFinalStateUnknown:
		var ok bool
		pod, ok = t.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
			return
		}
	default:
		utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
		return
	}
	if err := sched.SchedulingQueue.Delete(pod); err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to dequeue %T: %v", obj, err))
	}
	if sched.VolumeBinder != nil {
		// Volume binder only wants to keep unassigned pods
		sched.VolumeBinder.DeletePodBindings(pod)
	}
	sched.Framework.RejectWaitingPod(pod.UID)
}

// Delete deletes the item from either of the two queues. It assumes the pod is
// only in one queue.
func (p *PriorityQueue) Delete(pod *v1.Pod) error {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.nominatedPods.delete(pod)
	err := p.activeQ.Delete(newPodInfoNoTimestamp(pod))
	if err != nil { // The item was probably not found in the activeQ.
		p.clearPodBackoff(pod)
		p.podBackoffQ.Delete(newPodInfoNoTimestamp(pod))
		p.unschedulableQ.delete(pod)
	}
	return nil
}
```

删除操作会出发scheduler pod DELETE事件，执行PriorityQueue相关的删除逻辑，其中就包括将pod相关信息从nominatedPodMap中删除

在添加完nominatedPodMap，更新pod P的`pod.status.nominatedNodeName`以及删除victims后，执行清理低优先级(< pod P)pod `pod.status.nominatedNodeName`操作，使其回到activeQ队列，重新被scheduler调度：

```go
potentialNodes := nodesWherePreemptionMightHelp(g.nodeInfoSnapshot.NodeInfoMap, fitError)
if len(potentialNodes) == 0 {
    klog.V(3).Infof("Preemption will not help schedule pod %v/%v on any node.", pod.Namespace, pod.Name)
    // In this case, we should clean-up any existing nominated node name of the pod.
    return nil, nil, []*v1.Pod{pod}, nil
}

...
// Clearing nominated pods should happen outside of "if node != nil". Node could
// be nil when a pod with nominated node name is eligible to preempt again,
// but preemption logic does not find any node for it. In that case Preempt()
// function of generic_scheduler.go returns the pod itself for removal of
// the 'NominatedPod' field.
for _, p := range nominatedPodsToClear {
    rErr := sched.podPreemptor.removeNominatedNodeName(p)
    if rErr != nil {
        klog.Errorf("Cannot remove 'NominatedPod' field of pod: %v", rErr)
        // We do not return as this error is not critical.
    }
}

func (p *podPreemptorImpl) removeNominatedNodeName(pod *v1.Pod) error {
	if len(pod.Status.NominatedNodeName) == 0 {
		return nil
	}
	return p.setNominatedNodeName(pod, "")
}

func (p *podPreemptorImpl) setNominatedNodeName(pod *v1.Pod, nominatedNodeName string) error {
	podCopy := pod.DeepCopy()
	podCopy.Status.NominatedNodeName = nominatedNodeName
	_, err := p.Client.CoreV1().Pods(pod.Namespace).UpdateStatus(podCopy)
	return err
}
```

注意这里"if node != nil"的一个特殊情况，就是pod P已经发生了抢占，但是调度失败了，这种情况下再次抢占会返回node=nil，而nominatedPodsToClear为pod P

对应的会触发pod的UPDATE事件，执行updatePodInSchedulingQueue函数，将pod放到activeQ队列中重新调度，同时，更新nominatedPodMap相关信息：

```go
func (sched *Scheduler) updatePodInSchedulingQueue(oldObj, newObj interface{}) {
	pod := newObj.(*v1.Pod)
	if sched.skipPodUpdate(pod) {
		return
	}
	if err := sched.SchedulingQueue.Update(oldObj.(*v1.Pod), pod); err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to update %T: %v", newObj, err))
	}
}

...
// Update updates a pod in the active or backoff queue if present. Otherwise, it removes
// the item from the unschedulable queue if pod is updated in a way that it may
// become schedulable and adds the updated one to the active queue.
// If pod is not present in any of the queues, it is added to the active queue.
func (p *PriorityQueue) Update(oldPod, newPod *v1.Pod) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if oldPod != nil {
		oldPodInfo := newPodInfoNoTimestamp(oldPod)
		// If the pod is already in the active queue, just update it there.
		if oldPodInfo, exists, _ := p.activeQ.Get(oldPodInfo); exists {
			p.nominatedPods.update(oldPod, newPod)
			err := p.activeQ.Update(updatePod(oldPodInfo, newPod))
			return err
		}

		// If the pod is in the backoff queue, update it there.
		if oldPodInfo, exists, _ := p.podBackoffQ.Get(oldPodInfo); exists {
			p.nominatedPods.update(oldPod, newPod)
			p.podBackoffQ.Delete(oldPodInfo)
			err := p.activeQ.Add(updatePod(oldPodInfo, newPod))
			if err == nil {
				p.cond.Broadcast()
			}
			return err
		}
	}

	// If the pod is in the unschedulable queue, updating it may make it schedulable.
	if usPodInfo := p.unschedulableQ.get(newPod); usPodInfo != nil {
		p.nominatedPods.update(oldPod, newPod)
		if isPodUpdated(oldPod, newPod) {
			// If the pod is updated reset backoff
			p.clearPodBackoff(newPod)
			p.unschedulableQ.delete(usPodInfo.Pod)
			err := p.activeQ.Add(updatePod(usPodInfo, newPod))
			if err == nil {
				p.cond.Broadcast()
			}
			return err
		}
		// Pod is already in unschedulable queue and hasnt updated, no need to backoff again
		p.unschedulableQ.addOrUpdate(updatePod(usPodInfo, newPod))
		return nil
	}
	// If pod is not in any of the queues, we put it in the active queue.
	err := p.activeQ.Add(p.newPodInfo(newPod))
	if err == nil {
		p.nominatedPods.add(newPod, "")
		p.cond.Broadcast()
	}
	return err
}
```

这样整个scheduler抢占流程就分析完了，总结过程如下：

首先从node列表中选取抢占node和对应的抢占victims，并枚举每个node上被抢占的最小pod列表；之后从这些node中按照一定规则选取出最佳抢占node

在选取出抢占node以及对应的victims后，执行相关的清理工作，包括：更新pod P相关的nominated信息，将pod P对应的抢占node添加到nominatedPodMap中，同时调用kube-apiserver更新pod P的`pod.status.nominatedNodeName`，使pod P从unschedulableQ列队移到activeQ队列，等待scheduler重新调度；接着调用kube-apiserver删除抢占victims，使这些pod从被抢占的node上消失；最后，清空低优先级抢占pod的`pod.status.nominatedNodeName`信息，使它们被scheduler重新调度

注意留意上述流程与nominatedPodMap之间的关系，nominatedPodMap记录了pod抢占相关信息，用于协助预选和抢占过程顺利完成

## Predicate(预选)

再分析完抢占后，我们再回过头来看看预选过程：

```go
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
// addNominatedPods adds pods with equal or greater priority which are nominated
// to run on the node given in nodeInfo to meta and nodeInfo. It returns 1) whether
// any pod was added, 2) augmented metadata, 3) augmented CycleState 4) augmented nodeInfo.
func (g *genericScheduler) addNominatedPods(ctx context.Context, pod *v1.Pod, meta predicates.Metadata, state *framework.CycleState,
	nodeInfo *schedulernodeinfo.NodeInfo) (bool, predicates.Metadata,
	*framework.CycleState, *schedulernodeinfo.NodeInfo, error) {
	if g.schedulingQueue == nil || nodeInfo == nil || nodeInfo.Node() == nil {
		// This may happen only in tests.
		return false, meta, state, nodeInfo, nil
	}
	nominatedPods := g.schedulingQueue.NominatedPodsForNode(nodeInfo.Node().Name)
	if len(nominatedPods) == 0 {
		return false, meta, state, nodeInfo, nil
	}
	nodeInfoOut := nodeInfo.Clone()
	var metaOut predicates.Metadata
	if meta != nil {
		metaOut = meta.ShallowCopy()
	}
	stateOut := state.Clone()
	stateOut.Write(migration.PredicatesStateKey, &migration.PredicatesStateData{Reference: metaOut})
	podsAdded := false
	for _, p := range nominatedPods {
		if podutil.GetPodPriority(p) >= podutil.GetPodPriority(pod) && p.UID != pod.UID {
			nodeInfoOut.AddPod(p)
			if metaOut != nil {
				if err := metaOut.AddPod(p, nodeInfoOut.Node()); err != nil {
					return false, meta, state, nodeInfo, err
				}
			}
			status := g.framework.RunPreFilterExtensionAddPod(ctx, stateOut, pod, p, nodeInfoOut)
			if !status.IsSuccess() {
				return false, meta, state, nodeInfo, status.AsError()
			}
			podsAdded = true
		}
	}
	return podsAdded, metaOut, stateOut, nodeInfoOut, nil
}
```

这里我们应该对预选算法中2次执行的逻辑更加清晰了，第一遍是为了确保pod P在抢占pod(优先级 >= pod P)最终成功调度在node情况下能够正常运行；第二遍是为了确保pod P在抢占pod(优先级 >= pod P)最终没有调度在node情况下能够成功运行。最有这两种情况都满足，我们才能确保pod P是可以被调度到node上的

## Refs

* [Pod Priority and Preemption](https://kubernetes.io/docs/concepts/configuration/pod-priority-preemption/)