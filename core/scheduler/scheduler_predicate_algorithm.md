Kubernetes Scheduler Algorithm - Predicate
==========================================

在介绍完scheduler的整体框架后，本章开始介绍算法调度——预选流程

回到scheduler调度算法入口：

```go
scheduleResult, err := sched.Algorithm.Schedule(schedulingCycleCtx, state, pod)
```

其中`genericScheduler.Schedule`负责具体的调度过程，在经过预选和优选算法后，最终返回一个最合适的调度node，如下：

```go
// Schedule tries to schedule the given pod to one of the nodes in the node list.
// If it succeeds, it will return the name of the node.
// If it fails, it will return a FitError error with reasons.
func (g *genericScheduler) Schedule(ctx context.Context, state *framework.CycleState, pod *v1.Pod) (result ScheduleResult, err error) {
    ...
	filteredNodes, failedPredicateMap, filteredNodesStatuses, err := g.findNodesThatFit(ctx, state, pod)
	if err != nil {
		return result, err
	}
	trace.Step("Computing predicates done")
    ...
    priorityList, err := g.prioritizeNodes(ctx, state, pod, metaPrioritiesInterface, filteredNodes)
	if err != nil {
		return result, err
	}
    ...
    host, err := g.selectHost(priorityList)
	trace.Step("Prioritizing done")

	return ScheduleResult{
		SuggestedHost:  host,
		EvaluatedNodes: len(filteredNodes) + len(failedPredicateMap) + len(filteredNodesStatuses),
		FeasibleNodes:  len(filteredNodes),
	}, err        
}
```

上述截取了最关键的几个部分：

* findNodesThatFit：预选算法，从所有节点中过滤出满足预选策略的节点filteredNodes，并进入优选阶段
* prioritizeNodes：优选算法，对预选过滤出的节点filteredNodes，根据优选策略分别进行打分，得到priorityList
* selectHost：从优选列表中选择出总分最高的一个节点，最后返回该节点名称和相关信息

本章主要分析预选算法，也就是`findNodesThatFit`部分。预选可以大致分为三个步骤：

1. 获取节点信息

获取所有节点以及最少可行的节点数目(达到这个数目就可以停止预选，进入优选了)：

```go
allNodes := len(g.nodeInfoSnapshot.NodeInfoList)
numNodesToFind := g.numFeasibleNodesToFind(int32(allNodes))

...
// numFeasibleNodesToFind returns the number of feasible nodes that once found, the scheduler stops
// its search for more feasible nodes.
func (g *genericScheduler) numFeasibleNodesToFind(numAllNodes int32) (numNodes int32) {
	if numAllNodes < minFeasibleNodesToFind || g.percentageOfNodesToScore >= 100 {
		return numAllNodes
	}

	adaptivePercentage := g.percentageOfNodesToScore
	if adaptivePercentage <= 0 {
		basePercentageOfNodesToScore := int32(50)
		adaptivePercentage = basePercentageOfNodesToScore - numAllNodes/125
		if adaptivePercentage < minFeasibleNodesPercentageToFind {
			adaptivePercentage = minFeasibleNodesPercentageToFind
		}
	}

	numNodes = numAllNodes * adaptivePercentage / 100
	if numNodes < minFeasibleNodesToFind {
		return minFeasibleNodesToFind
	}

	return numNodes
}
```

2. 并发执行预选算法

在分析具体代码前，我们先看一下Kubernetes构建的内部[goroutine pool](https://github.com/kubernetes/kubernetes/blob/v1.17.4/staging/src/k8s.io/client-go/util/workqueue/parallelizer.go)，如下：

```go
type DoWorkPieceFunc func(piece int)

// ParallelizeUntil is a framework that allows for parallelizing N
// independent pieces of work until done or the context is canceled.
func ParallelizeUntil(ctx context.Context, workers, pieces int, doWorkPiece DoWorkPieceFunc) {
	var stop <-chan struct{}
	if ctx != nil {
		stop = ctx.Done()
	}

	toProcess := make(chan int, pieces)
	for i := 0; i < pieces; i++ {
		toProcess <- i
	}
	close(toProcess)

	if pieces < workers {
		workers = pieces
	}

	wg := sync.WaitGroup{}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer utilruntime.HandleCrash()
			defer wg.Done()
			for piece := range toProcess {
				select {
				case <-stop:
					return
				default:
					doWorkPiece(piece)
				}
			}
		}()
	}
	wg.Wait()
}
```

`ParallelizeUntil`是一个轻量级的多goroutine并发处理函数，参数含义如下：

* workers：表示并发处理的goroutine数目
* pieces：表示总共需要处理的任务数目
* doWorkPiece：表示具体的执行函数
* ctx：用于结束通知，当调用context cancel()时，会结束处理

Kubernetes将并发处理逻辑抽象成`ParallelizeUntil`，以便利用该函数方便地进行并发调用

在简单了解`ParallelizeUntil`的功能后，我们再切回来看预选执行代码：

```go
// Create filtered list with enough space to avoid growing it
// and allow assigning.
filtered = make([]*v1.Node, numNodesToFind)
errCh := util.NewErrorChannel()
var (
    predicateResultLock sync.Mutex
    filteredLen         int32
)

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
```

可以看到固定起了16个goroutine对节点检查预选策略(到目前为止硬编码为16，是否可以参数化，还是没有必要，可以讨论)。而执行预选的具体内容为checkNode

checkNode的逻辑也很清晰，对node执行podFitsOnNode预选。如果通过，则添加到filtered切片中；否则把错误信息存放到`filteredNodesStatuses`与`failedPredicateMap`中

当通过预选算法达到指定最少数目节点时，整个检查过程会退出。之后通过该次所有执行检查的节点数目设置下一次预选检查的起点以保障所有节点检查的机会均等

深入`podFitsOnNode`查看具体的预选过程：

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

}
```

题外话：评价一个代码是否可读性好的一个很重要的依据就是注释是否写的清晰扼要，而Kubernetes在这方便就做的很好，是一个很好的golang代码参考规范

通过注释知道：podFitsOnNode用于检查node是否满足给定的预选策略，这个函数会在`Schedule`和`Preempt`两种场景下被调用，`Preempt`相比`Schedule`会在调用这个函数前剔除掉被抢占的pods

podFitsOnNode主体会有两遍检查，第一遍会假定优先级大于或等于检查pod的被任命的pod已经在node上运行了；第二遍假定优先级大于或等于检查pod的被任命的pod没有在node上运行。这两种场景下node都能通过预选策略，才可以认为是该节点可被调度

查看核心预选代码：

```go
// IMPORTANT NOTE: this list contains the ordering of the predicates, if you develop a new predicate
// it is mandatory to add its name to this list.
// Otherwise it won't be processed, see generic_scheduler#podFitsOnNode().
// The order is based on the restrictiveness & complexity of predicates.
// Design doc: https://github.com/kubernetes/community/blob/master/contributors/design-proposals/scheduling/predicates-ordering.md
var (
	predicatesOrdering = []string{CheckNodeUnschedulablePred,
		GeneralPred, HostNamePred, PodFitsHostPortsPred,
		MatchNodeSelectorPred, PodFitsResourcesPred, NoDiskConflictPred,
		PodToleratesNodeTaintsPred, PodToleratesNodeNoExecuteTaintsPred, CheckNodeLabelPresencePred,
		CheckServiceAffinityPred, MaxEBSVolumeCountPred, MaxGCEPDVolumeCountPred, MaxCSIVolumeCountPred,
		MaxAzureDiskVolumeCountPred, MaxCinderVolumeCountPred, CheckVolumeBindingPred, NoVolumeZoneConflictPred,
		EvenPodsSpreadPred, MatchInterPodAffinityPred}
)

// Ordering returns the ordering of predicates.
func Ordering() []string {
	return predicatesOrdering
}

...

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
```

这段代码逻辑很清晰：首先遍历所有预选策略，然后逐一进行判断是否符合。这里我们举一个最常用的预选策略例子`PodFitsResourcesPred`进行说明：

```go
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

// CreateFromKeys creates a scheduler from a set of registered fit predicate keys and priority keys.
func (c *Configurator) CreateFromKeys(predicateKeys, priorityKeys sets.String, extenders []algorithm.SchedulerExtender) (*Scheduler, error) {
	klog.V(2).Infof("Creating scheduler with fit predicates '%v' and priority functions '%v'", predicateKeys, priorityKeys)

	predicateFuncs, pluginsForPredicates, pluginConfigForPredicates, err := c.getPredicateConfigs(predicateKeys)
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
```

从上面代码追踪到`PodFitsResourcesPred`预选策略对应的逻辑为：`PodFitsResources`，如下：

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

// GetResourceRequest returns a *schedulernodeinfo.Resource that covers the largest
// width in each resource dimension. Because init-containers run sequentially, we collect
// the max in each dimension iteratively. In contrast, we sum the resource vectors for
// regular containers since they run simultaneously.
//
// If Pod Overhead is specified and the feature gate is set, the resources defined for Overhead
// are added to the calculated Resource request sum
//
// Example:
//
// Pod:
//   InitContainers
//     IC1:
//       CPU: 2
//       Memory: 1G
//     IC2:
//       CPU: 2
//       Memory: 3G
//   Containers
//     C1:
//       CPU: 2
//       Memory: 1G
//     C2:
//       CPU: 1
//       Memory: 1G
//
// Result: CPU: 3, Memory: 3G
func GetResourceRequest(pod *v1.Pod) *schedulernodeinfo.Resource {
	result := &schedulernodeinfo.Resource{}
	for _, container := range pod.Spec.Containers {
		result.Add(container.Resources.Requests)
	}

	// take max_resource(sum_pod, any_init_container)
	for _, container := range pod.Spec.InitContainers {
		result.SetMaxResource(container.Resources.Requests)
	}

	// If Overhead is being utilized, add to the total requests for the pod
	if pod.Spec.Overhead != nil && utilfeature.DefaultFeatureGate.Enabled(features.PodOverhead) {
		result.Add(pod.Spec.Overhead)
	}

	return result
}
```

首先判断是否超过node允许的pod数目；接着计算pod需要的资源(Max(InitContainers, Containers) + Overhead)；最后判断node剩余资源是否足够pod运行

至此，预选流程分析大致结束，接下来分析优选算法……