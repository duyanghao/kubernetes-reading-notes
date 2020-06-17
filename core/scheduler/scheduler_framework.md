Kubernetes Scheduler Framework
==============================

在简单介绍完Scheduler的初始化流程后，下面开始分析scheduler的整体框架代码

如下是框架入口代码：

```go
// Run begins watching and scheduling. It waits for cache to be synced, then starts scheduling and blocked until the context is done.
func (sched *Scheduler) Run(ctx context.Context) {
	if !cache.WaitForCacheSync(ctx.Done(), sched.scheduledPodsHasSynced) {
		return
	}

	wait.UntilWithContext(ctx, sched.scheduleOne, 0)
}
```

`scheduleOne`负责pod调度的整体流程，从这个函数可以窥见scheduler的大致工作原理：

```go
// scheduleOne does the entire scheduling workflow for a single pod.  It is serialized on the scheduling algorithm's host fitting.
func (sched *Scheduler) scheduleOne(ctx context.Context) {
	...
}
```

我们对该函数逐块进行分析，依次整理各个步骤要完成的事情

## step1 - 获取待调度的pod

```go
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
```

典型的controller代码逻辑，从cache队列中获取待调度的pod，进行简单的容错判断，最后打印标示功能

## step2 - 对pod寻找待调度node

```go
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
```

具体执行调度算法的逻辑为：

```go
scheduleResult, err := sched.Algorithm.Schedule(schedulingCycleCtx, state, pod)
```

这个我们后面在预选和优选算法中会具体分析，这里不展开；最终返回调度结果，如下：

```go
// ScheduleResult represents the result of one pod scheduled. It will contain
// the final selected Node, along with the selected intermediate information.
type ScheduleResult struct {
	// Name of the scheduler suggest host
	SuggestedHost string
	// Number of nodes scheduler evaluated on one pod scheduled
	EvaluatedNodes int
	// Number of feasible nodes on one pod scheduled
	FeasibleNodes int
}
```

## step3 - Assume volume&Assume pod

```go
// Tell the cache to assume that a pod now is running on a given node, even though it hasn't been bound yet.
// This allows us to keep scheduling without waiting on binding to occur.
assumedPodInfo := podInfo.DeepCopy()
assumedPod := assumedPodInfo.Pod

// Assume volumes first before assuming the pod.
//
// If all volumes are completely bound, then allBound is true and binding will be skipped.
//
// Otherwise, binding of volumes is started after the pod is assumed, but before pod binding.
//
// This function modifies 'assumedPod' if volume binding is required.
allBound, err := sched.VolumeBinder.Binder.AssumePodVolumes(assumedPod, scheduleResult.SuggestedHost)
if err != nil {
    sched.recordSchedulingFailure(assumedPodInfo, err, SchedulerError,
        fmt.Sprintf("AssumePodVolumes failed: %v", err))
    metrics.PodScheduleErrors.Inc()
    return
}

// Run "reserve" plugins.
if sts := fwk.RunReservePlugins(schedulingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost); !sts.IsSuccess() {
    sched.recordSchedulingFailure(assumedPodInfo, sts.AsError(), SchedulerError, sts.Message())
    metrics.PodScheduleErrors.Inc()
    return
}

// assume modifies `assumedPod` by setting NodeName=scheduleResult.SuggestedHost
err = sched.assume(assumedPod, scheduleResult.SuggestedHost)
if err != nil {
    // This is most probably result of a BUG in retrying logic.
    // We report an error here so that pod scheduling can be retried.
    // This relies on the fact that Error will check if the pod has been bound
    // to a node and if so will not add it back to the unscheduled pods queue
    // (otherwise this would cause an infinite loop).
    sched.recordSchedulingFailure(assumedPodInfo, err, SchedulerError, fmt.Sprintf("AssumePod failed: %v", err))
    metrics.PodScheduleErrors.Inc()
    // trigger un-reserve plugins to clean up state associated with the reserved Pod
    fwk.RunUnreservePlugins(schedulingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
    return
}
```

AssumePodVolumes用于产生pod对应的PVs and PVCs；而assume用于设置pod属性`NodeName=scheduleResult.SuggestedHost`

## step4 - pod与node进行绑定

```go
// bind the pod to its host asynchronously (we can do this b/c of the assumption step above).
go func() {
    bindingCycleCtx, cancel := context.WithCancel(ctx)
    defer cancel()
    metrics.SchedulerGoroutines.WithLabelValues("binding").Inc()
    defer metrics.SchedulerGoroutines.WithLabelValues("binding").Dec()

    // Run "permit" plugins.
    permitStatus := fwk.RunPermitPlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
    if !permitStatus.IsSuccess() {
        var reason string
        if permitStatus.IsUnschedulable() {
            metrics.PodScheduleFailures.Inc()
            reason = v1.PodReasonUnschedulable
        } else {
            metrics.PodScheduleErrors.Inc()
            reason = SchedulerError
        }
        if forgetErr := sched.Cache().ForgetPod(assumedPod); forgetErr != nil {
            klog.Errorf("scheduler cache ForgetPod failed: %v", forgetErr)
        }
        // trigger un-reserve plugins to clean up state associated with the reserved Pod
        fwk.RunUnreservePlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
        sched.recordSchedulingFailure(assumedPodInfo, permitStatus.AsError(), reason, permitStatus.Message())
        return
    }

    // Bind volumes first before Pod
    if !allBound {
        err := sched.bindVolumes(assumedPod)
        if err != nil {
            sched.recordSchedulingFailure(assumedPodInfo, err, "VolumeBindingFailed", err.Error())
            metrics.PodScheduleErrors.Inc()
            // trigger un-reserve plugins to clean up state associated with the reserved Pod
            fwk.RunUnreservePlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
            return
        }
    }

    // Run "prebind" plugins.
    preBindStatus := fwk.RunPreBindPlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
    if !preBindStatus.IsSuccess() {
        var reason string
        metrics.PodScheduleErrors.Inc()
        reason = SchedulerError
        if forgetErr := sched.Cache().ForgetPod(assumedPod); forgetErr != nil {
            klog.Errorf("scheduler cache ForgetPod failed: %v", forgetErr)
        }
        // trigger un-reserve plugins to clean up state associated with the reserved Pod
        fwk.RunUnreservePlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
        sched.recordSchedulingFailure(assumedPodInfo, preBindStatus.AsError(), reason, preBindStatus.Message())
        return
    }

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
}()
```

最后通过设置`binding object`，异步地进行pod与node之间的绑定：

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

接下来我们分析预选流程……