Kubernetes Scheduler Principle
==============================

Scheduler是Kubernetes组件中功能&逻辑相对单一&简单的模块，分析Kubernetes源码从scheduler开始是一个不错的选择

一句话总结scheduler的功能就是：watch kube-apiserver，监听`PodSpec.NodeName`为空的pod，并利用预选和优选算法为该pod选择一个最佳的调度node节点，最终将pod与该node进行绑定

## The scheduling algorithm

如上所述，scheduler会依次为每个pod选择一个node，选择的算法流程大致如下：

```
For given pod:

    +---------------------------------------------+
    |               Schedulable nodes:            |
    |                                             |
    | +--------+    +--------+      +--------+    |
    | | node 1 |    | node 2 |      | node 3 |    |
    | +--------+    +--------+      +--------+    |
    |                                             |
    +-------------------+-------------------------+
                        |
                        |
                        v
    +-------------------+-------------------------+

    Pred. filters: node 3 doesn't have enough resource

    +-------------------+-------------------------+
                        |
                        |
                        v
    +-------------------+-------------------------+
    |             remaining nodes:                |
    |   +--------+                 +--------+     |
    |   | node 1 |                 | node 2 |     |
    |   +--------+                 +--------+     |
    |                                             |
    +-------------------+-------------------------+
                        |
                        |
                        v
    +-------------------+-------------------------+

    Priority function:    node 1: p=2
                          node 2: p=5

    +-------------------+-------------------------+
                        |
                        |
                        v
            select max{node priority} = node 2
```

从上图可以看出，选择流程可以分为三步：

* 预选 - scheduler会遍历每个node，查看是否满足设置的一系列预选策略(例如：最基本的资源是否足够)。并剔除掉无法满足所有预选策略的节点，剩下的节点进入优选阶段
* 优选 - scheduler会对通过预选阶段的每个节点按照一系列优选策略进行打分(例如：最低负载)，并统计每个节点优选总分
* 选择 - 最后，在通过优选阶段后，选择具有最高总分的节点作为pod的调度节点(如果总分相同，则随机选取)

### Predicates and priorities policies

这里补充介绍一下预选和优选策略。顾名思义：预选策略用于过滤，剔除不合适的节点；而优选策略则用于选择出最合适的节点。两种策略侧重点不同，作用阶段也不同，具体策略可以参考[如下](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-scheduling/scheduler_algorithm.md)。另外Kubernetes分别内置了这两种策略，这在后续源码分析中会详细介绍，这里不展开

## 入口函数

Scheduler的总入口如下：

* [cmd/kube-scheduler/scheduler.go](https://github.com/kubernetes/kubernetes/blob/v1.17.4/cmd/kube-scheduler/scheduler.go)：负责scheduler的初始化
* [pkg/scheduler/scheduler.go:](https://github.com/kubernetes/kubernetes/blob/v1.17.4/pkg/scheduler/scheduler.go)：scheduler的整体框架代码(除开了调度算法这块)
* [pkg/scheduler/core/generic_scheduler.go](https://github.com/kubernetes/kubernetes/blob/v1.17.4/pkg/scheduler/core/generic_scheduler.go)：scheduler的调度代码(预选&优选)

我们后续将从这三个入口对scheduler源码展开分析

## Refs

* [scheduler community](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-scheduling/scheduler.md)