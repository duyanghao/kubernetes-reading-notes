Kubernetes Scheduler Extensibility - Scheduler Framework
========================================================

## Overview

extender提供了非侵入scheduler core的方式扩展scheduler，但是有如下缺点：

* 缺少灵活性：extender提供的接口只能由scheduler core在固定点调用，比如："Filter" extenders只能在默认预选结束后进行调用；而"Prioritize" extenders只能在默认优选执行后调用
* 性能差：相比原生调用func来说，走http/https + 加解JSON包开销较大
* 错误处理困难：scheduler core在调用extender后，如果出现错误，需要中断调用，很难将错误信息传递给extender，终止extender逻辑
* 无法共享cache：extender是webhook，以单独的server形式与scheduler一起运行，如果scheduler core提供的参数无法满足extender处理需求，同时由于无法共享scheduler core cache，那么extender需要自行与kube-apiserver进行通信，并建立cache    

为了解决scheduler extender存在的问题，scheduler framework在scheduler core基础上进行了改造和提取，在scheduler几乎所有关键路径上设置了plugins扩展点，用户可以在不修改scheduler core代码的前提下开发plugins，最后与core一起编译打包成二进制包实现扩展

## Scheduling Cycle & Binding Cycle

scheduler整个调度流程可以分为如下两个阶段：

* scheduling cycle：选择出一个节点以供pod运行，主要包括预选&优选，串行执行
* binding cycle：将scheduling cycle选择的node与pod进行绑定，主要包括bind操作，并发执行

这两个阶段合称为"scheduling context"，每个阶段在调度失败或者发生错误时都可能发生中断并被放入scheduler队列等待重新调度

## Extension points

pod调度流程以及对应的scheduler plugins扩展点如下：

![](../images/scheduler_plugin_extension.png)

这里按照调用顺序依次介绍各个plugin扩展点：

* Queue sort：用于对scheduelr优先级队列进行排序，需要实现"less(pod1, pod2)"接口，且该插件只会生效一个
* Pre-filter：用于检查集群和pod需要满足的条件，或者对pod进行预选 预处理，需要实现"PreFilter"接口
* Filter：对应scheduler预选算法，用于根据预选策略对节点进行过滤
* Pre-Score：对应"Pre-filter"，主要用于优选 预处理，比如：更新cache，产生logs/metrics等
* Scoring：对应scheduler优选算法，分为"score"(Map)和"normalize scoring"(Reduce)两个阶段
  * score：并发执行node打分；同一个node在打分的时候，并发执行所有插件对该node进行score
  * normalize scoring：并发执行所有插件的normalize scoring；每个插件对所有节点score进行reduce，最终将分数限制在[MinNodeScore, MaxNodeScore]有效范围
* Reserve(aka Assume)：scheduling cycle的最后一步，用于将node相关资源预留(assume)给pod，更新scheduler cache；binding cycle执行失败，则会执行对应的Un-reserve插件，清理掉与pod相关的assume资源，并进行scheduling queue等待重新调度
* Permit：binding cycle的第一个步骤，判断是否允许pod与node执行bind，有如下三种行为：
  * approve：允许，进入Pre-bind流程
  * deny：不允许，执行Un-reserve插件，并进入scheduling queue等待重新调度
  * wait (with a timeout)：pod将一直持续处于Permit阶段，直到approve，进入Pre-bind；如果超时，则会被deny，等待重新被调度
* Pre-bind：执行bind操作之前的准备工作，例如volume相关的操作
* Bind：用于执行pod与node之间的绑定操作，只有在所有pre-bind plugins相关操作都完成的情况下才会被执行；另外，如果一个bind插件选择处理pod，那么其它bind插件都会被忽略 
* Post-bind：binding cycle最后一个步骤，用于在bind操作执行成功后清理相关资源

在介绍完scheduler framework扩展点后，我们开始介绍如何按照framework规范进行plugins开发

## Plugin dev process

#### step1 - Plugin Registration



#### step2 - Plugin dev

#### step3 - Configuring Plugins

## coscheduling(aka gang scheduling)

## Refs

* [Scheduling Framework](https://kubernetes.io/docs/concepts/scheduling-eviction/scheduling-framework/)
* [Scheduling Profiles](https://kubernetes.io/docs/reference/scheduling/profiles/)
* [design proposal of the scheduling framework](https://github.com/kubernetes/enhancements/blob/master/keps/sig-scheduling/20180409-scheduling-framework.md)
* [scheduler-plugins](https://github.com/kubernetes-sigs/scheduler-plugins)