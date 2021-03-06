SuperEdge 分布式健康检查edge-health-admission源码分析
=================================================

## 前言

SuperEdge分布式健康检查功能由边端的edge-health-daemon以及云端的edge-health-admission组成：

* edge-health-daemon：对同区域边缘节点执行分布式健康检查，并向apiserver发送健康状态投票结果(给node打annotation)
* edge-health-admission：不断根据node edge-health annotation调整kube-controller-manager设置的node taint(去掉NoExecute taint)以及endpoints(将失联节点上的pods从endpoint subsets notReadyAddresses移到addresses中)，从而实现云端和边端共同决定节点状态

整体架构如下所示：

![](images/edge-health-arch.png)

之所以创建edge-health-admission云端组件，是因为当云边断连时，kube-controller-manager会执行如下操作：

* 失联的节点被置为ConditionUnknown状态，并被添加NoSchedule和NoExecute的taints
* 失联的节点上的pod从Service的Endpoint列表中移除

当edge-health-daemon在边端根据健康检查判断节点状态正常时，会更新node：去掉NoExecute taint。但是在node成功更新之后又会被kube-controller-manager给刷回去(再次添加NoExecute taint)，因此必须添加Kubernetes mutating admission webhook也即edge-health-admission将kube-controller-manager对node api resource的更改做调整，最终实现分布式健康检查效果

本文将基于我对edge-health的重构PR [Refactor edge-health and admission webhook for a better maintainability and extendibility](https://github.com/superedge/superedge/pull/46) 分析edge-health-admission组件，在深入源码之前先介绍一下[Kubernetes Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)





## edge-health-admission源码分析

## 总结

## 展望