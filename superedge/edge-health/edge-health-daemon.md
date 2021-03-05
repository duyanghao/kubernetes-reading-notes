SuperEdge 分布式健康检查edge-health-daemon源码分析
==============================================

## 前言

边缘计算场景下，边缘节点与云端的网络环境十分复杂，连接并不可靠，在原生Kubernetes集群中，会造成apiserver和节点连接的中断，节点状态的异常，最终导致pod的驱逐和endpoint的缺失，造成服务的中断和波动，具体来说原生Kubernetes处理如下：

* 失联的节点被置为ConditionUnknown状态，并被添加NoSchedule和NoExecute的taints
* 失联的节点上的pod被驱逐，并在其他节点上进行重建
* 失联的节点上的pod从Service的Endpoint列表中移除

因此，边缘计算场景仅仅依赖边端和apiserver的连接情况是不足以判断节点是否异常的，会因为网络的不可靠造成误判，影响正常服务。而相较于云端和边缘端的连接，显然边端节点之间的连接更为稳定，具有一定的参考价值，因此superedge提出了边缘分布式健康检查机制。该机制中节点状态判定除了要考虑apiserver的因素外，还引入了节点的评估因素，进而对节点进行更为全面的状态判断。通过这个功能，能够避免由于云边网络不可靠造成的大量的pod迁移和重建，保证服务的稳定

具体来说，主要通过如下三个层面增强节点状态判断的准确性：

* 每个节点定期探测其他节点健康状态
* 集群内所有节点定期投票决定各节点的状态
* 云端和边端节点共同决定节点状态

而分布式健康检查最终的判断处理如下：

![](images/edge-health-effect.png)

## edge-health-daemon源码分析

分布式健康检查架构图如下：

![](images/edge-health-arch.png)

从图中可以看到分布式健康检查功能实现组件有两个：

* edge-health-daemon(边缘)：负责对同区域边缘节点执行分布式健康检查，并向apiserver发送健康状态投票结果
* edge-health-admission(云端)：[Kubernetes mutating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook)，负责在云端协助edge-health-daemon完成最终边缘节点状态的裁定

本章将介绍edge-health-daemon原理。在深入源码之前先介绍一下edge-health-daemon相关数据结构：

```go
type EdgeHealthMetadata struct {
	*NodeMetadata
	*CheckMetadata
}

type NodeMetadata struct {
	NodeList []v1.Node
	sync.RWMutex
}

type CheckMetadata struct {
	CheckInfo            map[string]map[string]CheckDetail // Checker ip:{Checked ip:Check detail}
	CheckPluginScoreInfo map[string]map[string]float64     // Checked ip:{Plugin name:Check score}
	sync.RWMutex
}

type CheckDetail struct {
	Normal bool
	Time   time.Time
}

type CommunInfo struct {
	SourceIP    string                 // ClientIP，Checker ip
	CheckDetail map[string]CheckDetail // Checked ip:Check detail
	Hmac        string
}
```

含义如下：

* NodeMetadata：为了实现分区域分布式健康检查机制而维护的边缘节点cache，其中包含该区域内的所有边缘节点列表NodeList
* CheckMetadata：存放健康检查的结果，具体来说包括两个数据结构：
  * CheckPluginScoreInfo：为`Checked ip:{Plugin name:Check score}`组织形式。第一级key表示：被检查的ip；第二级key表示：检查插件的名称；value表示：检查分数
  * CheckInfo：为`Checker ip:{Checked ip:Check detail}`组织形式。第一级key表示：执行检查的ip；第二级key表示：被检查的ip；value表示检查结果CheckDetail
* CheckDetail：代表健康检查的结果
  * Normal：Normal为true表示检查结果正常；false表示异常
  * Time：表示得出该结果时的时间，用于结果有效性的判断(超过一段时间没有更新的结果将无效)
* CommunInfo：边缘节点向其它节点发送健康检查结果时使用的数据，其中包括：
  * SourceIP：表示执行检查的ip
  * CheckDetail：为`Checked ip:Check detail`组织形式，包含被检查的ip以及检查结果
  * Hmac：边缘节点通信过程中使用的密钥，用于判断数据的有效性(是否被篡改)

edge-health-daemon主体逻辑包括四部分功能：

* SyncNodeList：根据边缘节点所在的zone刷新node cache，同时更新CheckMetadata相关数据
* ExecuteCheck：对每个边缘节点执行若干种类的健康检查插件(ping，kubelet等)，并将各插件检查分数汇总，根据用户设置的基准线得出节点是否健康的结果
* Commun：将本节点对其它各节点健康检查的结果发送给其它节点
* Vote：对所有节点健康检查的结果分类，如果某个节点被大多数(>1/2)节点判定为正常，则对该节点添加`superedgehealth/node-health：true` annotation，表明该节点分布式健康检查结果为正常；否则，对该节点添加`superedgehealth/node-health：false` annotation，表明该节点分布式健康检查结果为异常

下面依次对上述功能进行源码分析：

1、SyncNodeList



2、ExecuteCheck

3、Commun

4、Vote



## 总结

## 展望

