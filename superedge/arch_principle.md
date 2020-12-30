superedge功能体验
================

[superedge](https://github.com/superedge/superedge)是腾讯推出的Kubernetes-native边缘计算管理框架。相比[openyurt](https://github.com/alibaba/openyurt)以及[kubeedge](https://github.com/kubeedge/kubeedge)，superedge除了具备Kubernetes零侵入以及边缘自治特性，还支持独有的分布式健康检查以及边缘服务访问控制等高级特性，极大地消减了云边网络不稳定对服务的影响，同时也很大程度上方便了边缘集群服务的发布与治理

## 特性

* **Kubernetes-native**：superedge在原生Kubernetes基础上进行了扩展，增加了边缘计算的某干组件，对Kubernetes完全无侵入；另外通过简单部署superedge核心组件就可以使原生Kubernetes集群开启边缘计算功能；另外零侵入使得可以在边缘集群上部署任何Kubernetes原生工作负载(deployment, statefulset, daemonset, and etc)
* 边缘自治：superedge提供L3级别的边缘自治能力，当边端节点与云端网络不稳定或者断连时，边缘节点依旧可以正常运行，不影响已经部署的边缘服务
* 分布式健康检查：superedge提供边端分布式健康检查能力，每个边缘节点会部署edge-health，同一个边缘集群中的边缘节点会相互进行健康检查，对节点进行状态投票。这样即便云边网络存在问题，只要边缘端节点之间的连接正常，就不会对该节点进行驱逐。整个设计避免了由于云边网络不稳定造成的大量的pod迁移和重建，保证了服务的稳定
* 服务访问控制：superedge自研了ServiceGroup实现了基于边缘计算的服务访问控制。基于该特性只需构建DeploymentGrid以及ServiceGrid两种Custom Resource，就可以便捷地在共属同一个集群的不同机房或区域中各自部署一组服务，并且使得各个服务间的请求在本机房或本地域内部即可完成(闭环)，避免了服务跨地域访问。利用该特性可以极大地方便边缘集群服务的发布与治理
* 云边隧道：superedge支持自建隧道(目前支持TCP, HTTP and HTTPS)打通不同网络环境下的云边连接问题。实现对无公网IP边缘节点的统一操作和维护

## 整体架构

![img](https://github.com/superedge/superedge/raw/main/docs/img/superedge_arch.png)

组件功能总结如下：

### 云端组件

云端除了边缘集群部署的原生Kubernetes master组件(cloud-kube-apiserver，cloud-kube-controller以及cloud-kube-scheduler)外，主要管控组件还包括：

* [**tunnel-cloud**](https://github.com/superedge/superedge/blob/main/docs/components/tunnel.md): 负责维持与边缘节点[**tunnel-edge**](https://github.com/superedge/superedge/blob/main/docs/components/tunnel.md)的网络隧道，目前支持TCP/HTTP/HTTPS协议
* [**application-grid controller**](https://github.com/superedge/superedge/blob/main/docs/components/service-group.md)：服务访问控制ServiceGroup对应的Kubernetes Controller，负责管理DeploymentGrids以及ServiceGrids CRDs，并由这两种CR生成对应的Kubernetes deployment以及service，同时自研实现服务拓扑感知，使得服务闭环访问
* [**edge-admission**](https://github.com/superedge/superedge/blob/main/docs/components/edge-health.md): 通过边端节点分布式健康检查的状态报告决定节点是否健康，并协助cloud-kube-controller执行相关处理动作(打taint)

### 边缘组件

边端除了原生Kubernetes worker节点需要部署的kubelet，kube-proxy外，还添加了如下边缘计算组件：

* [**lite-apiserver**](https://github.com/superedge/superedge/blob/main/docs/components/lite-apiserver.md)：边缘自治的核心组件，是cloud-kube-apiserver的代理服务，缓存了边缘节点组件对apiserver的某些请求，当遇到这些请求而且与cloud-kube-apiserver网络存在问题的时候会直接返回给client端
* [**edge-health**](https://github.com/superedge/superedge/blob/main/docs/components/edge-health.md): 边端分布式健康检查服务，负责执行具体的监控和探测操作，并进行投票选举判断节点是否健康
* [**tunnel-edge**](https://github.com/superedge/superedge/blob/main/docs/components/tunnel.md)：负责建立与云端边缘集群[**tunnel-cloud**](https://github.com/superedge/superedge/blob/main/docs/components/tunnel.md)的网络隧道，并接受API请求，转发给边缘节点组件(kubelet)
* application-grid wrapper：与application-grid controller结合完成ServiceGrid内的闭环服务访问(服务拓扑感知)

## 功能概述

