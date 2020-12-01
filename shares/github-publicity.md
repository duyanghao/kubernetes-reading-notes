Table of Contents
=================

* [前言](#前言)
* [项目总览](#项目总览)
* [<a href="https://github.com/duyanghao/kubernetes-reading-notes">kubernetes-reading-notes</a>](#kubernetes-reading-notes)
* [<a href="https://github.com/duyanghao/Eagle">Eagle</a>](#eagle)
* [<a href="https://github.com/duyanghao/velero-volume-controller">velero-volume-controller</a>](#velero-volume-controller)
* [<a href="https://github.com/duyanghao/gin-apiserver">gin-apiserver</a>](#gin-apiserver)
* [<a href="https://github.com/duyanghao/cluster-coredns-controller">cluster-coredns-controller</a>](#cluster-coredns-controller)
* [<a href="https://github.com/duyanghao/sample-container-runtime">sample-container-runtime</a>](#sample-container-runtime)
* [<a href="https://github.com/duyanghao/registry-notification-server">registry-notification-server</a>](#registry-notification-server)
* [<a href="https://github.com/duyanghao/DemoOs">DemoOs</a>](#demoos)
* [<a href="https://github.com/duyanghao/registry-sync-tools">registry-sync-tools</a>](#registry-sync-tools)
* [<a href="https://github.com/duyanghao/crds-code-generation-tools">crds-code-generation-tools</a>](#crds-code-generation-tools)
    * [STEP 1 - Generate CRDs](#step-1---generate-crds)
    * [STEP 2 - Copy CRDs to your own project](#step-2---copy-crds-to-your-own-project)
    * [STEP 3 - Edit your own CRDs](#step-3---edit-your-own-crds)
    * [STEP 4 - Generate code relevant with your CRDs(such as clientset and so on)](#step-4---generate-code-relevant-with-your-crdssuch-as-clientset-and-so-on)
* [<a href="https://github.com/duyanghao/registry-pressure-measurement-tools">registry-pressure-measurement-tools</a>](#registry-pressure-measurement-tools)
* [<a href="https://github.com/duyanghao/GSEAsyncServer">GSEAsyncServer</a>](#gseasyncserver)
* [Conclusion](#conclusion)
      
## 前言

本文对自研的github项目进行了一个概括性的介绍，包括功能和使用场景，希望项目能更多地被认识和推广

## 项目总览

|  项目名称   | 语言  | 功能 | 使用场景 |
|  ----  | ----  |  ----  | ----  |
| kubernetes-reading-notes  | go | 云原生阅读笔记  | 帮助学习以Kubernetes为核心的云原生技术栈 |
| Eagle  | go | 自研P2P镜像分发解决方案  | P2P镜像分发 |
| velero-volume-controller  | go | 云原生备份还原工具Velero Restic Integration控制器 | 帮助自动给Pod打annotation，协助velero restic的工作 |
| gin-apiserver  | go | 基于gin的apiserver开发框架 | 根据此框架可以快速开发云原生apiserver |
| cluster-coredns-controller  | go | 基于coredns的分布式域名解决方案 | 自动同步tkestack中的所有集群，并构建coredns域名，实现流量分布式访问 |
| sample-container-runtime | go | 自研云原生容器运行时 | 试图构建一个云原生时代的容器运行时范例 |
| registry-notification-server | go | 基于docker distribution event notification protocol实现的endpoint server | 完成了镜像Repository&Tag查询，日志查询以及镜像迁移功能，适合与上层平台集成 |
| DemoOs | Assembly | 多任务demo os | 提供了一个多任务的demo os范例，是内核入门的不二选择 |
| registry-sync-tools | shell | 云原生镜像迁移工具 | helm chart部署，实现从github上拉取镜像列表，并定期同步镜像的功能 |
| crds-code-generation-tools | go | CRDs template以及clientset生成工具 | 提供了一个简单易用的工具(在原生codegen基础上包装了一层)，用于生成CRDs template以及相关代码 |
| registry-pressure-measurement-tools | python | 镜像仓库压测工具 | 基于openstack压测方案二次定制的镜像压测工具，适用于用少数机器压测docker distribution的场景 |
| GSEAsyncServer | go | 自研轻量级异步任务处理框架 | 提供一个简单且高效的轻量级异步任务处理框架，可以单独使用，也可以简单改造作为一个子模块进行集成 |

还有一些其它的项目，这里不一一列举了。本文主要对上述项目展开介绍

## [kubernetes-reading-notes](https://github.com/duyanghao/kubernetes-reading-notes)

![](/public/img/github-overview/kubernetes-reading-notes.png)

kubernetes-reading-notes主要以源码分析为主，实践总结为辅：

* 源码：分析了Kubernetes核心组件：kube-apiserver，kube-scheduler，kube-controller，kubelet以及kube-proxy。另外会展开分析与kubernetes核心组件密切关联的其它项目，例如：etcd，container-runtime以及golang等
* 实践：会不定期上传云原生实践的一些文档，例如：[K8s&云原生技术开放日（深圳站）- harbor企业级方案设计与落地实践](https://cloud.tencent.com/developer/salon/salon-1151)，[腾讯云十年乘风破浪直播 - Kubernetes集群高可用&备份还原概述](https://mp.weixin.qq.com/s?__biz=MzUxODA5ODA1Nw==&mid=2247488105&idx=1&sn=cfb8e689a251fcbce1ef13d8afa66256&chksm=f98f4f8fcef8c6997de4f4c034e76cb2eb67ce0b8fb717c7ff040152fc21cb2f43f3164d547c&mpshare=1&scene=1&srcid=1022HsY0bRMBKPY5P00mVnjW&sharer_sharetime=1603685681187&sharer_shareid=3b976c5e6fc040f7754b741576df2331&rd2werd=1#wechat_redirect)，[自研镜像P2P分发系统-Eagle分享](https://github.com/duyanghao/kubernetes-reading-notes/blob/master/shares/eagle.pptx)

**通过本项目可以更加深层次的理解以Kubernetes为核心的云原生技术栈**

## [Eagle](https://github.com/duyanghao/Eagle)

![img](https://github.com/duyanghao/Eagle/raw/master/docs/images/eagle_arch.png)

镜像P2P主要用于解决大规模容器分发场景下的镜像拉取性能问题，目前主流的开源解决方案有[Dragonfly](https://github.com/dragonflyoss/Dragonfly)(Alibaba)以及[Kraken](https://github.com/uber/kraken)(Uber)， 这两种解决方案各有优缺点，设计模式也各有不同：

- Dragonfly：采用supernode中心控制设计模式，所有的peer数据传输任务都由supernode负责调度，整个集群将管理集中在supernode组件
- Kraken：采用随机分散设计模式，Tracker组件只负责管理所有peer的连接信息(包括各个peer拥有的数据)，而实际的数据传输流程则交由各个peer自行协商决定

**[Eagle](https://github.com/duyanghao/Eagle)充分参考了[Dragonfly](https://github.com/dragonflyoss/Dragonfly)，[Kraken](https://github.com/uber/kraken)以及[FID](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=8064123)的原理和特性。 在上述项目基础上去掉了一些不必要特性，保留了最核心的组件和功能，精简而实用**

目前`Eagle`支持如下特性：

- Non-invasive：`Eagle`对[docker](https://github.com/moby/moby)以及[docker distribution](https://github.com/docker/distribution)代码无侵入，可以无感知对接
- High-availability：`Eagle`从客户端侧以及服务端侧实现了`Tracker`以及`Seeder`的高可用，整个架构无单点故障
- SSI(Seeder Storage Interface)：`Eagle`对`Seeder`存储实现了插件式接口，用户可以根据SSI接口实现对接第三方存储(目前默认本地文件系统)
- Host level speed limit：`Eagle`提供针对整个节点P2P下载和上传的网络限速功能
- LRUCache delete policy：`Eagle`提供LRU算法实现Proxy测和Seeder测的磁盘回收功能，并提供参数限制Cache使用大小
- Lightweight：`Eagle`由少数核心组件构成，理论上是P2P系统组件的最小集合，属于轻量级的解决方案

未来`Eagle`希望支持如下特性：

- Peer optimal arithmetic：`Eagle`希望实现基于网络拓扑的Peer优选算法，提高传输效率以及节省跨IDC带宽
- Push notification mechanism：实现镜像上传同步更新到`Seeder` Cache，这样可以最大限度减少`Seeder`回源操作

其中，`Peer optimal arithmetic`是目前所有开源项目都没有实现的特性(参考[Kraken #244](https://github.com/uber/kraken/issues/244)和[Dragonfly #1311](https://github.com/dragonflyoss/Dragonfly/issues/1311))，也是本项目的重点研究对象

更多关于Eagle的详细原理和介绍可以参考github项目：https://github.com/duyanghao/Eagle

## [velero-volume-controller](https://github.com/duyanghao/velero-volume-controller)

![img](https://github.com/duyanghao/velero-volume-controller/raw/master/docs/images/architecture.png)

对于社区最火的云原生备份还原工具Velero，由于v1.5版本之前Velero restic integration不支持批量备份Pod，必须手动给所有Pod设置annotation，于是开发了[velero-volume-controller](https://github.com/duyanghao/velero-volume-controller)与velero restic结合使用解决该问题；另外，虽然v1.5版本之后Velero restic integration支持了[Opt-out approach](https://velero.io/docs/v1.5/restic/)做全量pod volume的备份操作，**但是velero-volume-controller支持的细粒度范围控制我认为在短时间内依旧有用**

## [gin-apiserver](https://github.com/duyanghao/gin-apiserver)

`gin-apiserver`是一个基于[gin](https://github.com/gin-gonic/gin)框架写的apiserver框架，**主要用于企业生产环境中apiserver的快速构建和开发**

1、特性

* 支持configmap reload api
* 支持ping-pong健康检查&版本获取
* 支持dump-goroutine-stack-traces

2、组成

`gin-apiserver`框架的核心就是pkg包，下面主要针对该包结构进行描述：

```
pkg/
├── config
│   ├── config.go
│   ├── key.go
│   ├── model.go
│   └── opt_defs.go
├── controller
│   ├── ping.go
│   ├── todo.go
│   └── version.go
├── log
│   └── log.go
├── middleware
│   ├── basic_auth_middleware.go
├── models
│   └── common.go
├── route
│   └── routes.go
├── service
│   └── todo.go
├── store
└── util
```

- config：主要用于配置文件，实现：文件+环境变量+命令行参数读取
- controller: 对应MVC中controller，调用service中的接口进行实际处理，自己只做数据校验与拼接
- service: 负责主要的逻辑实现
- log: 日志模块，实现：模块名(文件名)+函数名+行数+日志级别
- middleware: 中间件，负责通用的处理，例如：鉴权
- models: 对应MVC中的model
- route: gin路由
- store: 存储模块，可以添加MySQL、Redis等
- util: 通用的库函数

3、使用

* step1 - 替换项目名称
* step2 - 开发业务controller和service
* step3 - 启动服务

4、基于gin-apiserver的第三方实现

- [coredns-dynapi-adapter - coredns dynamic middleware apiserver adapter](https://github.com/duyanghao/coredns-dynapi-adapter)

## [cluster-coredns-controller](https://github.com/duyanghao/cluster-coredns-controller)

![img](https://github.com/duyanghao/cluster-coredns-controller/raw/master/docs/images/architecture.png)

cluster-coredns-controller是以tkestack为底座，基于coredns实现的controller。该controller会自动同步tkestack集群，并按照一定规则生成coredns对应的Corefile以及Zonefile，最终实现应用基于Kubernetes Ingress的分布式流量访问架构。**本项目适合集成在基于Ingress访问的分布式架构中**

## [sample-container-runtime](https://github.com/duyanghao/sample-container-runtime)

sample-container-runtime是基于《自己动手写Docker》[mydocker](https://github.com/xianlubird/mydocker/tree/code-6.5)项目二次定制的容器运行时，目前已经实现aufs，namespace隔离，cgroups资源控制，容器命令行工具(容器查看，日志查看，进入容器，停止容器，启动容器，删除容器，容器commit以及容器指定环境变量运行等)以及容器网络(**容器与容器通信，容器与宿主机通信，容器与外部宿主机通信**)

接下来会计划支持对CRI以及OCI的支持，**试图将sample-container-runtime构建成云原生时代的容器运行时范例**

## [registry-notification-server](https://github.com/duyanghao/registry-notification-server)

![img](https://github.com/duyanghao/registry-notification-server/raw/master/images/notifications.png)

registry-notification-server是基于docker distribution event notification协议开发的endpoint server，当docker distribution检查到镜像pull或者push操作事件时，会触发webhook notifications给endpoint server。而registry-notification-server就是根据这个协议完成了镜像Repository&Tag查询，日志查询以及镜像迁移功能。**本项目适合集成在各PaaS平台的镜像仓库模块，用于镜像和日志查询**

## [DemoOs](https://github.com/duyanghao/DemoOs)

![img](https://duyanghao.github.io/public/img/demoos/run.png)

DemoOs是对《Linux内核完全剖析：基于0.12内核》中的例子进行了抽取，并单独构建的demo os项目

该项目主要实现的功能是：有两个任务（不能说是进程，因为并没有PCB结构），分别打印字符A和B（利用系统调用中断0x80）。由定时中断（每10ms发生一次）切换两个任务，这样每个任务大约可以打印10个字符，轮流交替（每打印一个字符则循环等待到1ms时间）

虽说这个OS小，但是X86 CPU体系结构的基本特性都应用到了。其中包括GDT、LDT、IDT、BIOS、描述符（中断门和陷阱门）、选择符、内核态、用户态、实模式、保护模式以及中断等

**DemoOs可谓是：麻雀虽小，五脏俱全，是入门Linux内核的不二选择**

## [registry-sync-tools](https://github.com/duyanghao/registry-sync-tools)

![img](https://github.com/duyanghao/registry-sync-tools/raw/master/images/registry-sync-tools.png)

registry-sync-tools是一个kubernetes-native工具，用于定期从github中获取镜像列表，并依据该列表将镜像从一个镜像仓库推送到另一个镜像仓库。**支持helm chart一键部署，适用于日常镜像的备份**

## [crds-code-generation-tools](https://github.com/duyanghao/crds-code-generation-tools)

[crds-code-generation-tools](https://github.com/duyanghao/crds-code-generation-tools)对code-generator进行了包装，最终呈现出一个容易使用的CRDs模板生成工具，按照如下步骤可以轻松构建出CRDs模板以及生成对应CRDs的clientset，listers和informers。使用如下：

```
hack/crds-code-generation.sh GroupName GroupPackage Version Kind Plural(eg: duyanghao.example.com duyanghao v1 Project projects)
```

![img](https://github.com/duyanghao/crds-code-generation-tools/raw/master/images/kubernetes-group-version.png)

#### STEP 1 - Generate CRDs

```bash
# execute crds-code-generation.sh
$ git clone https://github.com/duyanghao/crds-code-generation-tools.git && cd crds-code-generation-tools
$ bash hack/crds-code-generation.sh duyanghao.example.com duyanghao v1 Project projects
# CRDs template will be listed like below:
pkg
└── apis
  └── duyanghao
      ├── register.go
      └── v1
          ├── doc.go
          ├── register.go
          └── types.go 
artifacts
└── crd.yaml
```

#### STEP 2 - Copy CRDs to your own project

```bash
# copy CRDs to your own project
$ grep -rl "github.com/duyanghao/crds-code-generation-tools" ./ | xargs sed -i '' 's/github.com\/duyanghao\/crds-code-generation-tools/your_project/g'
$ cp -r artifacts your_project/artifacts
$ cp -r hack your_project/hack
$ cp -r pkg/apis your_project/pkg/apis
```

#### STEP 3 - Edit your own CRDs

```go
# Complete the Spec and Status fields if necessary 
$ cat pkg/apis/duyanghao/v1/types.go
package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Project struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ProjectSpec `json:"spec"`
}

// ProjectSpec is the spec for a Project resource
type ProjectSpec struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProjectList is a list of Project resources
type ProjectList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Project `json:"items"`
}
```

#### STEP 4 - Generate code relevant with your CRDs(such as clientset and so on)

```bash
# generate code with update-codegen.sh
$ bash hack/update-codegen.sh
Generating deepcopy funcs
Generating clientset for duyanghao:v1 at github.com/duyanghao/crds-code-generation-tools/generated/clientset
Generating listers for duyanghao:v1 at github.com/duyanghao/crds-code-generation-tools/generated/listers
Generating informers for duyanghao:v1 at github.com/duyanghao/crds-code-generation-tools/generated/informers
$ tree -L 2 generated
generated
├── clientset
│   └── versioned
├── informers
│   └── externalversions
└── listers
    └── duyanghao
```

**本项目适用于快速构建简单的CRDs模板以及对应的clientset**

## [registry-pressure-measurement-tools](https://github.com/duyanghao/registry-pressure-measurement-tools)

registry-pressure-measurement-tools是基于[openstack test_plans](https://docs.openstack.org/developer/performance-docs/test_results/container_repositories/registry2/index.html)二次定制的镜像仓库压测解决方案，**该方案适用于采用少量机器(Docker宿主机)压测docker distribution的场景**

![img](https://github.com/duyanghao/registry-pressure-measurement-tools/raw/master/images/pt-Few-Machines.png)

最终呈现的压测数据如下：

![img](https://github.com/duyanghao/registry-pressure-measurement-tools/raw/master/images/pull_time.png)

## [GSEAsyncServer](https://github.com/duyanghao/GSEAsyncServer)

[GSEAsyncServer](https://github.com/duyanghao/GSEAsyncServer)是自研的Go异步任务处理框架，采用有缓存channel进行任务生产和消费，每个任务会单独以一个goroutine运行，并设置超时限制，整个项目精简且高效，代码只有几百行：

![img](https://github.com/duyanghao/GSEAsyncServer/raw/master/images/architecture.png)

**该项目适合单独运行，也很容易抽取核心代码与其它系统进行集成**

```go
type TaskWork struct {
	taskClient *Task
	taskChan   chan TaskChan
	queueChan  chan int
	sync.RWMutex
}

...
func NewTaskWork(c *Configuration.MysqlConfig) (*TaskWork, error) {
	...
	return &TaskWork{
		taskClient: task,
		taskChan:   make(chan TaskChan),
		queueChan:  make(chan int, WORK_CHANNEL_LEN),
	}, nil
}

...
func (tw *TaskWork) Run() error {
	defer func() {
		close(tw.taskChan)
		close(tw.queueChan)
		tw.taskClient.db.Close()
	}()
	for task := range tw.taskChan {
		tw.queueChan <- 1
		go func(task TaskChan) {
			// handle task
			CustomizeLog(2, fmt.Sprintf("Handle task: %+v", task))
			err := tw.work(task)
			if err != nil {
				CustomizeLog(0, fmt.Sprintf("Async task: %+v error: %s", task, err))
			} else {
				CustomizeLog(2, fmt.Sprintf("Successfully async task: %+v", task))
			}
			glog.V(5).Infof("\n=======================分割线======================\n")

			<-tw.queueChan

		}(task)
	}

	return nil
}

func (tw *TaskWork) work(task TaskChan) error {
	CustomizeLog(2, fmt.Sprintf("Message: %s received ...", task.MessageTask.Msg))
	// Do whatever you want to do(eg: send http request using tw.taskClient.client or interact with mysql using tw.taskClient.db) ...
	time.Sleep(1 * time.Minute)
	return nil
}

func (tw *TaskWork) AsyncTask(task TaskChan) error {
	select {
	case tw.taskChan <- task:
		return nil
	case <-time.After(PROCESS_MAX_TIMEOUT):
		return fmt.Errorf("Async task %+v timeout", task)
	}
}
```

## Conclusion

本文对部分自研github项目的功能以及使用场景进行了概述，希望通过本文可以使项目能更多地被认识和推广

![img](https://duyanghao.github.io/public/img/wechat/duyanghao.png)