Golang module概述
================

## 前言

>> In the world of software management there exists a dreaded place called “dependency hell.” The bigger your system grows and the more packages you integrate into your software, the more likely you are to find yourself, one day, in this pit of despair.

依赖管理是一个语言必须要解决的问题。golang依赖管理发展历史可以归纳如下：

* goinstall(2010.02)：将依赖的代码库下载到本地，并通过import引用这些库
* go get(2011.12)：go get代替goinstall
* godep(2013.09)：godep提供了一个依赖文件，记录所有依赖具体的版本和路径，编译时将依赖下载到workspace中，然后切换到指定版本，并设置GOPATH访问(解决go get没有版本管理的缺陷)
* [gopkg.in](https://labix.org/gopkg.in)(2014.03)：通过import路径中添加版本号来标示不同版本，而实际代码存放于github中，go通过redirect获取代码。例如(import gopkg.in/yaml.v1，实际代码地址为：https://github.com/go-yaml/yaml)
* vendor(2015.06)；Go 1.5版本引入vendor(类似godep)，存放于项目根目录，编译时优先使用vendor目录，之后再去GOPATH，GOROOT目录查找(解决GOPATH无法管控依赖变更和丢失的问题)
* [dep](https://github.com/golang/dep)(2016.08)：dep期望统一Golang依赖管理，虽然提供了兼容其它依赖管理工具的功能，但是本质上还是利用GOPATH和vendor解决依赖管理
* [go module](https://research.swtch.com/vgo-principles)(2018.08)：Go 1.11发布的官方依赖管理解决方案，并最终统一了Go依赖管理(by Russ Cox)。go module以semantic version(语义版本控制)和Minimal Version Selection, MVS(最小版本选择)为核心，相比dep更具稳定性；同时也解决了vendor代码库依赖过于庞大，造成存储浪费的问题

通过如上历史，我们可以看出：go依赖管理的发展历史，其实就是go去google的历史(google内部没有强烈的版本管理需求)，也是典型的社区驱动开发的例子

接下来，我将详细探讨go module的两大核心概念：semantic version(语义化版本)和Minimal Version Selection, MVS(最小版本选择)

## [semantic version](https://semver.org/)

golang使用semantic version来标识package的版本。具体来说：

* MAJOR version when you make incompatible API changes(不兼容的修改)
* MINOR version when you add functionality in a backwards compatible manner(特性添加，版本兼容)
* PATCH version when you make backwards compatible bug fixes(bug修复，版本兼容)

![](images/semantic_versioning.png)

这里，只要模块的主版本号(MAJOR)不变，次版本号(MINOR)以及修订号(PATCH)的变更都不会引起破坏性的变更(breaking change)。这就要求开发人员尽可能按照semantic version发布和管理模块(实际是否遵守以及遵守的程度不能保证，参考Hyrum's Law)

## [Minimal Version Selection](https://research.swtch.com/vgo-mvs)

>> A [versioned Go command](https://research.swtch.com/vgo-intro) must decide which module versions to use in each build. I call this list of modules and versions for use in a given build the *build list*. For stable development, today's build list must also be tomorrow's build list. But then developers must also be allowed to change the build list: to upgrade all modules, to upgrade one module, or to downgrade one module.

>> The version selection problem therefore is to define the meaning of, and to give algorithms implementing, these four operations on build lists:
> 1.Construct the current build list.
> 2.Upgrade all modules to their latest versions.
> 3.Upgrade one module to a specific newer version.
> 4.Downgrade one module to a specific older version.

这里将一次构建(go build)中所依赖模块及其版本列表称为build list，对于一个稳定发展的项目，build list应该尽可能保持不变，同时也允许开发人员修改build list，比如升级或者降级依赖。而依赖管理因此也可以归纳为如下四个操作：

* 构建项目默认build list
* 升级所有依赖模块到它们的最新版本
* 升级某个依赖模块到指定版本
* 将某个依赖模块降级到固定版本

>> Minimal version selection assumes that each module declares its own dependency requirements: a list of minimum versions of other modules. Modules are assumed to follow the import compatibility rule—packages in any newer version should work as well as older ones—so a dependency requirement gives only a minimum version, never a maximum version or a list of incompatible later versions.

>> Then the definitions of the four operations are:
> 1.To construct the build list for a given target: start the list with the target itself, and then append each requirement's own build list. If a module appears in the list multiple times, keep only the newest version.
> 2.To upgrade all modules to their latest versions: construct the build list, but read each requirement as if it requested the latest module version.
> 3.To upgrade one module to a specific newer version: construct the non-upgraded build list and then append the new module's build list. If a module appears in the list multiple times, keep only the newest version.
> 4.To downgrade one module to a specific older version: rewind the required version of each top-level requirement until that requirement's build list no longer refers to newer versions of the downgraded module.

Minimal version selection也即最小版本选择，如果光看下面的操作可能会很迷惑(或者矛盾)明明是选择最新的版本(keep only the newest version)？为什么叫最小版本选择？

其实，最小版本选择比较的对象是该模块的最新版本：如果项目需要依赖的模块版本是v1.2，而该模块实际最新的版本是v1.3，那么最小版本选择算法会选取v1.2版本而非v1.3。也即'最小版本'表示项目所需要依赖模块的最小版本号(v1.2)，而不是该模块实际的最小版本号(v1.1)，也并非该模块实际的最大版本号(v1.3)

这里，我们举例子对golang module最小版本选择算法进行解释：

![](images/init_eg.png)

> > There are two useful (and equivalent) ways to define build list construction: as a recursive process and as a graph traversal.
> >
> > The recursive definition of build list construction is as follows. Construct the rough build list for M by starting an empty list, adding M, and then appending the build list for each of M's requirements. Simplify the rough build list to produce the final build list, by keeping only the newest version of any listed module.
> >
> > ![img](https://research.swtch.com/version-select-list.png)

  

## Refs

* [Minimal Version Selection](https://research.swtch.com/vgo-mvs)
* [The Principles of Versioning in Go](https://research.swtch.com/vgo-principles#sat-example)
* [Golang 版本管理系列 翻译 11 篇全](https://github.com/vikyd/note/tree/master/go_and_versioning)

