web3-contract-framework
=======================

## Introduction

`web3-contract-framework` is a smart contract framework for web3 projects.

## Features

* 轻量化&标准化: 项目短小精悍，只覆盖Web3合约开发生命周期的所有必要组件模块；且各模块代码及标准均参考业界主流项目建设
* 合约接口化: 所有对外的合约均通过接口进行提供，解耦合约定义和具体实现，提高合约的可扩展性和可维护性
* 高度集成：合约编译、测试、审计、部署、升级等高度集成，通过Makefile可执行所有操作
* 第三方扩展：支持通过thirdparties集成第三方生态组件，内置：MakerDAO、Oracle等

## Architecture

TODO: ...

## 项目命名标准

- 目录命名标准：首字母小写，多个单词中划线分割(除特殊字符外)
- 文件命名标准：首字母大写，驼峰命名
- ts脚本的命名标准：首字母小写，驼峰命名

## Framework

`web3-contract-framework`框架核心目录如下，下面针对该项目结构展开介绍：

- contract：业务逻辑相关合约
    - core：存放业务逻辑合约，切分标准如下：
        - 根据业务逻辑划分，可以是文件或者目录 
        - common目录，里面包含了公共的合约   
    - factories：存放项目使用到的工厂合约，切分标准如下：
        - 按照功能进行文件划分（纯文件）
    - kyc：存放项目使用到的身份认证合约，切分标准：
        - 按照功能进行文件划分（纯文件）
    - config：存放配置合约，主要管理项目合约的地址、配置参数等内容。切分标准如下：
        - Config.sol：配置合约，存储具体的配置内容，并对这些存储进行读写操作
        - ConfigOptions.sol：该文件内添加所有合约配置项，包括合约地址(`enum Addresses`)以及相关配置项(`enum Numbers`)等
        - ConfigHepler.sol：该文件主要提供一个中间层，是对`Config.sol`合约存储读操作的进一步封装（内容拼接、类型转换等），用于内部其它合约快速获取对应配置内容
    - models：存放合约数据结构以及相关的enum等，切分标准如下：
        - 与core，factories，kyc及external目录文件划分对应，文件名称为：`M` + 对应合约文件名（eg：Oracle.sol => MOracle.sol）
    - libraries：存放公共工具库函数，切分标准如下：
        - 按照功能进行文件划分（纯文件）
    - external：存放对外部合约的二次封装，切分标准：
        - erc：对erc合约的二次封装（和业务逻辑无关），按照erc协议种类进行文件划分（纯文件）
        - thirdparties：对第三方生态组件的二次封装（和业务逻辑无关），按照第三方项目名称进行目录划分
    - interfaces：存放业务逻辑合约的接口定义，切分标准如下：
        - internal，存放内部合约调用接口
            - 将上述configs，core，factories，kyc目录下合约的外部调用方法抽出，形成新的接口合约。该目录内的结构和外部configs，core，factories，kyc目录的结构一致，文件名称为：`I` + 对应合约文件名（eg：Config.sol => IConfig.sol）
        - external：存放外部合约调用接口
            - 将上述external目录下合约的外部调用方法抽出，形成新的接口合约。该目录结构和外部external目录结构一致，文件名称为：`I` + 对应合约文件名（eg：Oracle.sol => IOracle.sol）
- scripts：合约部署脚本
    - deploys：合约部署脚本（新增）
        - 按照功能进行文件划分（纯文件），实际执行可以统一成一个文件，可以通过配置执行不同操作
    - upgrades：合约升级脚本（可升级）
        - 按照功能进行文件划分（纯文件），实际执行可以统一成一个文件，可以通过配置执行不同操作
    - others：生成abi脚本，初始化操作等
        - 按照功能进行文件划分（纯文件）
- docs：
    - abi：按照interfaces结构目录划分，具体文件名为合约名+abi后缀（eg：Oracle.sol => Oracle.abi）
    - ARCHITECTURE.md：架构描述
    - CHANGELOG：
        - 以CHANGELOG-'VERSION'.md构成每个迭代版本的变更内容（eg：CHANGELOG-v1.0.0.md）
    - BUSINESSLOGIC：
        - 以BUSINESSLOGIC-'VERSION'.md构成每个迭代版本的业务逻辑内容，方便后续集成测试使用（eg：BUSINESSLOGIC-v1.0.0.md）。BUSINESSLOGIC文件内容由如下三部分组成：
            - 业务概览：对整体合约业务逻辑的概要性描述
            - 核心实现逻辑：合约业务流程的核心实现逻辑
            - 参考&备注：一些参考链接和补充性内容
- test：合约测试脚本（TypeScript脚本）
    - unit-test：存放单元测试脚本
        - 该目录内的结构和contracts下configs，core，factories，kyc目录的结构一致，测试脚本名称为：`test` + 对应合约文件名（eg：Oracle.sol => testOracle.ts）
    - system-test：存放系统测试脚本
        - 按功能进行文件划分（纯文本）
- internal-audit: 合约人工审计报告
    - 按照迭代版本进行目录切分，合约人工审计报告文件名以日期形式存放（格式为excel or pdf）
- Makefile: 集成所有合约操作（统一入口），包括：静态代码检查、编译打包、测试、审计、部署等全生命周期流程
- README.md: 项目描述文档