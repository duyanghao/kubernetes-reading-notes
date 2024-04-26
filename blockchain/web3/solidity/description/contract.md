合约
====

Solidity中的合约类似于面向对象语言中的类。 它们在状态变量中包含持久的数据，以及可以修改这些变量的函数。 在不同的合约（实例）上调用一个函数将执行一个EVM函数调用， 从而切换上下文，使调用合约中的状态变量无法访问。 一个合约和它的函数需要被调用才会发生。 在以太坊中没有 "cron" 的概念，在特定的事件中自动调用一个函数。

1、创建合约

可以通过以太坊交易 “从外部” 或从 Solidity 合约内部创建合约。

在以太坊上以编程方式创建合约的一种方法是通过JavaScript API web3.js。 它有一个名为 web3.eth.Contract 的函数， 以方便创建合约。

当一个合约被创建时，它的 构造函数（constructor） （一个用 constructor 关键字声明的函数）被执行一次。

构造函数是可选的。但是只允许有一个构造函数，这意味着不支持重载。

构造函数执行完毕后，合约的最终代码被存储在区块链上。 这段代码包括所有公开和外部函数，以及所有通过函数调用可从那里到达的函数。 部署的代码不包括构造函数代码或只从构造函数调用的内部函数。

如果一个合约想创建另一个合约，创建者必须知道所创建合约的源代码（和二进制）。 这意味着，循环的创建依赖是不可能的。

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.22 <0.9.0;


contract OwnedToken {
    // `TokenCreator` 是如下定义的合约类型。
    // 不创建新合约的话，也可以引用它。
    TokenCreator creator;
    address owner;
    bytes32 name;

    // 这是注册 creator 和设置名称的构造函数。
    constructor(bytes32 name_) {
        // 状态变量通过其名称访问，
        // 而不是通过例如 `this.owner` 的方式访问。
        // 函数可以直接或通过 `this.f` 访问。
        // 但后者提供了一个对函数的外部可视方法。
        // 特别是在构造函数中，您不应该从外部访问函数，
        // 因为该函数还不存在。
        // 详见下一节。
        owner = msg.sender;

        // 我们进行了从 `address` 到 `TokenCreator` 的显式类型转换，
        // 并假定调用合约的类型是 `TokenCreator`，
        // 没有真正的方法来验证，
        // 这并没有创建一个新的合约。
        creator = TokenCreator(msg.sender);
        name = name_;
    }

    function changeName(bytes32 newName) public {
        // 只有创建者可以改变名称。
        // 我们根据合约的地址进行比较，
        // 它可以通过显式转换为地址来检索。
        if (msg.sender == address(creator))
            name = newName;
    }

    function transfer(address newOwner) public {
        // 只有当前所有者才能发送 token。
        if (msg.sender != owner) return;

        // 我们通过使用下面定义的 `TokenCreator` 合约的一个函数
        // 来询问创建者合约是否应该进行转移。
        // 如果调用失败（例如由于气体值耗尽），
        // 这里的执行也会失败。
        if (creator.isTokenTransferOK(owner, newOwner))
            owner = newOwner;
    }
}


contract TokenCreator {
    function createToken(bytes32 name)
        public
        returns (OwnedToken tokenAddress)
    {
        // 创建一个新的 `Token` 合约并返回其地址。
        // 从JavaScript方面来看，
        // 这个函数的返回类型是 `address`，
        // 因为这是ABI中最接近的类型。
        return new OwnedToken(name);
    }

    function changeName(OwnedToken tokenAddress, bytes32 name) public {
        // 同样，`tokenAddress` 的外部类型是简单的 `address`。
        tokenAddress.changeName(name);
    }

    // 执行检查，以确定是否应该将代币转移到 `OwnedToken` 合约上。
    function isTokenTransferOK(address currentOwner, address newOwner)
        public
        pure
        returns (bool ok)
    {
        // 检查一个任意的条件，看是否应该进行转移。
        return keccak256(abi.encodePacked(currentOwner, newOwner))[0] == 0x7f;
    }
}
```

2、可见性和 getter 函数
