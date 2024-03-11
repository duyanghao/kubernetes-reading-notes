智能合约概述
===========

学习达到标准：
1）interface与contract的区别？什么时候使用interface，什么时候使用contract
2）event是什么？为什么需要它？
3）require与revert的qubie？出现问题时，会返回gas吗？
4）payable的作用？什么时候使用payable？它跟fallback、receive函数的关系是什么？
5）library在solidity里的意义，什么时候使用它，怎么使用它？
6）怎么调用外部合约？有哪些注意事项？msg.sender会变换吗？
7）delegatecall、callcode、call的区别？

## Solidity简介

Solidity是一门为实现智能合约而创建的面向对象的高级编程语言。 智能合约是管理以太坊中账户行为的程序。

Solidity 是静态类型语言，支持继承，库和复杂的用户自定义的类型以及其他特性。

1. 了解智能合约基础知识

如果您是智能合约概念的新手，我们建议您从深入了解 “智能合约介绍” 部分开始，包括以下内容：

用 Solidity 编写的 一个简单的智能合约例子。

区块链基础知识.

以太坊虚拟机.

2. 了解 Solidity

一旦您熟悉了基础知识，我们建议您阅读 "Solidity 示例" 和 “语言描述” 部分，以了解该语言的核心概念。

## 智能合约概述

### 简单的智能合约

1、简单的智能合约：

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

contract SimpleStorage {
    uint storedData;

    function set(uint x) public {
        storedData = x;
    }

    function get() public view returns (uint) {
        return storedData;
    }
}
```

第一行告诉您，源代码是根据GPL3.0版本授权的。

下一行指定源代码是为Solidity 0.4.16版本编写的，或该语言的较新版本，直到但不包括0.9.0版本。

Solidity意义上的合约是代码（其 函数）和数据（其 状态）的集合， 驻留在以太坊区块链的一个特定地址。 这一行 uint storedData; 声明了一个名为 storedData 的状态变量， 类型为 uint （ unsigned integer，共 256 位）。 您可以把它看作是数据库中的一个槽，您可以通过调用管理数据库的代码函数来查询和改变它。 在这个例子中，合约定义了可以用来修改或检索变量值的函数 set 和 get

要访问当前合约的一个成员（如状态变量），通常不需要添加 this. 前缀， 只需要通过它的名字直接访问它。 

所有的标识符（合约名称，函数名称和变量名称）都只能使用ASCII字符集。 UTF-8编码的数据可以用字符串变量的形式存储。

该合约能完成的事情并不多（由于以太坊构建的基础架构的原因）， 它能允许任何人在合约中存储一个单独的数字，并且这个数字可以被世界上任何人访问， 且没有可行的办法阻止您发布这个数字。

2、子货币（Subcurrency）例子：

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;

contract Coin {
    // 关键字 "public" 使变量可以从其他合约中访问。
    address public minter;
    mapping(address => uint) public balances;

    // 事件允许客户端对您声明的特定合约变化做出反应
    event Sent(address from, address to, uint amount);

    // 构造函数代码只有在合约创建时运行
    constructor() {
        minter = msg.sender;
    }

    // 向一个地址发送一定数量的新创建的代币
    // 但只能由合约创建者调用
    function mint(address receiver, uint amount) public {
        require(msg.sender == minter);
        balances[receiver] += amount;
    }

    // 错误类型变量允许您提供关于操作失败原因的信息。
    // 它们会返回给函数的调用者。
    error InsufficientBalance(uint requested, uint available);

    // 从任何调用者那里发送一定数量的代币到一个地址
    function send(address receiver, uint amount) public {
        if (amount > balances[msg.sender])
            revert InsufficientBalance({
                requested: amount,
                available: balances[msg.sender]
            });

        balances[msg.sender] -= amount;
        balances[receiver] += amount;
        emit Sent(msg.sender, receiver, amount);
    }
}
```

下面的合约实现了一个最简单的加密货币。

address public minter; 这一行声明了一个可以被公开访问的 address 类型的状态变量。 address 类型是一个160位的值，且不允许任何算数操作。 这种类型适合存储合约地址或 外部账户 的密钥对。

关键字 public 自动生成一个函数，允许您在这个合约之外访问这个状态变量的当前值。 如果没有这个关键字，其他的合约没有办法访问这个变量。 由编译器生成的函数的代码大致如下所示（暂时忽略 external 和 view）：

```solidity
function minter() external view returns (address) { return minter; }
```

mapping(address => uint) public balances; 也创建了一个公共状态变量，映射 类型将地址映射到 无符号整数。

Mappings can be seen as hash tables which are virtually initialised such that every possible key exists from the start and is mapped to a value whose byte-representation is all zeros. However, it is neither possible to obtain a list of all keys of a mapping, nor a list of all values. Record what you added to the mapping, or use it in a context where this is not needed. Or even better, keep a list, or use a more suitable data type.

而由 public 关键字创建的 getter 函数 则是更复杂一些的情况， 它大致如下所示：

```solidity
function balances(address account) external view returns (uint) {
    return balances[account];
}
```

您可以用这个函数来查询单个账户的余额。

这一行 event Sent(address from, address to, uint amount); 声明了一个 "事件"， 它是在函数 send 的最后一行发出的。以太坊客户端，如网络应用，可以监听区块链上发出的这些事件，而不需要太多的成本。 一旦发出，监听器就会收到参数 from， to 和 amount，这使得跟踪交易成为可能。

为了监听这个事件，您可以使用以下方法 JavaScript 代码， 使用 web3.js 来创建 Coin 合约对象， 然后在任何用户界面调用上面自动生成的 balances 函数：

```js
Coin.Sent().watch({}, '', function(error, result) {
    if (!error) {
        console.log("Coin transfer: " + result.args.amount +
            " coins were sent from " + result.args.from +
            " to " + result.args.to + ".");
        console.log("Balances now:\n" +
            "Sender: " + Coin.balances.call(result.args.from) +
            "Receiver: " + Coin.balances.call(result.args.to));
    }
})
```

The constructor is a special function that is executed during the creation of the contract and cannot be called afterwards. In this case, it permanently stores the address of the person creating the contract. The msg variable (together with tx and block) is a special global variable that contains properties which allow access to the blockchain. msg.sender is always the address where the current (external) function call came from.

最后，真正被用户或其他合约所调用的，以完成本合约功能的方法是 mint 和 send。

mint 函数发送一定数量的新创建的代币到另一个地址。 require 函数调用定义了一些条件，如果不满足这些条件就会恢复所有的变化。 在这个例子中， require(msg.sender == minter); 确保只有合约的创建者可以调用 mint。 一般来说，创建者可以随心所欲地铸造代币，但在某些时候，这将导致一种叫做 "溢出" 的现象。 请注意，由于默认的 检查过的算术，如果表达式 balances[receiver] += amount; 溢出， 即当任意精度算术中的 balances[receiver] + amount 大于 uint 的最大值（ 2**256 - 1）时， 交易将被恢复。对于函数 send 中的语句 balances[receiver] += amount; 也是如此。

错误（Errors） 允许您向调用者提供更多关于一个条件或操作失败原因的信息。 错误与 恢复状态 一起使用。 revert 语句无条件地中止和恢复所有的变化， 类似于 require 函数，但它也允许您提供错误的名称和额外的数据， 这些数据将提供给调用者（并最终提供给前端应用程序或区块资源管理器），以便更容易调试失败或做出反应。

任何人（已经拥有一些这样的代币）都可以使用 send 函数来发送代币给其他任何人。 如果发送者没有足够的代币可以发送， 那么 if 条件就会为真。 因此， revert 将导致操作失败，同时使用 InsufficientBalance 错误向发送者提供错误细节。

### 区块链基础

对于程序员来说，区块链这个概念并不难理解，这是因为大多数难懂的东西 （挖矿，哈希，椭圆曲线密码学，点对点网络（P2P） 等） 都只是用于提供特定的功能和承诺。 您只需接受这些既有的特性功能，不必关心底层技术。

1、交易/事务

区块链是全球共享的事务性数据库，这意味着每个人都可加入网络来阅读数据库中的记录。 如果您想改变数据库中的某些东西，您必须创建一个被所有其他人所接受的事务。 事务一词意味着您想做的（假设您想要同时更改两个值），要么一点没做，要么全部完成。 此外，当您的事务被应用到数据库时，其他事务不能修改数据库。

举个例子，设想一张表，列出电子货币中所有账户的余额。 如果请求从一个账户转移到另一个账户， 数据库的事务特性确保了如果从一个账户扣除金额，它总被添加到另一个账户。 如果由于某些原因，无法添加金额到目标账户时，源账户也不会发生任何变化。

2、区块

要克服的一个主要障碍是（用比特币的术语）所谓的 “双花攻击 (double-spend attack)”： 如果网络中存在两个交易，都想清空一个账户，会发生什么？ 只有其中一个交易是有效的，通常是最先被接受的那个。 问题是，在点对点的网络中，"第一" 不是一个客观的术语。

对此，抽象的答案是，您不必在意。一个全球公认的交易顺序将为您选择， 解决这样的冲突。这些交易将被捆绑成所谓的 "区块"， 然后它们将在所有参与节点中执行和分发。 如果两个交易相互矛盾，最终排在第二位的那个交易将被拒绝，不会成为区块的一部分。

这些区块按时间形成了一个线性序列，这就是 “区块链” 一词的由来。 区块每隔一段时间就会被添加到链上，但这些时间间隔在未来可能会发生变化。 如需了解最新信息，建议在 Etherscan 等网站上对网络进行监控。

### 以太坊虚拟机

以太坊虚拟机或EVM是以太坊智能合约的运行环境。 它不仅是沙盒封装的，而且实际上是完全隔离的， 这意味着在EVM内运行的代码不能访问网络，文件系统或其他进程。 甚至智能合约之间的访问也是受限的。

账户
在以太坊有两种共享同一地址空间的账户： 外部账户，由公钥-私钥对（也就是人）控制； 合约账户，由与账户一起存储的代码控制。

外部账户的地址是由公钥确定的， 而合约的地址是在合约创建时确定的 （它是由创建者地址和从该地址发出的交易数量得出的，即所谓的 "nonce"）。

无论账户是否存储代码，这两种类型都被EVM平等对待。

Every account has a persistent key-value store mapping 256-bit words to 256-bit words called storage.

此外，每个账户有一个以太 余额 （ balance ）（单位是“Wei”， 1 ether 是 10**18 wei）， 余额会因为发送包含以太币的交易而改变。



## Refs

* [Solidity官方文档](https://docs.soliditylang.org/zh/latest/)
* [Solidity英文文档](https://docs.soliditylang.org/en/v0.8.21/introduction-to-smart-contracts.html)
