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

1、账户

在以太坊有两种共享同一地址空间的账户： 外部账户，由公钥-私钥对（也就是人）控制； 合约账户，由与账户一起存储的代码控制。

外部账户的地址是由公钥确定的， 而合约的地址是在合约创建时确定的 （它是由创建者地址和从该地址发出的交易数量得出的，即所谓的 "nonce"）。

无论账户是否存储代码，这两种类型都被EVM平等对待。

Every account has a persistent key-value store mapping 256-bit words to 256-bit words called storage.

此外，每个账户有一个以太 余额 （ balance ）（单位是“Wei”， 1 ether 是 10**18 wei）， 余额会因为发送包含以太币的交易而改变。

总结：账户分为外部账户（地址为公钥）和合约账户（创建者地址和从该地址发出的交易数量nonce得出的），其中合约账户存储代码

2、Transactions

A transaction is a message that is sent from one account to another account (which might be the same or empty, see below). It can include binary data (which is called “payload”) and Ether.

If the target account contains code, that code is executed and the payload is provided as input data.

If the target account is not set (the transaction does not have a recipient or the recipient is set to null), the transaction creates a new contract. As already mentioned, the address of that contract is not the zero address but an address derived from the sender and its number of transactions sent (the “nonce”). The payload of such a contract creation transaction is taken to be EVM bytecode and executed. The output data of this execution is permanently stored as the code of the contract. This means that in order to create a contract, you do not send the actual code of the contract, but in fact code that returns that code when executed.

>> While a contract is being created, its code is still empty. Because of that, you should not call back into the contract under construction until its constructor has finished executing.

交易可以看作是从一个帐户发送到另一个帐户的消息 （这里的账户，可能是相同的或特殊的零帐户，请参阅下文）。 它能包含一个二进制数据（被称为“合约负载”）和以太。

如果目标账户含有代码，此代码会被执行，并以合约负载（二进制数据） 作为入参。

如果目标账户没有设置（交易没有接收者或接收者被设置为 null）， 交易会创建一个 新合约。 这种合约创建交易的有效负载被认为是EVM字节码并被执行。 该执行的输出数据被永久地存储为合约的代码。 这意味着，为创建一个合约，您不需要发送实际的合约代码，而是发送能够产生合约代码的代码。

3、Gas

---
什么是 gas？

以太坊在区块链上实现了一个运行环境，被称为以太坊虚拟机（EVM）。每个参与到网络的节点都会运行EVM作为区块验证协议的一部分。他们会验证区块中涵盖的每个交易并在EVM中运行交易所触发的代码。每个网络中的全节点都会进行相同的计算并储存相同的值。合约执行会在所有节点中被多次重复，这个事实得使得合约执行的消耗变得昂贵，所以这也促使大家将能在链下进行的运算都不放到区块链上进行。对于每个被执行的命令都会有一个特定的消耗，用单位gas计数。每个合约可以利用的命令都会有一个相应的gas值。

gas和交易消耗的gas

每笔交易都被要求包括一个gas limit（有的时候被称为startGas）和一个交易愿为单位gas支付的费用。矿工可以有选择的打包这些交易并收取这些费用。在现实中，今天所有的交易最终都是由矿工选择的，但是用户所选择支付的交易费用多少会影响到该交易被打包所需等待的时长。如果该交易由于计算，包括原始消息和一些触发的其他消息，需要使用的gas数量小于或等于所设置的gas limit，那么这个交易会被处理。如果gas总消耗超过gas limit，那么所有的操作都会被复原，但交易是成立的并且交易费仍会被矿工收取。区块链会显示这笔交易完成尝试，但因为没有提供足够的gas导致所有的合约命令都被复原。所以交易里没有被使用的超量gas都会以以太币的形式打回给交易发起者。因为gas消耗一般只是一个大致估算，所以许多用户会超额支付gas来保证他们的交易会被接受。这没什么问题，因为多余的gas会被退回给你。

估算交易消耗

一个交易的交易费由两个因素组成：

gasUsed：该交易消耗的总gas数量

gasPrice：该交易中单位gas的价格（用以太币计算）

交易费 = gasUsed * gasPrice

gasUsed：每个EVM中的命令都被设置了相应的gas消耗值。gasUsed是所有被执行的命令的gas消耗值总和。

gasPrice：一个用户可以构建和签名一笔交易，但每个用户都可以各自设置自己希望使用的gasPrice，甚至可以是0。然而，以太坊客户端的Frontier版本有一个默认的gasPrice，即0.05e12 wei。矿工为了最大化他们的收益，如果大量的交易都是使用默认gasPrice即0.05e12 wei，那么基本上就很难有矿工去接受一个低gasPrice交易，更别说0 gasPrice交易了。

交易费案例

你可以将gasLimit理解为你汽车油箱的上限。同时将gasPrice理解为油价。

对于一辆车来说，油价可能是 $2.5（价格）每升（单位）。在以太坊中，就是20 GWei（价格）每gas（单位）。为了填满你的"油箱"，需要 10升$2.5的油 = $25。同样的，21000个20 GWei的gas = 0.00042 ETH。

因此，总交易费将会是0.00042以太币。

发送代币通常需要消耗大约5万至10万的gas，所以总交易费会上升0.001至0.002个ETH。

什么是"区块gas limit"?

区块gas limit是单个区块允许的最多gas总量，以此可以用来决定单个区块中能打包多少笔交易。例如，我们有5笔交易的gas limit分别是10、20、30、40和50.如果区块gas limit是100，那么前4笔交易就能被成功打包进入这个区块。矿工有权决定将哪些交易打包入区块。所以，另一个矿工可以选择打包最后两笔交易进入这个区块（50+40），然后再将第一笔交易打包（10）。如果你尝试将一个会使用超过当前区块gas limit的交易打包，这个交易会被网络拒绝，你的以太坊客户端会反馈错误"交易超过区块gas limit"。

目前区块的gas limit是 4,712,357 gas，数据来自于ethstats.net，这表示着大约224笔转账交易（gas limit为21000）可以被塞进一个区块（区块时间大约在15-20秒间波动）。这个协议允许每个区块的矿工调整区块gas limit，任意加减 1/2024（0.0976%）。

谁来决定
区块的gas limit是由在网络上的矿工决定的。与可调整的区块gas limit协议不同的是一个默认的挖矿策略，即大多数客户端默认最小区块gas limit为4,712,388。

区块gas limit是怎样改变的
以太坊上的矿工需要用一个挖矿软件，例如ethminer。它会连接到一个geth或者Parity以太坊客户端。Geth和Pairty都有让矿工可以更改配置的选项。

---

一经创建，每笔交易都会被收取一定数量的 gas， 这些 gas 必须由交易的发起人 （ tx.origin）支付。 在 EVM 执行交易时，gas 根据特定规则逐渐耗尽。 如果 gas 在某一点被用完（即它会为负）， 将触发一个 gas 耗尽异常， 这将结束执行并撤销当前调用栈中对状态所做的所有修改。

此机制激励了对 EVM 执行时间的经济利用， 并为 EVM 执行器（即矿工/持币者）的工作提供补偿。 由于每个区块都有最大 gas 量，因此还限制了验证块所需的工作量。

gas price 是交易发起人设定的值， 他必须提前向 EVM 执行器支付 gas_price * gas。 如果执行后还剩下一些 gas，则退还给交易发起人。 如果发生撤销更改的异常，已经使用的 gas 不会退还。

由于 EVM 执行器可以选择包含一笔交易， 因此交易发送者无法通过设置低 gas 价格滥用系统。

4、存储，内存和栈

The Ethereum Virtual Machine has three areas where it can store data: storage, memory and the stack.

Each account has a data area called storage, which is persistent between function calls and transactions. Storage is a key-value store that maps 256-bit words to 256-bit words. It is not possible to enumerate storage from within a contract, it is comparatively costly to read, and even more to initialise and modify storage. Because of this cost, you should minimize what you store in persistent storage to what the contract needs to run. Store data like derived calculations, caching, and aggregates outside of the contract. A contract can neither read nor write to any storage apart from its own.

The second data area is called memory, of which a contract obtains a freshly cleared instance for each message call. Memory is linear and can be addressed at byte level, but reads are limited to a width of 256 bits, while writes can be either 8 bits or 256 bits wide. Memory is expanded by a word (256-bit), when accessing (either reading or writing) a previously untouched memory word (i.e. any offset within a word). At the time of expansion, the cost in gas must be paid. Memory is more costly the larger it grows (it scales quadratically).

The EVM is not a register machine but a stack machine, so all computations are performed on a data area called the stack. It has a maximum size of 1024 elements and contains words of 256 bits. Access to the stack is limited to the top end in the following way: It is possible to copy one of the topmost 16 elements to the top of the stack or swap the topmost element with one of the 16 elements below it. All other operations take the topmost two (or one, or more, depending on the operation) elements from the stack and push the result onto the stack. Of course it is possible to move stack elements to storage or memory in order to get deeper access to the stack, but it is not possible to just access arbitrary elements deeper in the stack without first removing the top of the stack.

5、指令集

EVM的指令集应尽量保持最小，以避免不正确或不一致的实现，这可能导致共识问题。 所有的指令都是在基本的数据类型上操作的，256位的字或内存的片断（或其他字节数组）。 具备常用的算术，位，逻辑和比较操作。也可以做到有条件和无条件跳转。 此外，合约可以访问当前区块的相关属性，比如它的编号和时间戳。

6、消息调用

Contracts can call other contracts or send Ether to non-contract accounts by the means of message calls. Message calls are similar to transactions, in that they have a source, a target, data payload, Ether, gas and return data. In fact, every transaction consists of a top-level message call which in turn can create further message calls.

A contract can decide how much of its remaining gas should be sent with the inner message call and how much it wants to retain. If an out-of-gas exception happens in the inner call (or any other exception), this will be signaled by an error value put onto the stack. In this case, only the gas sent together with the call is used up. In Solidity, the calling contract causes a manual exception by default in such situations, so that exceptions “bubble up” the call stack.

As already said, the called contract (which can be the same as the caller) will receive a freshly cleared instance of memory and has access to the call payload - which will be provided in a separate area called the calldata. After it has finished execution, it can return data which will be stored at a location in the caller’s memory preallocated by the caller. All such calls are fully synchronous.

Calls are limited to a depth of 1024, which means that for more complex operations, loops should be preferred over recursive calls. Furthermore, only 63/64th of the gas can be forwarded in a message call, which causes a depth limit of a little less than 1000 in practice.

合约可以通过消息调用的方式来调用其它合约或者发送以太币到非合约账户。 消息调用和交易非常类似，它们都有一个源，目标，数据，以太币，gas和返回数据。 事实上每个交易都由一个顶层消息调用组成，这个消息调用又可创建更多的消息调用。

被调用的合约（可以与调用者是同一个合约）将收到一个新清空的内存实例， 并可以访问调用的有效负载-由被称为 calldata 的独立区域所提供的数据。 在它执行完毕后，它可以返回数据，这些数据将被存储在调用者内存中由调用者预先分配的位置。 所有这样的调用都是完全同步的。

调用合约内部的函数也被称为消息调用吗？

7、委托调用和库

There exists a special variant of a message call, named delegatecall which is identical to a message call apart from the fact that the code at the target address is executed in the context (i.e. at the address) of the calling contract and msg.sender and msg.value do not change their values.

This means that a contract can dynamically load code from a different address at runtime. Storage, current address and balance still refer to the calling contract, only the code is taken from the called address.

This makes it possible to implement the “library” feature in Solidity: Reusable library code that can be applied to a contract’s storage, e.g. in order to implement a complex data structure.

存在一种特殊的消息调用，被称为 委托调用（delegatecall）， 除了目标地址的代码是在调用合约的上下文（即地址）中执行， msg.sender 和 msg.value 的值不会更改之外，其他与消息调用相同

这意味着合约可以在运行时动态地从不同的地址加载代码。 存储，当前地址和余额仍然指的是调用合约，只是代码取自被调用的地址。

这使得在Solidity中实现 “库” 的功能成为可能： 可重复使用的库代码，可以放在一个合约的存储上，例如，用来实现复杂的数据结构的库。

8、日志

It is possible to store data in a specially indexed data structure that maps all the way up to the block level. This feature called logs is used by Solidity in order to implement events. Contracts cannot access log data after it has been created, but they can be efficiently accessed from outside the blockchain. Since some part of the log data is stored in bloom filters, it is possible to search for this data in an efficient and cryptographically secure way, so network peers that do not download the whole blockchain (so-called “light clients”) can still find these logs.

有一种特殊的可索引的数据结构，其存储的数据可以一路映射直到区块层级。 这个特性被称为 日志（logs） ，Solidity用它来实现 事件。

9、创建

合约甚至可以通过一个特殊的指令来创建其他合约（不是简单的调用零地址）。 创建合约的调用 create calls 和普通消息调用的唯一区别在于，负载会被执行，执行的结果被存储为合约代码，调用者/创建者在栈上得到新合约的地址。

Note：创建合约两种方式：消息调用零地址及crate calls

10、停用和自毁

从区块链上删除代码的唯一方法是当该地址的合约执行 selfdestruct 操作。 存储在该地址的剩余以太币被发送到一个指定的目标，然后存储和代码被从状态中删除。 删除合约在理论上听起来是个好主意，但它有潜在的危险性， 因为如果有人向被删除的合约发送以太币，以太币就会永远丢失。

Note：即使一个合约通过 selfdestruct 删除，它仍然是区块链历史的一部分， 可能被大多数以太坊节点保留。 因此，使用 selfdestruct 与从硬盘上删除数据不一样。

尽管一个合约的代码中没有显式地调用 selfdestruct ， 它仍然有可能通过 delegatecall 或 callcode 执行自毁操作。

如果您想停用您的合约，您可以通过改变一些内部状态来 停用 它们， 从而使再次调用所有的功能都会被恢复。这样就无法使用合约了，因为它立即返回以太。

11、预编译合约

有一小群合约地址是特殊的。 1 和（包括） 8 之间的地址范围包含 “预编译合约“， 可以像其他合约一样被调用，但它们的行为（和它们的gas消耗） 不是由存储在该地址的EVM代码定义的（它们不包含代码）， 而是由EVM执行环境本身实现。

不同的EVM兼容链可能使用不同的预编译合约集。 未来也有可能在以太坊主链上添加新的预编译合约， 但您可以合理地预期它们总是在 1 和 0xffff （包括）之间。

## Refs

* [Solidity官方文档](https://docs.soliditylang.org/zh/latest/)
* [Solidity英文文档](https://docs.soliditylang.org/en/v0.8.21/introduction-to-smart-contracts.html)
