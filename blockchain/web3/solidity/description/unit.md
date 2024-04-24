单位和全局可用变量
==================

1、以太坊（Ether） 单位

一个字面常数可以带一个后缀 wei， gwei 或 ether 来指定一个以太坊的数量， 其中没有后缀的以太数字被认为单位是wei。

```
assert(1 wei == 1);
assert(1 gwei == 1e9);
assert(1 ether == 1e18);
```

单位后缀的唯一作用是乘以10的幂次方

2、时间单位

诸如 seconds， minutes， hours， days 和 weeks 等 后缀在字面常数后面，可以用来指定时间单位，其中秒是基本单位，单位的考虑方式很直白：

1 == 1 seconds

1 minutes == 60 seconds

1 hours == 60 minutes

1 days == 24 hours

1 weeks == 7 days

如果您使用这些单位进行日历计算，请注意，由于 闰秒 会造成不是每一年都等于365天，甚至不是每一天都有24小时，而且因为闰秒是无法预测的， 所以需要借助外部的预言机（oracle，是一种链外数据服务，译者注）来对一个确定的日期代码库进行时间矫正。

这些后缀单位不能应用于变量。例如， 如果您想用时间单位（例如 days）来将输入变量换算为时间，您可以用以下方式：

```solidity
function f(uint start, uint daysAfter) public {
    if (block.timestamp >= start + daysAfter * 1 days) {
        // ...
    }
}
```

3、特殊变量和函数

有一些特殊的变量和函数总是存在于全局命名空间，主要用于提供区块链的信息，或者是通用的工具函数。

3.1、区块和交易属性

blockhash(uint blockNumber) returns (bytes32): 当 blocknumber 是最近的256个区块之一时，给定区块的哈希值；否则返回0。

block.basefee （ uint）： 当前区块的基本费用 （ EIP-3198 和 EIP-1559）

block.chainid （ uint）： 当前链的ID

block.coinbase （ address payable）： 挖出当前区块的矿工地址

block.difficulty （ uint）： 当前块的难度（ EVM < Paris ）。对于其他EVM版本，它是为 block.prevrandao 的已废弃别名 （EIP-4399 ）

block.gaslimit （ uint）： 当前区块 gas 限额

block.number （ uint）： 当前区块号

block.timestamp （ uint）： 自 unix epoch 起始到当前区块以秒计的时间戳

gasleft() returns (uint256)： 剩余的 gas

msg.data （ bytes calldata）： 完整的 calldata

msg.sender （ address）： 消息发送者（当前调用）

msg.sig （ bytes4）： calldata 的前 4 字节（也就是函数标识符）

msg.value （ uint）： 随消息发送的 wei 的数量

tx.gasprice （ uint）： 随消息发送的 wei 的数量

tx.origin （ address）： 交易发起者（完全的调用链）

Note：对于每一个 外部（external） 函数调用， 包括 msg.sender 和 msg.value 在内所有 msg 成员的值都会变化。 这里包括对库函数的调用。

3.2、ABI编码和解码函数

abi.decode(bytes memory encodedData, (...)) returns (...): ABI-解码给定的数据，而类型在括号中作为第二个参数给出。例如： (uint a, uint[2] memory b, bytes memory c) = abi.decode(data, (uint, uint[2], bytes))

abi.encode(...) returns (bytes memory)： 对给定的参数进行ABI编码

abi.encodePacked(...) returns (bytes memory)： 对给定参数执行 紧打包编码。 请注意，打包编码可能会有歧义!

abi.encodeWithSelector(bytes4 selector, ...) returns (bytes memory)： ABI-对给定参数进行编码，并以给定的函数选择器作为起始的4字节数据一起返回

abi.encodeWithSignature(string memory signature, ...) returns (bytes memory)： 相当于 abi.encodeWithSelector(bytes4(keccak256(bytes(signature))), ...)

abi.encodeCall(function functionPointer, (...)) returns (bytes memory)： 对 函数指针 的调用进行ABI编码，参数在元组中找到。执行全面的类型检查，确保类型与函数签名相符。结果相当于 abi.encodeWithSelector(functionPointer.selector, (...))。

3.3、成员&错误处理

关于错误处理和何时使用哪个函数的更多细节， 请参见 assert 和 require 的专门章节。

assert(bool condition)
如果条件不满足，会导致异常，因此，状态变化会被恢复 - 用于内部错误。

require(bool condition)
如果条件不满足，则恢复状态更改 - 用于输入或外部组件的错误。

require(bool condition, string memory message)
如果条件不满足，则恢复状态更改 - 用于输入或外部组件的错误，可以同时提供一个错误消息。

revert()
终止运行并恢复状态更改。

revert(string memory reason)
终止运行并恢复状态更改，可以同时提供一个解释性的字符串。


地址类型的成员：

<address>.balance （ uint256 ）
以 Wei 为单位的 地址类型 的余额。

<address>.code （ bytes memory ）
在 地址类型 的代码（可以是空的）。

<address>.codehash （ bytes32 ）
地址类型 的代码哈希值

<address payable>.transfer(uint256 amount)
向 地址类型 发送数量为 amount 的 Wei，失败时抛出异常，发送 2300 gas 的矿工费，不可调节。

<address payable>.send(uint256 amount) returns (bool)
向 地址类型 发送数量为 amount 的 Wei，失败时返回 false 2300 gas 的矿工费用，不可调节。

<address>.call(bytes memory) returns (bool, bytes memory)
用给定的数据发出低级别的 CALL，返回是否成功的结果和数据，发送所有可用 gas，可调节。

<address>.delegatecall(bytes memory) returns (bool, bytes memory)
用给定的数据发出低级别的 DELEGATECALL，返回是否成功的结果和数据，发送所有可用 gas，可调节。

<address>.staticcall(bytes memory) returns (bool, bytes memory)
用给定的数据发出低级别的 STATICCALL，返回是否成功的结果和数据，发送所有可用 gas，可调节。

Note：您应该尽可能避免在执行另一个合约函数时使用 .call()，因为它绕过了类型检查、函数存在性检查和参数打包。

使用 send 有很多危险：如果调用栈深度已经达到 1024（这总是可以由调用者所强制指定）， 转账会失败；并且如果接收者用光了 gas，转账同样会失败。为了保证以太坊转账安全， 总是检查 send 的返回值，使用 transfer 或者下面更好的方式： 用接收者提款的模式。

合约相关

this （当前合约类型）
当前合约，可以明确转换为 地址类型

super
继承层次结构中更高一级的合约

selfdestruct(address payable recipient)
销毁当前合约，将其资金发送到给定的 地址类型 并结束执行。 注意， selfdestruct 有一些从EVM继承的特殊性：

接收合约的接收函数不会被执行。

合约只有在交易结束时才真正被销毁， 任何一个 revert 可能会 "恢复" 销毁。

此外，当前合约的所有函数都可以直接调用，包括当前函数。

4、保留关键词

这些关键字在 Solidity 中是保留的。它们在将来可能成为语法的一部分：

after， alias， apply， auto， byte， case， copyof， default， define， final， implements， in， inline， let， macro， match， mutable， null， of， partial， promise， reference， relocatable， sealed， sizeof， static， supports， switch， typedef， typeof， var。