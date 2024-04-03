Solidity 数据类型
================

1、前言

Solidity 是一种静态类型语言，这意味着每个变量（状态变量和局部变量）都需要被指定类型。 Solidity 提供了几种基本类型，可以用来组合出复杂类型。

Solidity中不存在"未定义"或"空"值的概念， 但新声明的变量总是有一个取决于其类型的 默认值。 为了处理任何意外的值，您应该使用 revert 函数 来恢复整个事务， 或者返回一个带有第二个 bool 值的元组来表示成功。

2、值类型

以下被称为值类型，因为它们的变量总是按值传递， 也就是说，当这些变量被用作函数参数或者用在赋值语句中时，总会进行值拷贝。

2.1、布尔类型

bool ：可能的取值为常数值 true 和 false。

运算符：

! (逻辑非)

&& (逻辑与, "and")

|| (逻辑或, "or")

== (等于)

!= (不等于)

运算符 || 和 && 都遵循同样的短路（ short-circuiting ）规则。 就是说在表达式 f(x) || g(y) 中， 如果 f(x) 的值为 true ， 那么 g(y) 就不会被执行，即使会出现一些副作用。

2.2、整型

int / uint: 分别表示有符号和无符号的不同位数的整型变量。 关键字 uint8 到 uint256 （无符号整型，从 8 位到 256 位）以及 int8 到 int256， 以 8 位为步长递增。 uint 和 int 分别是 uint256 和 int256 的别名。

运算符：

比较运算符： <=， <， ==， !=， >=， > （返回布尔值）

位运算符： &， |， ^ (异或)， ~ (位取反)

移位运算符： << （左移）， >> （右移）

算数运算符： +， -， 一元运算 - （只适用于有符号的整数）， *， /， % (取余)， ** (幂)

对于一个整数类型 X，您可以使用 type(X).min 和 type(X).max 来访问该类型代表的最小值和最大值。

2.3、定长浮点型

Solidity 还没有完全支持定长浮点型。可以声明定长浮点型的变量， 但不能给它们赋值或把它们赋值给其他变量。

fixed / ufixed：表示各种大小的有符号和无符号的定长浮点型。 在关键字 ufixedMxN 和 fixedMxN 中， M 表示该类型占用的位数， N 表示可用的小数位数。 M 必须能整除 8，即 8 到 256 位。 N 则可以是从 0 到 80 之间的任意数。 ufixed 和 fixed 分别是 ufixed128x18 和 fixed128x18 的别名。

Note:浮点型（在许多语言中的 float 和 double ，更准确地说是 IEEE 754 类型）和定长浮点型之间最大的不同点是， 在前者中整数部分和小数部分（小数点后的部分）需要的位数是灵活可变的，而后者中这两部分的长度受到严格的规定。 一般来说，在浮点型中，几乎整个空间都用来表示数字，但只有少数的位来表示小数点的位置。

2.4、地址类型

地址类型有两种基本相同的类型：

address: 保存一个20字节的值（一个以太坊地址的大小）。

address payable: 与 address 类型相同，但有额外的方法 transfer 和 send。

这种区别背后的想法是， address payable 是一个您可以发送以太币的地址， 而您不应该发送以太币给一个普通的 address，例如，因为它可能是一个智能合约， 而这个合约不是为接受以太币而建立的。

类型转换：

允许从 address payable 到 address 的隐式转换， 而从 address 到 address payable 的转换必须通过 payable(<address>) 来明确。

对于 uint160、整数、 bytes20 和合约类型，允许对 address 进行明确的转换和输出。

只有 address 类型和合约类型的表达式可以通过 payable(...) 显式转换为 address payable 类型。 对于合约类型，只有在合约可以接收以太的情况下才允许这种转换，也就是说， 合约要么有一个 receive 函数，要么有一个 payable 类型的 fallback 的函数。 请注意， payable(0) 是有效的，是这个规则的例外？？？

运算符：

<=, <, ==, !=, >= 和 >

Note：如果您使用较大字节的类型转换为 address，例如 bytes32，那么 address 就被截断了。 为了减少转换的模糊性，从 0.4.24 版本开始，编译器将强迫您在转换中明确地进行截断处理。以32字节的值 0x111122333344556677888899AAAABBBBCCCCDDDDEEFFFFCCCC 为例。

您可以使用 address(uint160(bytes20(b)))，结果是 0x111122223333444455556666777788889999aAaa， 或者您可以使用 address(uint160(uint256(b)))，结果是 0x777788889999AaAAbBbbCcccddDdeeeEfFFfCcCc。

2.5、地址类型成员变量

* balance 和 transfer

可以使用 balance 属性来查询一个地址的以太币余额， 也可以使用 transfer 函数向一个地址发送以太币（以 wei 为单位）：

```solidity
address payable x = payable(0x123);
address myAddress = address(this);
if (x.balance < 10 && myAddress.balance >= 10) x.transfer(10);
```

如果当前合约的余额不足，或者以太币转账被接收账户拒收，那么 transfer 功能就会失败。 transfer 功能在失败后会被还原。

Note：如果 x 是一个合约地址，它的代码（更具体地说：它的 接收以太的函数，如果有的话， 或者它的 Fallback 函数，如果有的话）将与 transfer 调用一起执行（这是EVM的一个特性，无法阻止）。 如果执行过程中耗尽了gas或出现了任何故障，以太币的转移将被还原，当前的合约将以异常的方式停止。

* send

send 是 transfer 的低级对应部分。如果执行失败，当前的合约不会因异常而停止，但 send 会返回 false。

使用 send 有一些危险：如果调用堆栈深度为1024，传输就会失败（这可以由调用者强制执行）， 如果接收者的gas耗尽，也会失败。因此，为了安全地进行以太币转账， 一定要检查 send 的返回值，或者使用 transfer，甚至使用更好的方式： 使用收款人提款的模式。

* call, delegatecall 和 staticcall

为了与不遵守ABI的合约对接，或者为了更直接地控制编码， 我们提供了 call, delegatecall 和 staticcall 函数。 它们都接受一个 bytes memory 参数，并返回成功条件（作为一个 bool） 和返回的数据（ bytes memory）。 函数 abi.encode, abi.encodePacked, abi.encodeWithSelector 和 abi.encodeWithSignature 可以用来编码结构化的数据。

```solidity
bytes memory payload = abi.encodeWithSignature("register(string)", "MyName");
(bool success, bytes memory returnData) = address(nameReg).call(payload);
require(success);
```

Note：所有这些函数都是低级别的函数，应该谨慎使用。 具体来说，任何未知的合约都可能是恶意的，如果您调用它， 您就把控制权交给了该合约，而该合约又可能回调到您的合约中， 所以要准备好在调用返回时改变您合约的状态变量。 与其他合约互动的常规方法是在合约对象上调用一个函数（ x.f()）？？？

可以用 gas 修饰器来调整所提供的gas：

```solidity
address(nameReg).call{gas: 1000000}(abi.encodeWithSignature("register(string)", "MyName"));
```

同样，所提供的以太值也可以被控制：

```solidity
address(nameReg).call{value: 1 ether}(abi.encodeWithSignature("register(string)", "MyName"));
```

最后，这些修饰器可以合并。它们的顺序并不重要：

```solidity
address(nameReg).call{gas: 1000000, value: 1 ether}(abi.encodeWithSignature("register(string)", "MyName"));
```

以类似的方式，可以使用函数 delegatecall：不同的是，它只使用给定地址的代码， 所有其他方面（存储，余额，...）都取自当前的合约。 delegatecall 的目的是为了使用存储在另一个合约中的库代码。 用户必须确保两个合约中的存储结构都适合使用delegatecall。

从 byzantium 开始，也可以使用 staticcall。这基本上与 call 相同， 但如果被调用的函数以任何方式修改了状态，则会恢复。

这三个函数 call， delegatecall 和 staticcall 都是非常低级的函数， 只应该作为 最后的手段 来使用，因为它们破坏了Solidity的类型安全。

gas 选项在所有三种方法中都可用，而 value 选项只在 call 中可用。

Note：It is best to avoid relying on hardcoded gas values in your smart contract code, regardless of whether state is read from or written to, as this can have many pitfalls. Also, access to gas might change in the future.

* code 和 codehash



2.6、合约类型

