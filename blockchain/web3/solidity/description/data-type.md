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

您可以查询任何智能合约的部署代码。使用 .code 获得作为 bytes memory 的EVM字节码， 这可能是空的。使用 .codehash 获得该代码的Keccak-256哈希值（作为 bytes32）。 注意，使用 addr.codehash 比 keccak256(addr.code) 更便宜。

Note:所有的合约都可以转换为 address 类型，所以可以用 address(this).balance 查询当前合约的余额。

2.6、合约类型

每个 合约 都定义了自己的类型。 您可以隐式地将一个合约转换为它们所继承的另一个合约。 合约可以显式地转换为 address 类型，也可以从 address 类型中转换。

只有在合约类型具有 receive 或 payable 类型的 fallback 函数的情况下， 才有可能明确转换为 address payable 类型和从该类型转换。 这种转换仍然使用 address(x) 进行转换。如果合约类型没有一个 receive 或 payable 类型的 fallback 函数， 可以使用 payable(address(x)) 来转换为 address payable 。 您可以在 地址类型 一节中找到更多信息。

如果您声明了一个本地类型的变量（ MyContract c ），您可以调用该合约上的函数。 注意要从相同合约类型的地方将其赋值。

您也可以实例化合约（这意味着它们是新创建的）。 您可以在 '通过关键字new创建合约' 部分找到更多细节。

合约不支持任何运算符。

合约类型的成员是合约的外部函数，包括任何标记为 public 的状态变量。

对于一个合约 C，您可以使用 type(C) 来访问 关于该合约的 类型信息 。

。。。

2.7 枚举类型

枚举是在 Solidity 中创建用户定义类型的一种方式。 它们可以显式地转换为所有整数类型，和从整数类型来转换，但不允许隐式转换。 从整数的显式转换在运行时检查该值是否在枚举的范围内，否则会导致 异常。 枚举要求至少有一个成员，其声明时的默认值是第一个成员。 枚举不能有超过256个成员。

数据表示与 C 语言中的枚举相同。选项由后续的从 0 开始无符号整数值表示。

使用 type(NameOfEnum).min 和 type(NameOfEnum).max 您可以得到给定枚举的最小值和最大值。

```solidity
pragma solidity ^0.8.8;

contract test {
    enum ActionChoices { GoLeft, GoRight, GoStraight, SitStill }
    ActionChoices choice;
    ActionChoices constant defaultChoice = ActionChoices.GoStraight;

    function setGoStraight() public {
        choice = ActionChoices.GoStraight;
    }

    // 由于枚举类型不属于ABI的一部分，因此对于所有来自 Solidity 外部的调用，
    // "getChoice" 的签名会自动被改成 "getChoice() returns (uint8)"。
    function getChoice() public view returns (ActionChoices) {
        return choice;
    }

    function getDefaultChoice() public pure returns (uint) {
        return uint(defaultChoice);
    }

    function getLargestValue() public pure returns (ActionChoices) {
        return type(ActionChoices).max;
    }

    function getSmallestValue() public pure returns (ActionChoices) {
        return type(ActionChoices).min;
    }
}
```

2.8 用户定义的值类型

一个用户定义的值类型允许在一个基本的值类型上创建一个零成本的抽象。 这类似于一个别名，但有更严格的类型要求。

一个用户定义的值类型是用 type C is V 定义的，其中 C 是新引入的类型的名称， V 必须是一个内置的值类型（“底层类型”）。 函数 C.wrap 被用来从底层类型转换到自定义类型。同样地， 函数 C.unwrap 被用来从自定义类型转换到底层类型。

类型 C 没有任何运算符或附加成员函数。特别是，甚至运算符 == 也没有定义。 不允许对其他类型进行显式和隐式转换。

下面的例子说明了一个自定义类型 UFixed256x18， 代表一个有18位小数的十进制定点类型和一个最小的库来对该类型做算术运算。

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.8;

// 使用用户定义的值类型表示一个18位小数，256位宽的定点类型。
type UFixed256x18 is uint256;

/// 一个在UFixed256x18上进行定点操作的最小库。
library FixedMath {
    uint constant multiplier = 10**18;

    /// 将两个UFixed256x18的数字相加。溢出时将返回，依靠uint256的算术检查。
    function add(UFixed256x18 a, UFixed256x18 b) internal pure returns (UFixed256x18) {
        return UFixed256x18.wrap(UFixed256x18.unwrap(a) + UFixed256x18.unwrap(b));
    }
    /// 将UFixed256x18和uint256相乘。溢出时将返回，依靠uint256的算术检查。
    function mul(UFixed256x18 a, uint256 b) internal pure returns (UFixed256x18) {
        return UFixed256x18.wrap(UFixed256x18.unwrap(a) * b);
    }
    /// 对一个UFixed256x18类型的数字相下取整。
    /// @return 不超过 `a` 的最大整数。
    function floor(UFixed256x18 a) internal pure returns (uint256) {
        return UFixed256x18.unwrap(a) / multiplier;
    }
    /// 将一个uint256转化为相同值的UFixed256x18。
    /// 如果整数太大，则恢复计算。
    function toUFixed256x18(uint256 a) internal pure returns (UFixed256x18) {
        return UFixed256x18.wrap(a * multiplier);
    }
}
```

2.9 函数类型

函数类型是一种表示函数的类型。可以将一个函数赋值给另一个函数类型的变量， 也可以将一个函数作为参数进行传递，还能在函数调用中返回函数类型变量。 函数类型有两类：- 内部（internal） 函数和 外部（external） 函数：

内部函数只能在当前合约内被调用（更具体来说， 在当前代码块内，包括内部库函数和继承的函数中）， 因为它们不能在当前合约上下文的外部被执行。 调用一个内部函数是通过跳转到它的入口标签来实现的， 就像在当前合约的内部调用一个函数。

外部函数由一个地址和一个函数签名组成，可以通过外部函数调用传递或者返回。

函数类型表示成如下的形式：

```solidity
function (<parameter types>) {internal|external} [pure|view|payable] [returns (<return types>)]
```

与参数类型相反，返回类型不能为空 —— 如果函数类型不需要返回， 则需要删除整个 returns (<return types>) 部分。

默认情况下，函数类型是内部函数，所以可以省略 internal 关键字。 注意，这只适用于函数类型。对于合约中定义的函数， 必须明确指定其可见性，它们没有默认类型。

转换：

当且仅当它们的参数类型相同，它们的返回类型相同，它们的内部/外部属性相同， 并且 A 的状态可变性比 B 的状态可变性更具限制性时， 一个函数类型 A 就可以隐式转换为一个函数类型 B。特别是：

pure 函数可以转换为 view 和 非 payable 函数

view 函数可以转换为 非 payable 函数

payable 函数可以转换为 非 payable 函数

其他函数类型之间的转换是不可能的。

关于 payable 和 非 payable 的规则可能有点混乱， 但实质上，如果一个函数是 payable，这意味着 它也接受零以太的支付，所以它也是 非 payable。 另一方面，一个 非 payable 的函数将拒收发送给它的以太， 所以 非 payable 的函数不能被转换为 payable 的函数。 声明一下，拒收以太比不拒收以太更有限制性。 这意味着您可以用一个不可支付的函数覆写一个可支付的函数，但不能反过来。

。。。


以下例子展示如何使用这些成员：

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.6.4 <0.9.0;

contract Example {
    function f() public payable returns (bytes4) {
        assert(this.f.address == address(this));
        return this.f.selector;
    }

    function g() public {
        this.f{gas: 10, value: 800}();
    }
}
```

以下例子展示如何使用内部函数类型：

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

library ArrayUtils {
    // 内部函数可以在内部库函数中使用，因为它们将是同一代码上下文的一部分
    function map(uint[] memory self, function (uint) pure returns (uint) f)
        internal
        pure
        returns (uint[] memory r)
    {
        r = new uint[](self.length);
        for (uint i = 0; i < self.length; i++) {
            r[i] = f(self[i]);
        }
    }

    function reduce(
        uint[] memory self,
        function (uint, uint) pure returns (uint) f
    )
        internal
        pure
        returns (uint r)
    {
        r = self[0];
        for (uint i = 1; i < self.length; i++) {
            r = f(r, self[i]);
        }
    }

    function range(uint length) internal pure returns (uint[] memory r) {
        r = new uint[](length);
        for (uint i = 0; i < r.length; i++) {
            r[i] = i;
        }
    }
}


contract Pyramid {
    using ArrayUtils for *;

    function pyramid(uint l) public pure returns (uint) {
        return ArrayUtils.range(l).map(square).reduce(sum);
    }

    function square(uint x) internal pure returns (uint) {
        return x * x;
    }

    function sum(uint x, uint y) internal pure returns (uint) {
        return x + y;
    }
}
```

Q：solidity function可以直接变量.使用function？用法有点奇怪？

3、引用类型

3.1 数组

数组可以在声明时指定长度，也可以动态调整大小。

一个元素类型为 T，固定长度为 k 的数组可以声明为 T[k]， 而动态数组声明为 T[]。

数组成员

length:
数组有 length 成员变量表示当前数组的长度。一经创建， 内存memory数组的大小就是固定的（但却是动态的，也就是说，它依赖于运行时的参数）。

push():
动态存储数组和 bytes （不是 string ）有一个叫 push() 的成员函数， 您可以用它在数组的末尾追加一个零初始化的元素。它返回一个元素的引用， 因此可以像 x.push().t = 2 或 x.push() = b 那样使用。

push(x):
动态存储数组和 bytes （不是 string ）有一个叫 push(x) 的成员函数， 您可以用它在数组的末端追加一个指定的元素。该函数不返回任何东西。

pop():
动态存储数组和 bytes （不是 string ）有一个叫 pop() 的成员函数， 您可以用它来从数组的末端移除一个元素。 这也隐含地在被删除的元素上调用 delete。该函数不返回任何东西。

数组切片

数组切片是对一个数组的连续部分的预览。 它们被写成 x[start:end]，其中 start 和 end 是表达式， 结果是uint256类型（或隐含的可转换类型）。分片的第一个元素是 x[start]， 最后一个元素是 x[end - 1]。

如果 start 大于 end，或者 end 大于数组的长度， 就会出现异常。

start 和 end 都是可选的： start 默认为 0， end 默认为数组的长度。

3.2、结构体

Solidity 提供了一种以结构形式定义新类型的方法，结构类型可以在映射和数组内使用， 它们本身可以包含映射和数组。

结构体不可能包含其自身类型的成员，尽管结构本身可以是映射成员的值类型， 或者它可以包含其类型的动态大小的数组。 这一限制是必要的，因为结构的大小必须是有限的。

3.3、映射类型

映射类型使用语法 mapping(KeyType KeyName? => ValueType ValueName?)， 映射类型的变量使用语法 mapping(KeyType KeyName? => ValueType ValueName?) VariableName 声明。 KeyType 可以是任何内置的值类型， bytes， string，或任何合约或枚举类型。 其他用户定义的或复杂的类型，如映射，结构体或数组类型是不允许的。 ValueType 可以是任何类型，包括映射，数组和结构体。 KeyName 和 ValueName 是可选的（所以 mapping(KeyType => ValueType) 也可以使用）， 可以是任何有效的标识符，而不是一个类型。

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.0 <0.9.0;

contract MappingExample {
    mapping(address => uint) public balances;

    function update(uint newBalance) public {
        balances[msg.sender] = newBalance;
    }
}

contract MappingUser {
    function f() public returns (uint) {
        MappingExample m = new MappingExample();
        m.update(100);
        return m.balances(address(this));
    }
}
```

4、地址类型

正如在 地址字面常数（Address Literals） 中所描述的那样，正确大小并通过校验测试的十六进制字是 address 类型。 其他字面常数不能隐含地转换为 address 类型。

只允许从 bytes20 和 uint160 显式转换到 address。

address a 可以通过 payable(a) 显式转换为 address payable。

Note：在 0.8.0 版本之前，可以显式地从任何整数类型（任何大小，有符号或无符号）转换为 address 或 address payable 类型。 从 0.8.0 开始，只允许从 uint160 转换。

Note：该篇文章内容丰富，后续遇到问题再细致查阅，本次只做概览目的

