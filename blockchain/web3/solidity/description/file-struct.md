Solidity 源文件结构
==================

源文件可以包含任意数量的 contract 定义, import 指令, pragma 指令和 using for 指令 和 struct, enum, function, error 以及 constant 变量 的定义。

1、SPDX 许可标识符

如果智能合约的源代码是公开的，就可以更好地建立对智能合约的信任。 由于提供源代码总是涉及到版权方面的法律问题， Solidity 编译器鼓励使用机器可读的 SPDX 许可标识符 。 每个源文件都应该以一个注释开始，表明其许可证

// SPDX-License-Identifier: MIT

编译器可以在文件的任何位置识别该注释， 但建议把它放在文件的顶部。

2、编译指示

pragma 关键字用于启用某些编译器特性或检查。 一个 pragma 指令始终是源文件的本地指令， 所以如果您想在整个项目中使用 pragma 指令， 您必须在您的所有文件中添加这个指令。 如果您 import 另一个文件， 该文件的 pragma 指令 不会 自动应用于导入文件。

版本编译指示：源文件可以（而且应该）用版本 pragma 指令来注释， 以拒绝用未来的编译器版本进行编译，因为这可能会引入不兼容的变化。版本编译指示使用如下： pragma solidity ^0.5.2;带有上述代码的源文件在 0.5.2 版本之前的编译器上不能编译， 在 0.6.0 版本之后的编译器上也不能工作（这第二个条件是通过使用 ^ 添加的）。

ABI编码编译指示：通过使用 pragma abicoder v1 或 pragma abicoder v2 ， 您可以选择ABI编码器和解码器的两种实现。新的 ABI 编码器（v2）能够对任意嵌套的数组和结构进行编码和解码。 除了支持更多的类型外，它还涉及更广泛的验证和安全检查， 这可能导致更高的gas costs，但也提高了安全性。 从 Solidity 0.6.0 开始，它被认为是非实验性的， 并且从 Solidity 0.8.0 开始，它被默认启用。 旧的 ABI 编码器仍然可以使用 pragma abicoder v1; 来选择。

3、导入其他源文件

Solidity 支持导入语句，以帮助模块化您的代码。在全局层面，您可以使用以下形式的导入语句：

```solidity
import "filename";
```

filename 部分被称为 导入路径。 该语句将所有来自 “filename” 的全局符号（以及在那里导入的符号） 导入到当前的全局范围（与ES6中不同，但对Solidity来说是向后兼容的）。 这种形式不建议使用，因为它不可预测地污染了命名空间。 如果您在 “filename” 里面添加新的顶层项目， 它们会自动出现在所有像这样从 “filename” 导入的文件中。 最好是明确地导入特定的符号。

下面的例子创建了一个新的全局符号 symbolName，其成员均来自 "filename" 中全局符号；

```solidity
import * as symbolName from "filename";
```

这意味着所有全局符号以 symbolName.symbol 的格式提供。

另一种语法不属于 ES6，但可能是有用的：

```solidity
import "filename" as symbolName;
```

这条语句等同于 import * as symbolName from "filename";。

如果有命名冲突，您可以在导入的同时重命名符号。 例如，下面的代码创建了新的全局符号 alias 和 symbol2， 它们分别从 "filename" 里面引用 symbol1 和 symbol2。

```solidity
import {symbol1 as alias, symbol2} from "filename";
```

4、注释

可以使用单行注释（ // ）和多行注释（ /*...*/ ）

```solidity
// 这是一个单行注释。

/*
这是一个
多行注释。
*/
```

Solidity合约也可以包含NatSpec注释。 它们用三重斜线（ ///）或双星号块（ /** ... */）来写， 它们应该直接用在函数声明或语句之上。

Solidity合约可以使用一种特殊形式的注释来为函数，返回变量等提供丰富的文档。 这种特殊形式被命名为Ethereum自然语言规范格式（NatSpec）。

该文件被划分为以开发人员为中心的信息和面向最终用户的信息。 这些信息可以在终端用户（人类）与合约交互（即签署交易）时显示给他们。

建议 Solidity 合约使用 NatSpec 对所有公共接口（ABI 中的一切）进行完全注释。

下面的例子显示了一个合约和一个使用所有可用标记的函数。

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.2 < 0.9.0;

/// @title 树的模拟器
/// @author Larry A. Gardner
/// @notice 您只能将此合约用于最基本的模拟。
/// @dev 目前所有的函数调用都是在没有副作用的情况下实现的
/// @custom:experimental 这是一个实验性的合约。
contract Tree {
    /// @notice 计算活体树木的树龄，按四舍五入计算
    /// @dev Alexandr N. Tetearing 算法可以提高精确度
    /// @param rings 树龄学样本的环数
    /// @return 树龄（岁），部分年份四舍五入
    function age(uint256 rings) external virtual pure returns (uint256) {
        return rings + 1;
    }

    /// @notice 返回该树的叶子数量。
    /// @dev 在此只是返回了一个固定的数字。
    function leaves() external virtual pure returns(uint256) {
        return 2;
    }
}

contract Plant {
    function leaves() external virtual pure returns(uint256) {
        return 3;
    }
}

contract KumquatTree is Tree, Plant {
    function age(uint256 rings) external override pure returns (uint256) {
        return rings + 2;
    }

    /// 返回这种特定类型的树的叶子数量。
    /// @inheritdoc Tree 合约
    function leaves() external override(Tree, Plant) pure returns(uint256) {
        return 3;
    }
}
```

所有标签都是可选的。下表解释了每个 NatSpec 标签的目的和它可能被使用的地方。 有一种特殊情况，如果没有使用标签，那么 Solidity 编译器将以同样的方式进行 /// 或 /** 注释， 如同它被标记为 @notice。

=============== ====================================================================================== =============================
``@title``      一个应该描述合约/接口的标题                                                                contract, library, interface
``@author``     作者的名字                                                                              contract, library, interface
``@notice``     向终端用户解释这个东西的作用                                                               contract, library, interface, function, public state variable, event
``@dev``        向开发人员解释任何额外的细节                                                               contract, library, interface, function, state variable, event
``@param``      就像在Doxygen中一样记录一个参数（必须在参数名之后）                                           function, event
``@return``     记录一个合约的函数的返回变量                                                                function, public state variable
``@inheritdoc`` 从基本函数中复制所有缺失的标签（必须在合约名称之后）                                            function, public state variable
``@custom:...`` 自定义标签，语义由应用程序定义                                                              everywhere
=============== ====================================================================================== =============================

如果您的函数返回多个值，如 (int quotient, int remainder) 那么使用多个 @return 语句，格式与 @param 语句相同。

自定义标签以 @custom: 开头，后面必须有一个或多个小写字母或连字符。 然而，它不能以连字符开始。它们可以在任何地方使用，是开发者文档的一部分。

当被编译器解析时，像上面例子中的文档将产生两个不同的JSON文件。 一个是为了让终端用户在执行函数时作为通知使用，另一个是为了让开发人员使用。

如果上述合约被保存为 ex1.sol，那么您可以用以下方法生成文档：

```bash
solc --userdoc --devdoc ex1.sol
```

Note:从Solidity 0.6.11版开始，NatSpec输出也包含一个 version（版本号） 和一个 kind（种类） 字段。 目前， version 被设置为 1， kind 必须是 user（用户） 或 dev（开发者） 之一。

上述文档将产生以下用户文档 JSON 文件作为输出：

```json
{
  "version" : 1,
  "kind" : "user",
  "methods" :
  {
    "age(uint256)" :
    {
      "notice" : "计算活体树木的树龄，按四舍五入计算"
    }
  },
  "notice" : "您只能将此合约用于最基本的模拟。"
}
```

除了用户文档文件，还应该产生一个开发者文档的JSON文件，看起来应该是这样的：

```json
{
  "version" : 1,
  "kind" : "dev",
  "author" : "Larry A. Gardner",
  "details" : "目前所有的函数调用都是在没有副作用的情况下实现的",
  "custom:experimental" : "这是一个实验性的合约。",
  "methods" :
  {
    "age(uint256)" :
    {
      "details" : "Alexandr N. Tetearing 算法可以提高精确度",
      "params" :
      {
        "rings" : "树龄学样本的环数"
      },
      "return" : "树龄（岁），部分年份四舍五入"
    }
  },
  "title" : "树的模拟器"
}
```

疑问：怎么理解一个是为了让终端用户在执行函数时作为通知使用？

## Refs

* [natspec](https://docs.soliditylang.org/zh/latest/natspec-format.html#natspec)

