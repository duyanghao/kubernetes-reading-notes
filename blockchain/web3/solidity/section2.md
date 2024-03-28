Solidity 合约示例
================

## 投票合约

下面的合约相当复杂，但展示了Solidity的很多特性。 它实现了一个投票合约。当然， 电子投票的主要问题是如何将投票权分配给正确的人以及如何防止人为操纵。 我们不会在这里解决所有的问题，但至少我们会展示如何进行委托投票， 与此同时，使计票是 自动且完全透明的。

我们的想法是为每张选票创建一份合约， 为每个选项提供一个简称。 然后，作为合约的创造者——即主席， 将给予每个地址单独的投票权。

地址后面的人可以选择自己投票，或者委托给他们信任的人来投票。

在投票时间结束时， winningProposal() 将返回拥有最大票数的提案。

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
/// @title 委托投票
contract Ballot {
    // 这声明了一个新的复杂类型，用于稍后变量。
    // 它用来表示一个选民。
    struct Voter {
        uint weight; // 计票的权重
        bool voted;  // 若为真，代表该人已投票
        address delegate; // 被委托人
        uint vote;   // 投票提案的索引
    }

    // 提案的类型
    struct Proposal {
        bytes32 name;   // 简称（最长32个字节）
        uint voteCount; // 得票数
    }

    address public chairperson;
    // 这声明了一个状态变量，为每个可能的地址存储一个 `Voter`。
    mapping(address => Voter) public voters;

    // 一个 `Proposal` 结构类型的动态数组。
    Proposal[] public proposals;

    /// 为 `proposalNames` 中的每个提案，创建一个新的（投票）表决
    constructor(bytes32[] memory proposalNames) {
        chairperson = msg.sender;
        voters[chairperson].weight = 1;

        // 对于提供的每个提案名称，
        // 创建一个新的 Proposal 对象并把它添加到数组的末尾。
        for (uint i = 0; i < proposalNames.length; i++) {
            // `Proposal({...})` 创建一个临时 Proposal 对象
            // `proposals.push(...)` 将其添加到 `proposals` 的末尾
            proposals.push(Proposal({
                name: proposalNames[i],
                voteCount: 0
            }));
        }
    }

    // 给予 `voter` 在这张选票上投票的权利。
    // 只有 `chairperson` 可以调用该函数。
    function giveRightToVote(address voter) external {
        // 若 `require` 的第一个参数的计算结果为 `false`，
        // 则终止执行，撤销所有对状态和以太币余额的改动。
        // 在旧版的 EVM 中这曾经会消耗所有 gas，但现在不会了。
        // 使用 `require` 来检查函数是否被正确地调用，通常是个好主意。
        // 您也可以在 `require` 的第二个参数中提供一个对错误情况的解释。
        require(
            msg.sender == chairperson,
            "Only chairperson can give right to vote."
        );
        require(
            !voters[voter].voted,
            "The voter already voted."
        );
        require(voters[voter].weight == 0);
        voters[voter].weight = 1;
    }

    /// 把您的投票委托给投票者 `to`。
    function delegate(address to) external {
        // 指定引用
        Voter storage sender = voters[msg.sender];
        require(sender.weight != 0, "You have no right to vote");
        require(!sender.voted, "You already voted.");

        require(to != msg.sender, "Self-delegation is disallowed.");

        // 委托是可以传递的，只要被委托者 `to` 也设置了委托。
        // 一般来说，这样的循环委托是非常危险的，因为如果传递的链条太长，
        // 可能需要消耗的gas就会超过一个区块中的可用数量。
        // 这种情况下，委托不会被执行。
        // 但在其他情况下，如果形成闭环，则会导致合约完全被 "卡住"。
        while (voters[to].delegate != address(0)) {
            to = voters[to].delegate;

            // 不允许闭环委托
            require(to != msg.sender, "Found loop in delegation.");
        }

        Voter storage delegate_ = voters[to];

        // 投票者不能将投票权委托给不能投票的账户。
        require(delegate_.weight >= 1);

        // 由于 `sender` 是一个引用，
        // 因此这会修改 `voters[msg.sender]`。
        sender.voted = true;
        sender.delegate = to;

        if (delegate_.voted) {
            // 若被委托者已经投过票了，直接增加得票数。
            proposals[delegate_.vote].voteCount += sender.weight;
        } else {
            // 若被委托者还没投票，增加委托者的权重。
            delegate_.weight += sender.weight;
        }
    }

    /// 把您的票(包括委托给您的票)，
    /// 投给提案 `proposals[proposal].name`。
    function vote(uint proposal) external {
        Voter storage sender = voters[msg.sender];
        require(sender.weight != 0, "Has no right to vote");
        require(!sender.voted, "Already voted.");
        sender.voted = true;
        sender.vote = proposal;

        // 如果 `proposal` 超过了数组的范围，
        // 则会自动抛出异常，并恢复所有的改动。
        proposals[proposal].voteCount += sender.weight;
    }

    /// @dev 结合之前所有投票的情况下，计算出获胜的提案。
    function winningProposal() public view
            returns (uint winningProposal_)
    {
        uint winningVoteCount = 0;
        for (uint p = 0; p < proposals.length; p++) {
            if (proposals[p].voteCount > winningVoteCount) {
                winningVoteCount = proposals[p].voteCount;
                winningProposal_ = p;
            }
        }
    }

    // 调用 `winningProposal()` 函数以获取提案数组中获胜者的索引，
    // 并以此返回获胜者的名称。
    function winnerName() external view
            returns (bytes32 winnerName_)
    {
        winnerName_ = proposals[winningProposal()].name;
    }
}
```

可能的优化
当前，为了把投票权分配给所有参与者，需要执行很多交易。 此外，如果两个或更多的提案有相同的票数， winningProposal() 无法登记平局。 您能想出一个办法来解决这些问题吗？

A1：可以设置一个批处理函数，批量分配投票权？
A2：将返回值设置为数组？如果元素为1，则没有平局；否则平局？

## 盲拍（秘密竞价）

在本节中，我们将展示如何轻松地在以太坊上创建一个盲拍的合约。 我们将从一个公开拍卖开始，每个人都可以看到出价， 然后将此合约扩展到盲拍合约， 在竞标期结束之前无法看到实际出价。

1、简单的公开拍卖

下面这个简单的拍卖合约的总体思路是，每个人都可以在竞标期间发送他们的竞标。 竞标已经包括发送资金/以太币，以便将竞标者与他们的竞标绑定。 如果最高出价被提高，之前的最高出价者就会拿回他们的钱。竞价期结束后，受益人需要手动调用合约，才能收到他们的钱 - 合约不能自己激活接收。

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;
contract SimpleAuction {
    // 拍卖的参数。
    // 时间是 unix 的绝对时间戳（自1970-01-01以来的秒数）
    // 或以秒为单位的时间段。
    address payable public beneficiary;
    uint public auctionEndTime;

    // 拍卖的当前状态。
    address public highestBidder;
    uint public highestBid;

    // 允许取回以前的竞标。
    mapping(address => uint) pendingReturns;

    // 拍卖结束后设为 `true`，将禁止所有的变更
    // 默认初始化为 `false`。
    bool ended;

    // 变化时将会发出的事件。
    event HighestBidIncreased(address bidder, uint amount);
    event AuctionEnded(address winner, uint amount);

    // 描述失败的错误信息。

    // 三斜线的注释是所谓的 natspec 注释。
    // 当用户被要求确认一个交易或显示一个错误时，它们将被显示。

    /// 竞拍已经结束。
    error AuctionAlreadyEnded();
    /// 已经有一个更高的或相等的出价。
    error BidNotHighEnough(uint highestBid);
    /// 竞拍还没有结束。
    error AuctionNotYetEnded();
    /// 函数 auctionEnd 已经被调用。
    error AuctionEndAlreadyCalled();

    /// 以受益者地址 `beneficiaryAddress` 创建一个简单的拍卖，
    /// 拍卖时长为 `_biddingTime`。
    constructor(
        uint biddingTime,
        address payable beneficiaryAddress
    ) {
        beneficiary = beneficiaryAddress;
        auctionEndTime = block.timestamp + biddingTime;
    }

    /// 对拍卖进行出价，具体的出价随交易一起发送。
    /// 如果没有在拍卖中胜出，则返还出价。
    function bid() external payable {
        // 参数不是必要的。因为所有的信息已经包含在了交易中。
        // 关键字 `payable` 是函数能够接收以太币的必要条件。

        // 如果拍卖已结束，撤销函数的调用。
        if (block.timestamp > auctionEndTime)
            revert AuctionAlreadyEnded();

        // 如果出价不高，就把钱送回去
        //（revert语句将恢复这个函数执行中的所有变化，
        // 包括它已经收到钱）。
        if (msg.value <= highestBid)
            revert BidNotHighEnough(highestBid);

        if (highestBid != 0) {
            // 简单地使用 highestBidder.send(highestBid)
            // 返还出价时，是有安全风险的，
            // 因为它可能执行一个不受信任的合约。
            // 让接收方自己取钱总是比较安全的。
            pendingReturns[highestBidder] += highestBid;
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
        emit HighestBidIncreased(msg.sender, msg.value);
    }

    /// 撤回出价过高的竞标。
    function withdraw() external returns (bool) {
        uint amount = pendingReturns[msg.sender];
        if (amount > 0) {
            // 将其设置为0是很重要的，
            // 因为接收者可以在 `send` 返回之前再次调用这个函数
            // 作为接收调用的一部分。
            pendingReturns[msg.sender] = 0;

            // msg.sender 不属于 `address payable` 类型，
            // 必须使用 `payable(msg.sender)` 明确转换，
            // 以便使用成员函数 `send()`。
            if (!payable(msg.sender).send(amount)) {
                // 这里不需抛出异常，只需重置未付款
                pendingReturns[msg.sender] = amount;
                return false;
            }
        }
        return true;
    }

    /// 结束拍卖，并把最高的出价发送给受益人。
    function auctionEnd() external {
        // 对于可与其他合约交互的函数（意味着它会调用其他函数或发送以太币），
        // 一个好的指导方针是将其结构分为三个阶段：
        // 1. 检查条件
        // 2. 执行动作 (可能会改变条件)
        // 3. 与其他合约交互
        // 如果这些阶段相混合，其他的合约可能会回调当前合约并修改状态，
        // 或者导致某些效果（比如支付以太币）多次生效。
        // 如果合约内调用的函数包含了与外部合约的交互，
        // 则它也会被认为是与外部合约有交互的。

        // 1. 条件
        if (block.timestamp < auctionEndTime)
            revert AuctionNotYetEnded();
        if (ended)
            revert AuctionEndAlreadyCalled();

        // 2. 影响
        ended = true;
        emit AuctionEnded(highestBidder, highestBid);

        // 3. 交互
        beneficiary.transfer(highestBid);
    }
}
```

疑问：竞标结束前根本没有给钱到受益者，为什么需要所谓的withdraw(撤回出价过高的竞标)？

A：因为bid函数中已经发送了以太币(有关键字 `payable` 是函数能够接收以太币的必要条件)，因此withdraw可以撤回竞标

疑问：多次竞拍是不是会有问题，会多出以太币？

A：因为可以让接收方自己通过withdraw去取回竞标的以太币，相当于每次调用一次撤回竞标，也可以一起撤回所有竞标（多次）

## 盲拍（秘密竞拍）

之前的公开拍卖接下来将被扩展为盲目拍卖。 盲拍的好处是，在竞价期即将结束时没有时间压力。 在一个透明的计算平台上创建一个盲拍可能听起来是一个矛盾，但加密技术可以实现它。

在 竞标期间，竞标者实际上并没有发送他们的出价， 而只是发送一个哈希版本的出价。 由于目前几乎不可能找到两个（足够长的）值， 其哈希值是相等的，因此竞标者可通过该方式提交报价。 在竞标结束后， 竞标者必须公开他们的出价：他们发送未加密的值，合约检查出价的哈希值是否与竞标期间提供的值相同。

另一个挑战是如何使拍卖同时做到 绑定和秘密 ： 唯一能阻止竞标者在赢得拍卖后不付款的方式是，让他们将钱和竞标一起发出。 但由于资金转移在以太坊中不能被隐藏，因此任何人都可以看到转移的资金。

下面的合约通过接受任何大于最高出价的值来解决这个问题。 当然，因为这只能在揭示阶段进行检查，有些出价可能是 无效 的， 而这是有目的的（它甚至提供了一个明确的标志，以便在高价值的转移中进行无效的出价）： 竞标者可以通过设置几个或高或低的无效出价来迷惑竞争对手。

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;
contract BlindAuction {
    struct Bid {
        bytes32 blindedBid;
        uint deposit;
    }

    address payable public beneficiary;
    uint public biddingEnd;
    uint public revealEnd;
    bool public ended;

    mapping(address => Bid[]) public bids;

    address public highestBidder;
    uint public highestBid;

    // 允许取回以前的竞标。
    mapping(address => uint) pendingReturns;

    event AuctionEnded(address winner, uint highestBid);

    // 描述失败的错误信息。

    /// 该函数被过早调用。
    /// 在 `time` 时间再试一次。
    error TooEarly(uint time);
    /// 该函数被过晚调用。
    /// 它不能在 `time` 时间之后被调用。
    error TooLate(uint time);
    /// 函数 auctionEnd 已经被调用。
    error AuctionEndAlreadyCalled();

    // 使用 修饰符（modifier） 可以更便捷的校验函数的入参。
    // `onlyBefore` 会被用于后面的 `bid` 函数：
    // 新的函数体是由 modifier 本身的函数体，其中`_`被旧的函数体所取代。
    modifier onlyBefore(uint time) {
        if (block.timestamp >= time) revert TooLate(time);
        _;
    }
    modifier onlyAfter(uint time) {
        if (block.timestamp <= time) revert TooEarly(time);
        _;
    }

    constructor(
        uint biddingTime,
        uint revealTime,
        address payable beneficiaryAddress
    ) {
        beneficiary = beneficiaryAddress;
        biddingEnd = block.timestamp + biddingTime;
        revealEnd = biddingEnd + revealTime;
    }

    /// 可以通过 `_blindedBid` = keccak256(value, fake, secret)
    /// 设置一个盲拍。
    /// 只有在出价披露阶段被正确披露，已发送的以太币才会被退还。
    /// 如果与出价一起发送的以太币至少为 "value" 且 "fake" 不为真，则出价有效。
    /// 将 "fake" 设置为 true ，
    /// 然后发送满足订金金额但又不与出价相同的金额是隐藏实际出价的方法。
    /// 同一个地址可以放置多个出价。
    function bid(bytes32 blindedBid)
        external
        payable
        onlyBefore(biddingEnd)
    {
        bids[msg.sender].push(Bid({
            blindedBid: blindedBid,
            deposit: msg.value
        }));
    }

    /// 披露你的盲拍出价。
    /// 对于所有正确披露的无效出价以及除最高出价以外的所有出价，您都将获得退款。
    function reveal(
        uint[] calldata values,
        bool[] calldata fakes,
        bytes32[] calldata secrets
    )
        external
        onlyAfter(biddingEnd)
        onlyBefore(revealEnd)
    {
        uint length = bids[msg.sender].length;
        require(values.length == length);
        require(fakes.length == length);
        require(secrets.length == length);

        uint refund;
        for (uint i = 0; i < length; i++) {
            Bid storage bidToCheck = bids[msg.sender][i];
            (uint value, bool fake, bytes32 secret) =
                    (values[i], fakes[i], secrets[i]);
            if (bidToCheck.blindedBid != keccak256(abi.encodePacked(value, fake, secret))) {
                // 出价未能正确披露。
                // 不返还订金。
                continue;
            }
            refund += bidToCheck.deposit;
            if (!fake && bidToCheck.deposit >= value) {
                if (placeBid(msg.sender, value))
                    refund -= value;
            }
            // 使发送者不可能再次认领同一笔订金。
            bidToCheck.blindedBid = bytes32(0);
        }
        payable(msg.sender).transfer(refund);
    }

    /// 撤回出价过高的竞标。
    function withdraw() external {
        uint amount = pendingReturns[msg.sender];
        if (amount > 0) {
            // 这里很重要，首先要设零值。
            // 因为，作为接收调用的一部分，
            // 接收者可以在 `transfer` 返回之前重新调用该函数。
            //（可查看上面关于 条件 -> 影响 -> 交互 的标注）
            pendingReturns[msg.sender] = 0;

            payable(msg.sender).transfer(amount);
        }
    }

    /// 结束拍卖，并把最高的出价发送给受益人。
    function auctionEnd()
        external
        onlyAfter(revealEnd)
    {
        if (ended) revert AuctionEndAlreadyCalled();
        emit AuctionEnded(highestBidder, highestBid);
        ended = true;
        beneficiary.transfer(highestBid);
    }

    // 这是一个 "internal" 函数，
    // 意味着它只能在本合约（或继承合约）内被调用。
    function placeBid(address bidder, uint value) internal
            returns (bool success)
    {
        if (value <= highestBid) {
            return false;
        }
        if (highestBidder != address(0)) {
            // 返还之前的最高出价
            pendingReturns[highestBidder] += highestBid;
        }
        highestBid = value;
        highestBidder = bidder;
        return true;
    }
}
```

/// Reveal your blinded bids. You will get a refund for all
/// correctly blinded invalid bids and for all bids except for
/// the totally highest.

疑问：reveal函数中，对于所有正确披露的无效出价以及除最高出价以外的所有出价，您都将获得退款。这里如果发送者有'多次'出现最高价，退款应该会把上一次的最高价一起退回去，但是这里好像只退了差额？

是否应该改成：

```solidity
    /// Reveal your blinded bids. You will get a refund for all
    /// correctly blinded invalid bids and for all bids except for
    /// the totally highest.
    function reveal(
        uint[] calldata values,
        bool[] calldata fakes,
        bytes32[] calldata secrets
    )
        external
        onlyAfter(biddingEnd)
        onlyBefore(revealEnd)
    {
        uint length = bids[msg.sender].length;
        require(values.length == length);
        require(fakes.length == length);
        require(secrets.length == length);

        uint refund;
        uint highestBid; 
        for (uint i = 0; i < length; i++) {
            Bid storage bidToCheck = bids[msg.sender][i];
            (uint value, bool fake, bytes32 secret) =
                    (values[i], fakes[i], secrets[i]);
            if (bidToCheck.blindedBid != keccak256(abi.encodePacked(value, fake, secret))) {
                // Bid was not actually revealed.
                // Do not refund deposit.
                continue;
            }
            refund += bidToCheck.deposit;
            if (!fake && bidToCheck.deposit >= value) {
                if (placeBid(msg.sender, value)) {
                    refund -= value;
                    // Make up refund deposit for the last highestBid.
                    refund += highestBid;
                    // reset current highestBid.
                    highestBid = value;
                }
            }
            // Make it impossible for the sender to re-claim
            // the same deposit.
            bidToCheck.blindedBid = bytes32(0);
        }
        payable(msg.sender).transfer(refund);
    }
```

这里为什么要这样改的原因是：这里没办法多次调用withdraw，因为reveal阶段一次性发送了多个竞标价，如果不做上述修改，则最终成功竞标的人会多出一部分竞标费（假设提了2个竞标价，都是'最高价'）

## 安全的远程购买

目前，远程购买商品需要多方相互信任。最简单的关系涉及一个卖家和一个买家。 买方希望从卖方那里收到一件物品，卖方希望得到金钱（或等价物）作为回报。 这里面有问题的部分是的运输。没有办法确定物品是否到达买方手中。

有多种方法来解决这个问题，但都有这样或那样的不足之处。 在下面的例子中，双方都要把两倍价值于物品的资金放入合约中作为托管。 只要发生这种情况，钱就会一直锁在合同里面，直到买方确认收到物品。 之后，买方会得到退回的资金（他们押金的一半），卖方得到三倍的资金（他们的押金加上物品的价值）。 这背后的想法是，双方都有动力去解决这个问题，否则他们的钱就会被永远锁定。

这个合约当然不能解决问题，但它概述了如何在合约内使用类似状态机的构造。

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;
contract Purchase {
    uint public value;
    address payable public seller;
    address payable public buyer;

    enum State { Created, Locked, Release, Inactive }
    // 状态变量的默认值是第一个成员，`State.created`。
    State public state;

    modifier condition(bool condition_) {
        require(condition_);
        _;
    }

    /// 只有买方可以调用这个函数。
    error OnlyBuyer();
    /// 只有卖方可以调用这个函数。
    error OnlySeller();
    /// 在当前状态下不能调用该函数。
    error InvalidState();
    /// 提供的值必须是偶数。
    error ValueNotEven();

    modifier onlyBuyer() {
        if (msg.sender != buyer)
            revert OnlyBuyer();
        _;
    }

    modifier onlySeller() {
        if (msg.sender != seller)
            revert OnlySeller();
        _;
    }

    modifier inState(State state_) {
        if (state != state_)
            revert InvalidState();
        _;
    }

    event Aborted();
    event PurchaseConfirmed();
    event ItemReceived();
    event SellerRefunded();

    // 确保 `msg.value` 是一个偶数。
    // 如果是奇数，除法会截断。
    // 通过乘法检查它不是一个奇数。
    constructor() payable {
        seller = payable(msg.sender);
        value = msg.value / 2;
        if ((2 * value) != msg.value)
            revert ValueNotEven();
    }

    /// 终止购买并收回 ether。
    /// 只能由卖方在合同锁定前能调用。
    function abort()
        external
        onlySeller
        inState(State.Created)
    {
        emit Aborted();
        state = State.Inactive;
        // 我们在这里直接使用 `transfer`。
        // 它可以安全地重入。
        // 因为它是这个函数中的最后一次调用，
        // 而且我们已经改变了状态。
        seller.transfer(address(this).balance);
    }

    /// 买方确认购买。
    /// 交易必须包括 `2 * value` ether。
    /// Ether 将被锁住，直到调用 confirmReceived。
    function confirmPurchase()
        external
        inState(State.Created)
        condition(msg.value == (2 * value))
        payable
    {
        emit PurchaseConfirmed();
        buyer = payable(msg.sender);
        state = State.Locked;
    }

    /// 确认您（买方）已经收到了该物品。
    /// 这将释放锁定的 ether。
    function confirmReceived()
        external
        onlyBuyer
        inState(State.Locked)
    {
        emit ItemReceived();
        // 首先改变状态是很重要的，否则的话，
        // 下面使用 `send` 调用的合约可以在这里再次调用。
        state = State.Release;

        buyer.transfer(value);
    }

    /// 该功能为卖家退款，
    /// 即退还卖家锁定的资金。
    function refundSeller()
        external
        onlySeller
        inState(State.Release)
    {
        emit SellerRefunded();
        // 首先改变状态是很重要的，否则的话，
        // 下面使用 `send` 调用的合约可以在这里再次调用。
        state = State.Inactive;

        seller.transfer(3 * value);
    }
}
```

有关键字 `payable` 是函数能够接收以太币的必要条件：confirmPurchase(买方)、constructor（卖方）

enum State { Created, Locked, Release, Inactive }

Created（购买前）=> Locked（购买付款，confirmPurchase，买方给出2倍商品价）=> Release（购买确认，confirmReceived，退还商品价给买方）=> Inactive(购买后，refundSeller，退还3倍商品价给卖方)

## 微支付通道

