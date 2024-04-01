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

在这一节中，我们将学习如何建立一个支付通道的实施实例。 它使用加密签名，使以太币在同一当事人之间的重复转移变得安全、即时，并且没有交易费用。 对于这个例子，我们需要了解如何签名和验证签名，并设置支付通道。

### 创建和验证签名

1、创建和验证签名

想象一下，Alice想发送一些以太给Bob， 即Alice是发送方，Bob是接收方。

Alice 只需要在链下发送经过加密签名的信息 (例如通过电子邮件)给Bob，它类似于写支票。

Alice和Bob使用签名来授权交易，这在以太坊的智能合约中是可以实现的。 Alice将建立一个简单的智能合约，让她传输以太币，但她不会自己调用一个函数来启动付款， 而是让Bob来做，从而支付交易费用。

该合约将按以下方式运作：

* Alice部署了 ReceiverPays 合约，附加了足够的以太币来支付将要进行的付款。
* Alice通过用她的私钥签署一个消息来授权付款。
* Alice将经过加密签名的信息发送给Bob。该信息不需要保密（后面会解释），而且发送机制也不重要。
* Bob通过向智能合约发送签名的信息来索取他的付款，合约验证了信息的真实性，然后释放资金。

2、创建签名

Alice不需要与以太坊网络交互来签署交易，这个过程是完全离线的。 在本教程中，我们将使用 web3.js 和 MetaMask 在浏览器中签署信息。 使用 EIP-712 中描述的方法， 因为它提供了许多其他安全优势。

/// 先进行哈希运算使事情变得更容易
var hash = web3.utils.sha3("message to sign");
web3.eth.personal.sign(hash, web3.eth.defaultAccount, function () { console.log("Signed"); });
备注

web3.eth.personal.sign 把信息的长度加到签名数据中。 由于我们先进行哈希运算，消息的长度总是正好是32字节， 因此这个长度前缀总是相同的。

3、签署内容

对于履行付款的合同，签署的信息必须包括：

收件人的钱包地址。

要转移的金额。

重放攻击的保护。

重放攻击是指一个已签署的信息被重复使用，以获得对第二次交易的授权。 为了避免重放攻击，我们使用与以太坊交易本身相同的技术， 即所谓的nonce，它是一个账户发送的交易数量。 智能合约会检查一个nonce是否被多次使用。

另一种类型的重放攻击可能发生在所有者部署 ReceiverPays 合约时， 先进行了一些支付，然后销毁该合约。后来， 他们决定再次部署 RecipientPays 合约， 但新的合约不知道以前合约中使用的nonces，所以攻击者可以再次使用旧的信息。

Alice可以通过在消息中包含合约的地址来防止这种攻击， 并且只有包含合约地址本身的消息才会被接受。 您可以在本节末尾的完整合约的 claimPayment() 函数的前两行找到这个例子。

4、组装参数

既然我们已经确定了要在签名信息中包含哪些信息， 我们准备把信息放在一起，进行哈希运算，然后签名。 简单起见，我们把数据连接起来。 ethereumjs-abi 库提供了一个名为 soliditySHA3 的函数， 模仿Solidity的 keccak256 函数应用于使用 abi.encodePacked 编码的参数的行为。 这里有一个JavaScript函数，为 ReceiverPays 的例子创建了适当的签名。

```js
// recipient， 是应该被支付的地址。
// amount，单位是 wei, 指定应该发送多少ether。
// nonce， 可以是任何唯一的数字，以防止重放攻击。
// contractAddress， 用于防止跨合约的重放攻击。
function signPayment(recipient, amount, nonce, contractAddress, callback) {
    var hash = "0x" + abi.soliditySHA3(
        ["address", "uint256", "uint256", "address"],
        [recipient, amount, nonce, contractAddress]
    ).toString("hex");

    web3.eth.personal.sign(hash, web3.eth.defaultAccount, callback);
}
```

在Solidity中恢复信息签名者
一般来说，ECDSA的签名由两个参数组成， r 和 s。 以太坊的签名包括第三个参数 v ，您可以用它来验证是哪个账户的私钥被用来签署信息， 以及作为交易的发送者。Solidity 提供了一个内置函数 ecrecover， 它接受一个消息以及 r, s 和 v 参数，然后返回用于签署该消息的地址。

提取签名参数
web3.js 产生的签名是 r, s 和 v 的拼接的， 所以第一步是把这些参数分开。您可以在客户端这样做， 但在智能合约内这样做意味着你只需要发送一个签名参数而不是三个。 将一个字节数组分割成它的组成部分是很麻烦的， 所以我们在 splitSignature 函数中使用 inline assembly 完成这项工作（本节末尾的完整合约中的第三个函数）。

计算信息哈希值
智能合约需要确切地知道哪些参数用于签名， 因此它必须通过参数重新创建消息，并使用该消息进行签名验证。 在 claimPayment 函数中，函数 prefixed 和 recoverSigner 做了这件事。

完整的合约：

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
// 这将报告一个由于废弃的 selfdestruct 而产生的警告
contract ReceiverPays {
    address owner = msg.sender;

    mapping(uint256 => bool) usedNonces;

    constructor() payable {}

    function claimPayment(uint256 amount, uint256 nonce, bytes memory signature) external {
        require(!usedNonces[nonce]);
        usedNonces[nonce] = true;

        // 这将重新创建在客户端上签名的信息。
        bytes32 message = prefixed(keccak256(abi.encodePacked(msg.sender, amount, nonce, this)));

        require(recoverSigner(message, signature) == owner);

        payable(msg.sender).transfer(amount);
    }

    /// 销毁合约并收回剩余的资金。
    function shutdown() external {
        require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }

    /// 签名方法。
    function splitSignature(bytes memory sig)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(sig.length == 65);

        assembly {
            // 前32个字节，在长度前缀之后。
            r := mload(add(sig, 32))
            // 第二个32字节。
            s := mload(add(sig, 64))
            // 最后一个字节（下一个32字节的第一个字节）。
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function recoverSigner(bytes32 message, bytes memory sig)
        internal
        pure
        returns (address)
    {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);

        return ecrecover(message, v, r, s);
    }

    /// 构建一个前缀哈希值，以模仿 eth_sign 的行为。
    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
```

### 编写一个简单的支付通道合约

Alice现在建立了一个简单但完整的支付通道的实现。 支付通道使用加密签名来安全、即时地重复转移以太币， 并且没有交易费用。

什么是支付通道？
支付通道允许参与者在不使用交易的情况下重复转移以太币。 这意味着，你可以避免与交易相关的延迟和费用。 我们将探讨两方（Alice和Bob）之间一个简单的单向支付通道。它涉及三个步骤：

Alice用以太币为智能合约提供资金。这就 "打开" 了支付通道。

Alice签署信息，说明欠接收者多少以太币。这个步骤对每一笔付款都要重复进行。

Bob "关闭" 支付通道，取出他的那部分以太币，并将剩余部分发回给发送方。

备注：只有步骤1和3需要以太坊交易，意味着步骤2中发送方可以通过链下方法（如电子邮件） 向接收方发送加密签名的信息。这意味着只需要两个交易就可以支持任何数量的转移。

Bob保证会收到他的资金，因为智能合约托管了以太币， 并兑现了一个有效的签名信息。智能合约也强制执行超时， 所以即使接收者拒绝关闭通道，Alice也能保证最终收回她的资金。 由支付通道的参与者决定保持通道的开放时间。对于一个短暂的交易， 如向网吧支付每分钟的网络访问费，支付通道可以保持有限的开放时间。 另一方面，对于经常性的支付，如向雇员支付每小时的工资， 支付渠道可能会保持开放几个月或几年。

开通支付渠道
为了开通支付通道，Alice部署了智能合约， 添加了要托管的以太币，并指定了预期接收者和通道存在的最长时间。 这就是本节末尾合同中的函数 SimplePaymentChannel。

进行支付
Alice通过向Bob发送签名信息进行支付。 这一步骤完全在以太坊网络之外进行。 消息由发送方加密签名，然后直接传送给接收方。

每条信息包括以下信息：

智能合约的地址，用于防止跨合约重放攻击。

到目前为止，欠接收方的以太币的总金额。

一个支付通道只关闭一次，就是在一系列转账结束后。 正因为如此，所发送的签名信息中只有一个能被赎回。 这就是为什么每条签名信息都指定了一个累计的以太币欠款总额， 而不是单个小额支付的金额。接收方自然会选择最新的签名信息来赎回， 因为那是总额最高的签名信息。每个签名信息的nonce不再需要了， 因为智能合约只兑现一个签名信息。 智能合约的地址仍然被用来防止一个支付渠道的签名信息被用于另一个渠道。

下面是经过修改的JavaScript代码，用于对上一节中的信息进行加密签名：

```js
function constructPaymentMessage(contractAddress, amount) {
    return abi.soliditySHA3(
        ["address", "uint256"],
        [contractAddress, amount]
    );
}

function signMessage(message, callback) {
    web3.eth.personal.sign(
        "0x" + message.toString("hex"),
        web3.eth.defaultAccount,
        callback
    );
}

// contractAddress， 是用来防止跨合同的重放攻击。
// amount，单位是wei，指定了应该发送多少以太。

function signPayment(contractAddress, amount, callback) {
    var message = constructPaymentMessage(contractAddress, amount);
    signMessage(message, callback);
}
```

关闭支付通道
当Bob准备好接收他的资金时， 是时候通过调用智能合约上的 close 函数关闭支付通道了。 关闭通道会向接收者支付欠他们的以太币，并销毁合约， 将任何剩余的以太币送回给Alice。 为了关闭通道，Bob需要提供一个由Alice签名的信息。

智能合约必须验证该消息是否包含发送者的有效签名。 进行这种验证的过程与接收者使用签名的过程相同。 Solidity函数 isValidSignature 和 recoverSigner 的工作方式 与上一节中的JavaScript对应函数一样，而后者的函数是从 ReceiverPays 合约中借用的。

只有支付通道的接收者可以调用 close 函数， 他们自然会传递最新的支付信息，因为该信息带有最高的欠款总额。 如果允许发送者调用这个函数，他们可以提供一个金额较低的签名消息， 骗取接收者的欠款。

该函数会验证签名的信息与给定的参数是否相符。 如果一切正常，接收者就会收到他们的那部分以太币， 而剩下的以太币将通过 selfdestruct 发送给发送者。 您可以在完整的合约中看到 close 函数。

通道到期
Bob可以在任何时候关闭支付通道，但如果他们没有这样做， Alice需要一个方法来收回她的托管资金。在合同部署的时候，设置了一个 到期时间。 一旦达到这个时间，Alice可以调用 claimTimeout 来收回她的资金。 您可以在完整的合约中看到 claimTimeout 函数。

在这个函数被调用后，Bob不能再接收任何以太。 所以Bob必须在过期前关闭通道，这一点很重要。

完整的合约

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
// 这将报告一个由于废弃的 selfdestruct 而产生的警告
contract SimplePaymentChannel {
    address payable public sender;      // 发送付款的账户。
    address payable public recipient;   // 接收付款的账户。
    uint256 public expiration;  // 超时时间，以防接收者永不关闭支付通道。

    constructor (address payable recipientAddress, uint256 duration)
        payable
    {
        sender = payable(msg.sender);
        recipient = recipientAddress;
        expiration = block.timestamp + duration;
    }

    /// 接收者可以在任何时候通过提供发送者签名的金额来关闭通道，
    /// 接收者将获得该金额，其余部分将返回发送者。
    function close(uint256 amount, bytes memory signature) external {
        require(msg.sender == recipient);
        require(isValidSignature(amount, signature));

        recipient.transfer(amount);
        selfdestruct(sender);
    }

    /// 发送者可以在任何时候延长到期时间。
    function extend(uint256 newExpiration) external {
        require(msg.sender == sender);
        require(newExpiration > expiration);

        expiration = newExpiration;
    }

    /// 如果达到超时时间而接收者没有关闭通道，
    /// 那么以太就会被释放回给发送者。
    function claimTimeout() external {
        require(block.timestamp >= expiration);
        selfdestruct(sender);
    }

    function isValidSignature(uint256 amount, bytes memory signature)
        internal
        view
        returns (bool)
    {
        bytes32 message = prefixed(keccak256(abi.encodePacked(this, amount)));

        // 检查签名是否来自付款方。
        return recoverSigner(message, signature) == sender;
    }

    /// 下面的所有功能是取自 '创建和验证签名' 的章节。

    function splitSignature(bytes memory sig)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        require(sig.length == 65);

        assembly {
            // 前32个字节，在长度前缀之后。
            r := mload(add(sig, 32))
            // 第二个32字节。
            s := mload(add(sig, 64))
            // 最后一个字节（下一个32字节的第一个字节）。
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function recoverSigner(bytes32 message, bytes memory sig)
        internal
        pure
        returns (address)
    {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);

        return ecrecover(message, v, r, s);
    }

    /// 构建一个前缀哈希值，以模仿eth_sign的行为。
    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
```

疑问：签名的具体算法暂不深究？