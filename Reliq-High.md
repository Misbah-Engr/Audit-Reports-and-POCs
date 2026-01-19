## Loan Tenure Erasure in borrowMore

Target: https://github.com/hackenproof-public/reliq-protocol 

## Summary
The reliqHYPE protocol fails to preserve the historical duration ("tenure") of a loan when a user interacts with borrowMore. The numberOfDays field in the Loan struct, which tracks the cumulative duration of the loan, is incorrectly reset to the remaining time until maturity instead of maintaining the total time the position has been open. This leads to a loss of historical data, where long-standing loans appear as if they were just opened with the remaining duration.

## Vulnerability Details
In ReliqHYPE.sol, the Loan struct contains a numberOfDays field intentionally updated in extendLoan to track the total duration:

```solidity
// ReliqHYPE.sol:606
Loans[msg.sender].numberOfDays = _loanTenure + numberOfDays;
However, the borrowMore function calculates the remaining time to maturity (newBorrowTenure) and indiscriminately overwrites the numberOfDays field with this value:
ReliqHYPE.sol:374
uint256 newBorrowTenure = (endDate - nextMidnight) / 1 days;
// ...
// ReliqHYPE.sol:405

numberOfDays: newBorrowTenure
```

This overwriting behavior discards the previous accumulated tenure. For example, if a user opens a 300-day loan, waits 200 days, and then calls borrowMore, the numberOfDays is reset to 100. If they subsequently extend the loan by 200 days, the recorded tenure becomes 300 (100 + 200) instead of the actual 500 (300 original + 200 extension).

## Impact
While this issue does not appear to directly compromise the solvency or interest calculations of the core lending logic (as extendLoan logic relies on block.timestamp and absolute dates), it corrupts the state data representing the loan's history.

- Misleading Data: Indexers, UIs, and analytics platforms relying on UserLoanBookUpdate events or on-chain getters will report incorrect loan durations.
- Broken Loyalty/Tenure Logic: Any future governance or rewards system that attempts to incentivize long-term holders based on the numberOfDays field will fail, as active users who borrow more will have their "loyalty score" reset.
- Auditing Difficulty: It becomes difficult to verify the true history of a loan position on-chain without reconstructing it entirely from events.


## Recommended Mitigation
Modify borrowMore to preserve the existing numberOfDays value instead of overwriting it with the remaining tenure. The numberOfDays should either remain unchanged (since the maturity date hasn't moved) or be carefully managed if it is intended to represent something else.

If numberOfDays is strictly for "Original Duration + Extensions", then borrowMore should copy the existing value:

```solidity
Loans[msg.sender] = Loan({
      collateral: netUserCollateral,
      borrowed: netUserBorrow,
      endDate: endDate,
-     numberOfDays: newBorrowTenure
+     numberOfDays: Loans[msg.sender].numberOfDays
  });
```

## Validation steps

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/ReliqHYPE.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "../src/InterestManager.sol";

contract MockBacking is ERC20 {
    constructor() ERC20("Mock Backing", "MBK") {}
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract SelfContainedHistoryErasure is Test {
    ReliqHYPE reliq;
    MockBacking backing;
    InterestManager interestManager;
    address owner = address(this);
    address user = address(0x1);
    address treasury = address(0x2);

    function setUp() public {
        backing = new MockBacking();
        reliq = new ReliqHYPE(IERC20(address(backing)));
        interestManager = new InterestManager(500); // 5% default rate

        reliq.setTreasuryAddress(treasury);
        reliq.setInterestManager(address(interestManager));
    }

    function testHistoryErasure() public {
        // setup market
        uint256 startAmount = 1000 ether;
        backing.mint(owner, startAmount);
        backing.approve(address(reliq), startAmount);
        reliq.setStart(startAmount, startAmount);
        reliq.setMaxMintable(startAmount + 10000 ether);

        // fund user
        backing.mint(user, 10000 ether);
        vm.startPrank(user);
        backing.approve(address(reliq), type(uint256).max);

        // buy collateral
        reliq.buy(user, 1000 ether);

        // open loan for 300 days
        // tenure counter = 300
        reliq.borrow(100 ether, 300);

        (, , , uint256 daysOne) = reliq.Loans(user);
        assertEq(daysOne, 300);

        // warp 200 days forward
        // remaining real time: 100 days
        vm.warp(block.timestamp + 200 days);

        // borrow more (triggers reset)
        reliq.borrowMore(10 ether);

        // check counter
        // expected: should ideally countain 300? or at least not 100
        // actual: 100 (remaining time)
        (, , , uint256 daysTwo) = reliq.Loans(user);
        console.log("tenure counter after borrowmore:", daysTwo);

        assertEq(
            daysTwo,
            100,
            "History Erased: Counter reset to remaining time"
        );

        // extend loan for 200 days
        // new end date = now + 100 (rem) + 200 (ext) = +300 days
        // total actual tenure = 200 (past) + 300 (future) = 500 days
        reliq.extendLoan(200);

        (, , , uint256 daysThree) = reliq.Loans(user);

        // counter says 100 + 200 = 300
        // 300 < 365
        // so even if we enforce strict checking on this counter, it passes
        console.log("tenure counter after extension:", daysThree);
        assertEq(daysThree, 300);

        vm.stopPrank();
    }
}
```

status: paid

