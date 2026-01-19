## Altar User Cap Bypass

Target: https://github.com/hackenproof-public/reliq-protocol 

## Summary
In line 18, the dev commented that,

```solidity
// Contributions are capped per user and globally.
```

The Altar.sacrifice function only checks if a single contribution amount is within [minContribution, maxContribution]. It does not enforce a cumulative per-user cap, allowing users to bypass the intended maximum contribution by making multiple smaller transactions.

## Vulnerability Details
The sacrifice function checks amount >= minContribution && amount <= maxContribution but does not check if userContributions[user] + amount <= maxContribution.

### Problematic Code (src/Altar.sol)
```solidity
function sacrifice(uint256 amount, address user) external nonReentrant {
    require(block.timestamp < deadline, "Altar: deadline passed");
    require(
        amount >= minContribution && amount <= maxContribution,
        "Altar: invalid amount"
    );
    require(
        totalContributions + amount <= depositCap,
        "Altar: deposit cap exceeded"
    );

    // ...
    userContributions[user] += amount;
    // ...
}
```

The check on line 107 only validates the current amount, not the cumulative total.

## Impact
Unfair Advantage: Whales can acquire a disproportionately large share of the offering by making multiple max-contribution transactions, circumventing fair distribution limits.
Undermines Fairness: The per-user cap is a common mechanism for fair launches; this bypass defeats its purpose.

## Recommended Mitigation
Add a cumulative check:

```solidity
function sacrifice(uint256 amount, address user) external nonReentrant {
    require(block.timestamp < deadline, "Altar: deadline passed");
    require(
        amount >= minContribution && amount <= maxContribution,
        "Altar: invalid amount"
    );
+   require(
+       userContributions[user] + amount <= maxContribution,
+       "Altar: max contribution exceeded"
+   );
    require(
        totalContributions + amount <= depositCap,
        "Altar: deposit cap exceeded"
    );
    // ...
}
```

## Validation steps

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/Altar.sol";
import "../src/ReliqHYPE.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockBackingCapBypass is ERC20 {
    constructor() ERC20("Mock Backing Token", "MBK") {}
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract AltarUserCapBypassTest is Test {
    Altar altar;
    ReliqHYPE reliq;
    MockBackingCapBypass backing;

    address owner = address(this);
    address whale = address(0x99);

    function setUp() public {
        backing = new MockBackingCapBypass();
        reliq = new ReliqHYPE(IERC20(address(backing)));
        altar = new Altar(address(reliq), address(backing));

        // Start ReliqHYPE
        backing.mint(owner, 1000 ether);
        backing.approve(address(reliq), 1000 ether);
        reliq.setTreasuryAddress(address(0x123));
        reliq.setStart(1000 ether, 0 ether);

        // Raise Cap for Altar use
        reliq.setMaxMintable(100000 ether);

        // Kickoff Altar
        // Min: 1 ether
        // Max (User): 10 ether (NatSpec says "Contributions are capped per user")
        // Global Cap: 100 ether
        uint256 deadline = block.timestamp + 1 days;
        altar.kickOff(deadline, 1 ether, 10 ether, 100 ether);
    }

    function testUserCapBypass() public {
        // Whale wants to take more than the 10 ether per user cap.
        uint256 whaleFunds = 50 ether;
        backing.mint(whale, whaleFunds);

        vm.startPrank(whale);
        backing.approve(address(altar), whaleFunds);

        // 1. Contribute max amount (10 ether) - Should succeed
        altar.sacrifice(10 ether, whale);
        assertEq(altar.userContributions(whale), 10 ether);

        // 2. Contribute AGAIN (10 ether) - Should REVERT if cap is enforced per user cumulatively
        // However, the implementation only checks `amount <= maxContribution` (per tx).
        altar.sacrifice(10 ether, whale);
        
        // 3. User has successfully contributed 20 ether, bypassing the 10 ether cap.
        assertEq(altar.userContributions(whale), 20 ether);
        
        console.log("Bug Confirmed: User contributed %s (Cap was 10)", altar.userContributions(whale));
        
        vm.stopPrank();
    }
}
```