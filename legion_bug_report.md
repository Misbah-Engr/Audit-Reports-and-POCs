## Incorrect Referrer Fee Transfer in supplyTokens Function

Closed as duplicate

Labels: 4 (Critical)

Lines of code
https://github.com/Legion-Team/legion-protocol-contracts/blob/master/src/LegionSale.sol#L353

## Vulnerability details/Description

In LegionSale, which is an abstract contract that LegionPreLiquidSaleV2 inherits from, supplyTokens function incorrectly transfers the Legion fee amount to the referrer fee receiver instead of the intended referrer fee amount.

```solidity
    function supplyTokens(
        uint256 amount,
        uint256 legionFee,
        uint256 referrerFee
    )
        external
        virtual
        onlyProject
        askTokenAvailable
        whenNotPaused
    {
        // Verify that tokens can be supplied for distribution
        _verifyCanSupplyTokens(amount);

        // Verify that the sale is not canceled
        _verifySaleNotCanceled();

        // Verify that tokens have not been supplied
        _verifyTokensNotSupplied();

        // Flag that tokens have been supplied
        saleStatus.tokensSupplied = true;

        // Calculate and verify Legion Fee
        if (legionFee != (saleConfig.legionFeeOnTokensSoldBps * amount) / 10_000) revert Errors.InvalidFeeAmount();

        // Calculate and verify Legion Fee
        if (referrerFee != (saleConfig.referrerFeeOnTokensSoldBps * amount) / 10_000) revert Errors.InvalidFeeAmount();

        // Emit TokensSuppliedForDistribution
        emit TokensSuppliedForDistribution(amount, legionFee, referrerFee);

        // Transfer the allocated amount of tokens for distribution
        SafeTransferLib.safeTransferFrom(addressConfig.askToken, msg.sender, address(this), amount);

        // Transfer the Legion fee to the Legion fee receiver address
        if (legionFee != 0) {
            SafeTransferLib.safeTransferFrom(
                addressConfig.askToken, msg.sender, addressConfig.legionFeeReceiver, legionFee
            );
        }

        // Transfer the Referrer fee to the referrer fee receiver address
        if (referrerFee != 0) {
            SafeTransferLib.safeTransferFrom(
         -->     addressConfig.askToken, msg.sender, addressConfig.referrerFeeReceiver, legionFee 
            );
        }
    }
```

This bug results in incorrect fee distribution, causing the referrer to receive more tokens than intended and potentially disrupting the protocol's fee structure.

## Impact
Referrers receive the Legion fee amount instead of their correct referrer fee amount
Protocol's fee distribution mechanism is compromised
Financial impact on both the protocol and project token distribution

## Proof of Concept
Inside LegionPreLiquidSaleV2Test.t.sol, add this at the end.

```solidity
    function test_supplyTokens_demonstratesReferrerFeeTransferBug() public {
        // Arrange
        prepareCreateLegionPreLiquidSale();
        prepareMintAndApproveProjectTokens();

        vm.prank(projectAdmin);
        ILegionPreLiquidSaleV2(legionSaleInstance).endSale();

        vm.warp(refundEndTime() + 1);

        vm.prank(legionBouncer);
        ILegionPreLiquidSaleV2(legionSaleInstance).publishSaleResults(
            claimTokensMerkleRoot, 4000 * 1e18, address(askToken), 0
        );

        // Record initial balances
        uint256 initialLegionFeeReceiverBalance = MockToken(askToken).balanceOf(legionFeeReceiver);
        uint256 initialReferrerFeeReceiverBalance = MockToken(askToken).balanceOf(testConfig.saleInitParams.referrerFeeReceiver);

        // Act
        vm.prank(projectAdmin);
        ILegionPreLiquidSaleV2(legionSaleInstance).supplyTokens(4000 * 1e18, 100 * 1e18, 40 * 1e18);

        // Assert
        uint256 finalLegionFeeReceiverBalance = MockToken(askToken).balanceOf(legionFeeReceiver);
        uint256 finalReferrerFeeReceiverBalance = MockToken(askToken).balanceOf(testConfig.saleInitParams.referrerFeeReceiver);

        // Legion fee receiver should receive 100 tokens (correct)
        assertEq(finalLegionFeeReceiverBalance - initialLegionFeeReceiverBalance, 100 * 1e18);
        
        // Referrer fee receiver should receive 40 tokens but actually receives 100 tokens (bug)
        assertEq(finalReferrerFeeReceiverBalance - initialReferrerFeeReceiverBalance, 100 * 1e18);
        // This assertion will fail because the referrer is receiving the legion fee amount (100 tokens) 
        // instead of the referrer fee amount (40 tokens)
        //assertEq(finalReferrerFeeReceiverBalance - initialReferrerFeeReceiverBalance, 40 * 1e18);
    }

## Result:

```bash
...

    ├─ [100622] 0xCB6f5076b5bbae81D7643BfBf57897E8E3FB1db9::supplyTokens(4000000000000000000000 [4e21], 100000000000000000000 [1e20], 40000000000000000000 [4e19])
    │   ├─ [100445] LegionPreLiquidSaleV2::supplyTokens(4000000000000000000000 [4e21], 100000000000000000000 [1e20], 40000000000000000000 [4e19]) [delegatecall]
    │   │   ├─ emit TokensSuppliedForDistribution(amount: 4000000000000000000000 [4e21], legionFee: 100000000000000000000 [1e20], referrerFee: 40000000000000000000 [4e19])
    │   │   ├─ [25875] MockToken::transferFrom(SHA-256: [0x0000000000000000000000000000000000000002], 0xCB6f5076b5bbae81D7643BfBf57897E8E3FB1db9, 4000000000000000000000 [4e21])
    │   │   │   ├─ emit Transfer(from: SHA-256: [0x0000000000000000000000000000000000000002], to: 0xCB6f5076b5bbae81D7643BfBf57897E8E3FB1db9, amount: 4000000000000000000000 [4e21])
    │   │   │   └─ ← [Return] true
    │   │   ├─ [23875] MockToken::transferFrom(SHA-256: [0x0000000000000000000000000000000000000002], 0x0000000000000000000000000000000000000010, 100000000000000000000 [1e20])
    │   │   │   ├─ emit Transfer(from: SHA-256: [0x0000000000000000000000000000000000000002], to: 0x0000000000000000000000000000000000000010, amount: 100000000000000000000 [1e20])
    │   │   │   └─ ← [Return] true
    │   │   ├─ [23875] MockToken::transferFrom(SHA-256: [0x0000000000000000000000000000000000000002], ECPairing: [0x0000000000000000000000000000000000000008], 100000000000000000000 [1e20])
    │   │   │   ├─ emit Transfer(from: SHA-256: [0x0000000000000000000000000000000000000002], to: ECPairing: [0x0000000000000000000000000000000000000008], amount: 100000000000000000000 [1e20])
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Stop]
    │   └─ ← [Return]
    ├─ [842] MockToken::balanceOf(0x0000000000000000000000000000000000000010) [staticcall]
    │   └─ ← [Return] 100000000000000000000 [1e20]
    ├─ [842] MockToken::balanceOf(ECPairing: [0x0000000000000000000000000000000000000008]) [staticcall]
    │   └─ ← [Return] 100000000000000000000 [1e20]
    ├─ [0] VM::assertEq(100000000000000000000 [1e20], 100000000000000000000 [1e20]) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(100000000000000000000 [1e20], 100000000000000000000 [1e20]) [staticcall]
    │   └─ ← [Return]
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 3.07ms (564.06µs CPU time)
```

And if you uncomment the last line

```bash
...

    │   ├─ [100445] LegionPreLiquidSaleV2::supplyTokens(4000000000000000000000 [4e21], 100000000000000000000 [1e20], 40000000000000000000 [4e19]) [delegatecall]
    │   │   ├─ emit TokensSuppliedForDistribution(amount: 4000000000000000000000 [4e21], legionFee: 100000000000000000000 [1e20], referrerFee: 40000000000000000000 [4e19])
    │   │   ├─ [25875] MockToken::transferFrom(SHA-256: [0x0000000000000000000000000000000000000002], 0xCB6f5076b5bbae81D7643BfBf57897E8E3FB1db9, 4000000000000000000000 [4e21])
    │   │   │   ├─ emit Transfer(from: SHA-256: [0x0000000000000000000000000000000000000002], to: 0xCB6f5076b5bbae81D7643BfBf57897E8E3FB1db9, amount: 4000000000000000000000 [4e21])
    │   │   │   └─ ← [Return] true
    │   │   ├─ [23875] MockToken::transferFrom(SHA-256: [0x0000000000000000000000000000000000000002], 0x0000000000000000000000000000000000000010, 100000000000000000000 [1e20])
    │   │   │   ├─ emit Transfer(from: SHA-256: [0x0000000000000000000000000000000000000002], to: 0x0000000000000000000000000000000000000010, amount: 100000000000000000000 [1e20])
    │   │   │   └─ ← [Return] true
    │   │   ├─ [23875] MockToken::transferFrom(SHA-256: [0x0000000000000000000000000000000000000002], ECPairing: [0x0000000000000000000000000000000000000008], 100000000000000000000 [1e20])
    │   │   │   ├─ emit Transfer(from: SHA-256: [0x0000000000000000000000000000000000000002], to: ECPairing: [0x0000000000000000000000000000000000000008], amount: 100000000000000000000 [1e20])
    │   │   │   └─ ← [Return] true
    │   │   └─ ← [Stop]
    │   └─ ← [Return]
    ├─ [842] MockToken::balanceOf(0x0000000000000000000000000000000000000010) [staticcall]
    │   └─ ← [Return] 100000000000000000000 [1e20]
    ├─ [842] MockToken::balanceOf(ECPairing: [0x0000000000000000000000000000000000000008]) [staticcall]
    │   └─ ← [Return] 100000000000000000000 [1e20]
    ├─ [0] VM::assertEq(100000000000000000000 [1e20], 100000000000000000000 [1e20]) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(100000000000000000000 [1e20], 100000000000000000000 [1e20]) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::assertEq(100000000000000000000 [1e20], 40000000000000000000 [4e19]) [staticcall]
    │   └─ ← [Revert] assertion failed: 100000000000000000000 != 40000000000000000000
    └─ ← [Revert] assertion failed: 100000000000000000000 != 40000000000000000000

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 3.17ms (608.94µs CPU time)

Ran 1 test suite in 12.27ms (3.17ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/LegionPreLiquidSaleV2Test.t.sol:LegionPreLiquidSaleV2Test
[FAIL: assertion failed: 100000000000000000000 != 40000000000000000000] test_supplyTokens_demonstratesReferrerFeeTransferBug() (gas: 1311526)
```


4 (Critical)
 2 weeks ago
0xHustling commented 2 weeks ago
@0xHustling
0xHustling
2 weeks ago
Member
Duplicate of #13




sentinelxyz
closed this as completed 2 weeks ago

