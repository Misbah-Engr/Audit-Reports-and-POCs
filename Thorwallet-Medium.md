### F-7/S-243 - Code4rena
## Permanent Bridged Token Holder Status has unintended issue

Medium

### Finding description and impact
The Titn contract marks recipients of bridged tokens as isBridgedTokenHolder in the _credit function, but this status is never reset, even when their token balance drops to zero. This deviates from LayerZero's design, which does not impose persistent restrictions based on token origin. Even if we take as an intentional design choice, it should be reset after the user token balance returns to zero, it has a problem when the user no longer holds bridge tokens.

```solidity
if (!isBridgedTokenHolder[_to]) {
    isBridgedTokenHolder[_to] = true;
}
```


Addresses remain restricted indefinitely by _validateTransfer even after transferring all bridged tokens away.
It also Reduces token flexibility and usability, as users face ongoing transfer limitations regardless of current holdings.

### Proof of Concept

- Deploy Titn on Chain A and Chain B, with isBridgedTokensTransferLocked = true.

- User sends 100 tokens from Chain A to Chain B via cross-chain transfer.

- _credit mints 100 tokens on Chain B, sets isBridgedTokenHolder[user] = true (Line 77).

- User transfers all 100 tokens to another address, reducing balance to 0.

- User receives 50 new tokens (non-bridged) on Chain B via a local transfer.

- User attempts to transfer these 50 tokens, but _validateTransfer (Line 62) reverts due to persistent isBridgedTokenHolder[user] = true.

### Recommended mitigation steps

Adjust Bridged Status Dynamically

```solidity
function _afterTokenTransfer(address from, address to, uint256 amount) internal virtual override {
    if (balanceOf(from) == 0) {
        isBridgedTokenHolder[from] = false;
    }
    if (!isBridgedTokenHolder[to]) {
        isBridgedTokenHolder[to] = true; // Set only on receipt
    }
}
```

Override _afterTokenTransfer to reset isBridgedTokenHolder when an address’s balance reaches zero, ensuring restrictions apply only to active holders of bridged tokens. Test to confirm proper behavior across chains.

### Links to affected code
contracts%2FTitn.sol#L106-L108

Comments on duplicate submission: 2

Improper Transfer Restrictions on Non-Bridged Tokens Due to Boolean Bridged Token Tracking, Allowing a DoS Attack Vector
Judge Comments
1
0xnev
Mar 7
> Valid, I believe medium is appropriate based on C4 medium severity guidelines, given no assets are compromisedlost. 2 — Med Assets not at direct risk, but the function of the protocol or its availability could be impacted, or leak value with a hypothetical attack path with stated assumptions, but external requirements. This only impacts the following invariant on Base. Non-bridged TITN Tokens Holders can transfer their TITN tokens freely to any address as long as the tokens have not been bridged from ARBITRUM. If usage of tokens are desired for defi protocols, the tokens can still be bridged via transfers to the LZ endpoint
S-98

Any Contract or User's Tokens Can Be Locked on Base Chain

Validator's comment during triage
0
Viraz
Feb 28
