# PSBT Fields vs OP_RETURN: Brainstorming Analysis

**Date:** 2026-02-28  
**Author:** Nav (AI Assistant)  
**Context:** Introspector - Arkade VM data storage mechanisms

---

## Executive Summary

This document analyzes two approaches for storing Arkade VM data (scripts, asset packets, witness data):
1. **Custom PSBT Fields** (current implementation)
2. **OP_RETURN Outputs** (alternative approach)

Both methods have distinct tradeoffs in security, data availability, on-chain footprint, and implementation complexity.

---

## Current Implementation: PSBT Fields

The introspector currently uses custom PSBT unknown fields:
```go
var ArkadeScript        = []byte("arkadescript")
var ArkadeScriptWitness = []byte("arkadescriptwitness")
```

These are encoded as PSBT unknown fields with key type `0xFC` (proprietary).

### How It Works
1. Arkade script bytecode is stored in PSBT input's `Unknown` field with key `arkadescript`
2. Script witness data (arguments) stored with key `arkadescriptwitness`
3. Asset packets are passed separately to the engine via `SetAssetPacket()`
4. Data exists only in PSBT; once signed and broadcast, it's stripped

---

## Alternative: OP_RETURN Approach

Store Arkade data in transaction outputs using `OP_RETURN <data>`.

### Potential Formats
- **Single OP_RETURN:** `OP_RETURN <arkade_marker> <compressed_data>`
- **Multiple OP_RETURNs:** Split data across multiple outputs (non-standard but possible)
- **Hybrid:** Hash commitment in OP_RETURN, full data in PSBT

---

## Critical Analysis: PSBT Fields

### ✅ Advantages

| Advantage | Details |
|-----------|---------|
| **Zero on-chain footprint** | Script/witness data never hits the chain; smaller txs, lower fees |
| **Privacy** | Script logic invisible to blockchain observers |
| **Unlimited size** | No practical size limit (within PSBT constraints) |
| **Standard PSBT workflow** | Works with existing PSBT tooling and signing flows |
| **Backward compatible** | Unknown fields ignored by non-Arkade software |
| **Mutable until signed** | Can update script/witness data during PSBT construction |

### ❌ Limitations & Challenges

| Limitation | Details | Severity |
|------------|---------|----------|
| **Data availability problem** | After broadcast, script data must be preserved separately | 🔴 Critical |
| **No on-chain audit trail** | Cannot verify what script was executed by looking at chain | 🟡 Medium |
| **Coordination overhead** | All parties need access to full PSBT, not just raw tx | 🟡 Medium |
| **Replay complexity** | Reconstructing historical script execution requires archived PSBTs | 🟡 Medium |
| **Counterparty trust** | Signer must trust that PSBT contains correct script | 🔴 Critical |
| **No SPV verification** | Light clients can't verify script execution without full PSBT | 🟡 Medium |

### ⚠️ Security Concerns

1. **Script substitution attack:** Malicious actor could provide different PSBT to signer vs. introspector
2. **Data loss risk:** If PSBT archive is lost, script history is unrecoverable
3. **Non-deterministic verification:** Same on-chain tx could have been signed with different scripts

---

## Critical Analysis: OP_RETURN

### ✅ Advantages

| Advantage | Details |
|-----------|---------|
| **On-chain data availability** | Script data permanently stored, verifiable by anyone |
| **Audit trail** | Full transparency - anyone can replay script execution |
| **No coordination overhead** | All data in the transaction itself |
| **SPV-friendly** | Light clients can fetch OP_RETURN data with proofs |
| **Immutable commitment** | Can't retroactively change what script was executed |
| **Self-contained verification** | Transaction contains everything needed to verify |

### ❌ Limitations & Challenges

| Limitation | Details | Severity |
|------------|---------|----------|
| **80-byte standard limit** | Bitcoin Core relay policy limits OP_RETURN to 80 bytes | 🔴 Critical |
| **On-chain bloat** | Every byte costs fees and increases UTXO set pressure | 🟡 Medium |
| **Privacy leak** | Script logic visible to all observers | 🟡 Medium |
| **No witness data** | OP_RETURN in outputs, not inputs - can't naturally include witness | 🔴 Critical |
| **Multi-output non-standard** | Multiple OP_RETURNs rejected by most nodes | 🔴 Critical |
| **Fixed at signing time** | Cannot update data after tx construction begins | 🟠 Low |

### ⚠️ Security Concerns

1. **Compression attacks:** If using compression, malicious data could exploit decompressor
2. **Size constraints force tradeoffs:** May need to truncate or hash data, losing verifiability
3. **Fee griefing:** Large OP_RETURN data increases tx fees, potentially making attacks cheaper

---

## Detailed Technical Comparison

### Size Analysis

| Data Type | Typical Size | PSBT Impact | OP_RETURN Feasibility |
|-----------|--------------|-------------|----------------------|
| Simple Arkade Script | 50-200 bytes | ✅ No issue | ⚠️ Barely fits (80 byte limit) |
| Complex Script | 200-1000 bytes | ✅ No issue | ❌ Exceeds limit |
| Script Witness | Variable (sigs, preimages) | ✅ No issue | ❌ Way too large |
| Asset Packet (single group) | ~100 bytes | ✅ No issue | ⚠️ Tight fit |
| Asset Packet (10 groups) | ~1KB | ✅ No issue | ❌ Exceeds limit |

### Verification Model

| Aspect | PSBT Fields | OP_RETURN |
|--------|-------------|-----------|
| Who can verify? | Only parties with PSBT | Anyone with tx |
| When verifiable? | Before broadcast + archived | Forever on-chain |
| What's verified? | Script + witness + output | Script + output (no witness) |
| Verification source | Off-chain archive | Blockchain |

---

## Hybrid Approaches

### Option 1: Hash Commitment in OP_RETURN

```
OP_RETURN <"ARK1"> <SHA256(script || witness)>
```

- ✅ Only 37 bytes on-chain
- ✅ Proves what script was used (if you have the preimage)
- ❌ Still requires off-chain data storage for full script
- ❌ Doesn't help with data availability

### Option 2: Merkle Root of Asset Packet

```
OP_RETURN <"ARK1"> <merkle_root(asset_groups)>
```

- ✅ Enables selective disclosure proofs
- ✅ Compact on-chain commitment
- ❌ Full data still needed off-chain

### Option 3: Script Hash Only, Witness in PSBT

- Script stored via OP_RETURN (compressed, or hash)
- Witness data in PSBT
- ✅ Witness naturally belongs with inputs
- ⚠️ Still limited by OP_RETURN size

### Option 4: Data Availability Layer

- Store hash on Bitcoin
- Full data on separate DA layer (e.g., Arweave, Celestia, or custom)
- ✅ Unlimited data, permanent storage
- ❌ External dependency, complexity
- ❌ Trust assumptions on DA layer

---

## Hidden Advantages We Might Have Missed

### PSBT Fields

1. **Multi-sig coordination:** PSBT naturally supports partial signatures; script data travels with the PSBT through signing rounds
2. **Hardware wallet compatibility:** PSBT is the standard for hardware wallets; unknown fields are safely ignored
3. **Batch processing:** Multiple scripts can be attached to different inputs independently
4. **Version negotiation:** Could include version field for script language upgrades
5. **Encryption potential:** Script data could be encrypted in PSBT, decrypted only by authorized parties
6. **Conditional inclusion:** Signer can choose whether to include script based on context

### OP_RETURN

1. **Timestamp proof:** On-chain data has blockchain timestamp, useful for disputes
2. **Cross-client compatibility:** Any Bitcoin software can extract OP_RETURN data
3. **Archive guarantees:** Bitcoin nodes already solve data availability
4. **Legal evidence:** On-chain data may carry more weight in legal proceedings
5. **Indexing:** Block explorers and indexers automatically capture OP_RETURN data
6. **Deterministic replay:** Anyone can independently verify historical executions

---

## Hidden Limitations We Might Have Missed

### PSBT Fields

1. **PSBT size limits:** Some implementations have maximum PSBT sizes
2. **Serialization ambiguity:** Different PSBT libraries may serialize unknown fields differently
3. **Key collision:** Other protocols might use similar key names
4. **Mobile wallet support:** Some mobile wallets strip unknown fields
5. **Backup complexity:** Users must backup PSBTs, not just seeds
6. **Watch-only limitations:** Watch-only wallets see txs but not the scripts that created them
7. **Multi-party coordination:** All parties must exchange full PSBTs, not just signatures

### OP_RETURN

1. **Node relay policies:** Non-standard txs may not propagate
2. **Miner policies:** Some miners may filter OP_RETURN txs
3. **Future soft forks:** Bitcoin consensus changes could affect OP_RETURN semantics
4. **Parsing complexity:** Need robust parser for potentially malformed data
5. **Fee estimation:** Larger txs complicate fee estimation in mempool congestion
6. **UTXO bloat perception:** Community pushback against "abusing" Bitcoin for data storage
7. **No deletion:** Once on-chain, data is permanent (could be good or bad)

---

## Questions to Consider

1. **Who needs to verify?**
   - Only introspector? → PSBT is fine
   - Any observer? → Need on-chain data

2. **What's the threat model?**
   - Malicious signer? → Need commitment on-chain
   - Data loss? → Need permanent storage

3. **What's the data retention requirement?**
   - Forever? → On-chain or DA layer
   - Until settlement? → PSBT + short-term archive

4. **What's the expected script size distribution?**
   - Mostly small? → OP_RETURN might work
   - Often large? → PSBT required

5. **How important is privacy?**
   - Critical? → PSBT or encrypted OP_RETURN
   - Not important? → OP_RETURN is fine

---

## Recommendations

### For Introspector's Current Use Case

**Stick with PSBT fields, but add:**

1. **Hash commitment:** Include `SHA256(script || asset_packet)` in a witness field or similar location that propagates to the final tx
2. **Archive infrastructure:** Build robust PSBT archival system with redundancy
3. **Verification protocol:** Define clear protocol for third parties to request and verify PSBTs

### If On-Chain Verifiability Becomes Critical

**Consider hybrid approach:**

1. Store script hash in OP_RETURN (37 bytes)
2. Keep full script + witness in PSBT
3. Define protocol for revealing script data post-broadcast
4. Optional: Publish full data to DA layer with on-chain pointer

### Not Recommended

- Multiple OP_RETURNs (non-standard, propagation issues)
- Large single OP_RETURN (exceeds limits)
- Relying solely on OP_RETURN for complex scripts

---

## Conclusion

The current PSBT-based approach is technically sound for the introspector's immediate needs. Its main weakness is data availability and verifiability by third parties. If the Arkade protocol requires external verifiability (e.g., for dispute resolution or light client support), a hybrid approach with minimal on-chain commitment + off-chain data storage is the most practical path forward.

The OP_RETURN approach, while appealing for its simplicity and on-chain guarantees, is fundamentally limited by Bitcoin's 80-byte size constraint. It could work for very simple scripts or hash commitments but cannot accommodate the full expressiveness of Arkade script + witness data.

---

## References

- [BIP-174: PSBT](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
- [OP_RETURN Discussion](https://en.bitcoin.it/wiki/OP_RETURN)
- Introspector codebase: `pkg/arkade/psbt_field.go`
- Arkade Script documentation: [docs.arkadeos.com](https://docs.arkadeos.com/experimental/arkade-script)
