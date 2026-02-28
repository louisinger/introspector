# PSBT Fields vs OP_RETURN: Brainstorming Analysis

**Date:** 2026-02-28  
**Author:** Nav (AI Assistant)  
**Context:** Introspector - Arkade VM data storage mechanisms

> **Assumption:** No byte limit on OP_RETURN (e.g., custom relay policy, direct miner submission, or Ark-controlled infrastructure)

---

## Executive Summary

This document analyzes two approaches for storing Arkade VM data (scripts, asset packets, witness data):
1. **Custom PSBT Fields** (current implementation)
2. **OP_RETURN Outputs** (alternative approach)

**With unlimited OP_RETURN size, the comparison shifts significantly.** The main tradeoffs become: privacy/cost vs. data availability/verifiability.

---

## Current Implementation: PSBT Fields

The introspector currently uses custom PSBT unknown fields:
```go
var ArkadeScript        = []byte("arkadescript")
var ArkadeScriptWitness = []byte("arkadescriptwitness")
```

### How It Works
1. Arkade script bytecode stored in PSBT input's `Unknown` field with key `arkadescript`
2. Script witness data (arguments) stored with key `arkadescriptwitness`
3. Asset packets passed separately to the engine via `SetAssetPacket()`
4. Data exists only in PSBT; once signed and broadcast, it's stripped

---

## Alternative: OP_RETURN Approach (No Size Limit)

Store Arkade data in transaction outputs using `OP_RETURN <data>`.

### Potential Formats
```
OP_RETURN <version:1> <type:1> <data:variable>
```

Types could include:
- `0x01` - Arkade Script
- `0x02` - Script Witness  
- `0x03` - Asset Packet
- `0x04` - Combined (all in one)

---

## Critical Analysis: PSBT Fields

### ✅ Advantages

| Advantage | Details |
|-----------|---------|
| **Zero on-chain footprint** | Script/witness data never hits the chain; smaller txs, lower fees |
| **Privacy** | Script logic invisible to blockchain observers |
| **Standard PSBT workflow** | Works with existing PSBT tooling and signing flows |
| **Backward compatible** | Unknown fields ignored by non-Arkade software |
| **Mutable until signed** | Can update script/witness data during PSBT construction |
| **No fee overhead** | Data doesn't increase transaction fees |

### ❌ Limitations & Challenges

| Limitation | Details | Severity |
|------------|---------|----------|
| **Data availability problem** | After broadcast, script data must be preserved separately | 🔴 Critical |
| **No on-chain audit trail** | Cannot verify what script was executed by looking at chain | 🔴 Critical |
| **Coordination overhead** | All parties need access to full PSBT, not just raw tx | 🟡 Medium |
| **Replay complexity** | Reconstructing historical script execution requires archived PSBTs | 🟡 Medium |
| **Counterparty trust** | Signer must trust that PSBT contains correct script | 🔴 Critical |
| **No SPV verification** | Light clients can't verify script execution without full PSBT | 🟡 Medium |
| **Script substitution attack** | Malicious actor could provide different PSBT to signer vs. introspector | 🔴 Critical |

### ⚠️ Security Concerns

1. **Script substitution attack:** Attacker shows user one PSBT, sends different one to introspector
2. **Data loss risk:** If PSBT archive is lost, script history is unrecoverable
3. **Non-deterministic verification:** Same on-chain tx could have been signed with different scripts
4. **No proof of execution:** Cannot prove to third party what script was actually executed

---

## Critical Analysis: OP_RETURN (No Size Limit)

### ✅ Advantages

| Advantage | Details |
|-----------|---------|
| **On-chain data availability** | Script data permanently stored, verifiable by anyone |
| **Immutable audit trail** | Full transparency - anyone can replay script execution |
| **No coordination overhead** | All data in the transaction itself |
| **SPV-friendly** | Light clients can fetch OP_RETURN data with merkle proofs |
| **Immutable commitment** | Can't retroactively change what script was executed |
| **Self-contained verification** | Transaction contains everything needed to verify |
| **Deterministic replay** | Anyone can independently verify historical executions |
| **No trust required** | Verifier doesn't need to trust any party for data |
| **Timestamp proof** | On-chain data has blockchain timestamp |
| **Archive guarantees** | Bitcoin nodes already solve data availability |

### ❌ Limitations & Challenges

| Limitation | Details | Severity |
|------------|---------|----------|
| **On-chain cost** | Every byte costs fees (1 sat/vB minimum, often higher) | 🟡 Medium |
| **Privacy leak** | Script logic visible to all observers | 🟡 Medium |
| **Permanent exposure** | Once on-chain, data is forever public | 🟡 Medium |
| **Chain bloat** | Increases blockchain size | 🟠 Low |
| **Fixed at signing time** | Cannot update data after tx construction begins | 🟠 Low |

### ⚠️ Security Concerns

1. **Privacy:** Competitors/adversaries can analyze all Arkade scripts on-chain
2. **Front-running:** Visible scripts could enable MEV-style attacks
3. **Regulatory:** On-chain data may be subject to legal discovery

---

## Re-evaluated Comparison (No Size Limit)

### Data Availability

| Aspect | PSBT Fields | OP_RETURN |
|--------|-------------|-----------|
| Where is data? | Off-chain, requires archive | On-chain, permanent |
| Who can access? | Only parties with PSBT | Anyone |
| Data loss risk | High (archive failure) | Zero (consensus guarantees) |
| Coordination needed | Yes (PSBT distribution) | No (self-contained) |

### Verification Model

| Aspect | PSBT Fields | OP_RETURN |
|--------|-------------|-----------|
| Who can verify? | Only parties with PSBT | Anyone with tx |
| When verifiable? | If PSBT preserved | Forever |
| Trust required? | Yes (PSBT source) | No |
| Dispute resolution | Complex (prove PSBT) | Simple (point to chain) |

### Cost Model

| Aspect | PSBT Fields | OP_RETURN |
|--------|-------------|-----------|
| On-chain cost | Zero | Linear with data size |
| Storage cost | Archive infrastructure | Zero (Bitcoin handles it) |
| Typical script (200 bytes) | 0 sats | ~200 sats (at 1 sat/vB) |
| Complex script (2KB) | 0 sats | ~2000 sats |
| Asset packet (1KB) | 0 sats | ~1000 sats |

### Privacy Model

| Aspect | PSBT Fields | OP_RETURN |
|--------|-------------|-----------|
| Script visibility | Private | Public |
| Business logic exposure | None | Complete |
| Counterparty analysis | Impossible | Trivial |

---

## Deep Dive: What OP_RETURN Enables

With no size limit, OP_RETURN becomes a compelling option:

### 1. Self-Proving Transactions
The transaction itself proves what script was executed. No external data needed.

### 2. Trustless Dispute Resolution
In case of disputes:
- PSBT: "Here's the PSBT I claim was used" → other party can deny
- OP_RETURN: "Look at the chain" → irrefutable

### 3. Light Client Support
SPV clients can:
- Fetch tx with merkle proof
- Extract OP_RETURN data
- Verify script execution locally

### 4. Decentralized Indexing
Anyone can build an index of all Arkade scripts without needing access to PSBTs.

### 5. Historical Analysis
Researchers, auditors, regulators can analyze protocol behavior without cooperation.

---

## Deep Dive: What PSBT Fields Preserve

### 1. Privacy
Script logic is proprietary/confidential? PSBT keeps it hidden.

### 2. Cost Efficiency
High-value scripts with low fee tolerance? PSBT costs nothing on-chain.

### 3. Flexibility
Need to modify script during multi-party signing? PSBT allows updates.

### 4. Existing Infrastructure
Hardware wallets, signing devices, PSBT coordinators all work out of the box.

---

## New Hybrid Approaches (Given No Size Limit)

### Option 1: Selective Disclosure
- Simple/standard scripts → embed in OP_RETURN
- Complex/private scripts → PSBT + hash commitment

### Option 2: Encrypted OP_RETURN
```
OP_RETURN <encrypted_script> <key_commitment>
```
- Data is on-chain (availability)
- Only authorized parties can decrypt (privacy)
- Key can be revealed for disputes

### Option 3: Tiered Approach
- Asset packet → always OP_RETURN (needed for verification)
- Script → OP_RETURN (usually small, important for audit)
- Witness → PSBT (often large, less critical for audit)

### Option 4: Compression
```
OP_RETURN <"ARK"> <version> <zstd_compressed_data>
```
- Reduce on-chain footprint by 60-80%
- Still self-contained
- Trivial to decompress

---

## Hidden Advantages We Might Have Missed

### PSBT Fields
1. **Partial signature coordination:** Script travels through signing rounds naturally
2. **Hardware wallet safety:** Unknown fields ignored, no risk of misinterpretation
3. **Encryption integration:** Easy to encrypt script in PSBT field
4. **Conditional execution:** Different introspectors could see different scripts (multi-path)
5. **Signature aggregation:** MuSig2 flows work naturally with PSBT
6. **Backward compatibility:** Old software ignores new fields

### OP_RETURN
1. **Cross-chain proofs:** Bitcoin tx proves execution on other chains (bridges)
2. **Legal evidence:** On-chain data is strong evidence in legal proceedings
3. **Insurance/audit:** Third parties can audit without cooperation
4. **Replay attacks detectable:** If same script used twice, visible on chain
5. **Protocol governance:** Community can analyze and discuss live protocol behavior
6. **Bug bounties:** Security researchers can analyze scripts for vulnerabilities
7. **Standardization path:** On-chain data enables protocol standardization

---

## Hidden Limitations We Might Have Missed

### PSBT Fields
1. **Forking issue:** If PSBT is modified after partial signing, signatures invalidated
2. **Size inflation:** Large scripts bloat PSBT, slow transmission
3. **No proof of deletion:** Cannot prove script was destroyed
4. **Censorship:** Archive operator could selectively lose PSBTs
5. **Key management:** Who controls the archive? Single point of failure
6. **Versioning hell:** Different PSBT libraries serialize differently
7. **Mobile sync:** Syncing PSBTs across devices is complex

### OP_RETURN
1. **Censorship (miners):** Miners could theoretically filter Arkade txs
2. **MEV extraction:** Visible scripts enable front-running
3. **Competitive intelligence:** Competitors see all your logic
4. **Regulatory surface:** On-chain data subject to legal requests
5. **Immutability:** Cannot "recall" a buggy script once broadcast
6. **Parsing attacks:** Malformed OP_RETURN data could crash parsers
7. **Fee volatility:** During fee spikes, large OP_RETURNs become expensive

---

## Critical Questions

### 1. What's the threat model?

| Threat | PSBT Solution | OP_RETURN Solution |
|--------|---------------|-------------------|
| Malicious signer | ❌ Can show different PSBT | ✅ Script on chain |
| Data loss | ❌ Archive failure | ✅ Chain is permanent |
| Privacy breach | ✅ Data off-chain | ❌ Data public |
| Dispute resolution | ❌ "He said, she said" | ✅ Chain is truth |

### 2. Who are the verifiers?
- Only introspector? → PSBT fine
- Counterparties? → Need at least commitment
- Public/regulators? → OP_RETURN ideal

### 3. What's the cost sensitivity?
- High-frequency, low-value → PSBT (cost matters)
- Low-frequency, high-value → OP_RETURN (verification matters)

### 4. What's the privacy requirement?
- Confidential business logic → PSBT or encrypted OP_RETURN
- Standard contracts → OP_RETURN acceptable

---

## Revised Recommendations

### For Maximum Security & Verifiability
**Use OP_RETURN with full data:**
- Script + witness + asset packet all on-chain
- Self-proving transactions
- No trust assumptions
- Higher cost, but strongest guarantees

### For Privacy-Sensitive Applications
**Use PSBT with hash commitment:**
- Full data in PSBT
- `SHA256(script || witness || packet)` in OP_RETURN or witness
- Reveal data for disputes only
- Balance of privacy and verifiability

### For Cost-Sensitive Applications
**Use PSBT with tiered commitment:**
- Critical data (asset packet) → OP_RETURN
- Script → Hash in OP_RETURN
- Witness → PSBT only
- Minimize on-chain footprint while preserving auditability

### For Standard Use Cases
**Use compressed OP_RETURN:**
- Full data, compressed (60-80% savings)
- Self-contained verification
- Reasonable cost
- No coordination overhead

---

## Conclusion

**With no OP_RETURN size limit, the calculus changes dramatically.**

The PSBT approach's main advantage becomes **privacy and cost**, while OP_RETURN wins on **data availability, verifiability, and trustlessness**.

For a protocol like Arkade where:
- Third-party verification matters (dispute resolution)
- Light client support is desirable
- Trust minimization is a core value

**OP_RETURN (or compressed OP_RETURN) is likely the better default**, with PSBT reserved for privacy-critical edge cases.

The current PSBT implementation is not wrong, but it creates a data availability problem that OP_RETURN solves elegantly. The cost of on-chain data is the price of trustlessness.

---

## Cost Analysis (Real Numbers)

Assuming 10 sat/vB fee rate:

| Data Type | Size | PSBT Cost | OP_RETURN Cost | Compressed OP_RETURN |
|-----------|------|-----------|----------------|---------------------|
| Simple script | 100 bytes | 0 | 1,000 sats | ~400 sats |
| Medium script | 500 bytes | 0 | 5,000 sats | ~2,000 sats |
| Complex script | 2 KB | 0 | 20,000 sats | ~8,000 sats |
| Asset packet (5 groups) | 500 bytes | 0 | 5,000 sats | ~2,000 sats |
| Full tx data | 3 KB | 0 | 30,000 sats | ~12,000 sats |

At 100k sats/USD, the complex script costs ~$0.08 uncompressed or ~$0.03 compressed.

**This is likely acceptable for most use cases.**

---

## References

- [BIP-174: PSBT](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
- [OP_RETURN Discussion](https://en.bitcoin.it/wiki/OP_RETURN)
- Introspector codebase: `pkg/arkade/psbt_field.go`
- Arkade Script documentation: [docs.arkadeos.com](https://docs.arkadeos.com/experimental/arkade-script)
