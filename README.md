# Architectural Specification: Zero-Knowledge Conflict-Free Replicated Data Types (ZK-CRDT) for Delay-Tolerant Bipartite Networks

## 1. METADATA & ABSTRACT

| Field | Value |
|---|---|
| Title | Architectural Specification: Zero-Knowledge Conflict-Free Replicated Data Types (ZK-CRDT) for Delay-Tolerant Bipartite Networks |
| Authors | Nicholas LaRosa |
| Date | July 2026 |
| Status | Architecture Design Document / Technical Whitepaper |
| Target Topology | Trusted, Partitioned Servers & Untrusted, Mobile Clients (DTN) |

### Abstract

This document specifies a zero-knowledge conflict-free replicated data type architecture for bipartite delay-tolerant networks in which trusted server partitions synchronize asynchronously while untrusted mobile clients connect intermittently, submit private operations, and may behave adversarially. The design targets private add/remove set semantics without requiring every operation to prove against a live global Merkle root.

Conventional Merkle-tree-based private CRDT designs expose a large vulnerability surface in delay-tolerant deployments: root invalidation under front-running, nullifier soundness failures caused by witness mutation, weak edge-device entropy linking otherwise private identities, and payload fuzzing that can corrupt server state before cryptographic validation completes. This specification eliminates those classes from the consensus-critical path by shifting from a global-state proof model to a state-disjoint, UTXO-inspired object model. Every mutation is an independent cryptographic output. Every removal consumes an output by emitting a deterministic nullifier. Convergence is achieved by set union over authenticated additions and nullifier tombstones rather than by ordering writes against a mutable root.

The cryptographic stack uses BBS+ algebraic blind signatures for regional authorization of additions over hidden tags, deterministic Poseidon-based pseudorandom functions for in-circuit tag derivation, and epoch-based nullifier sharding for replay-window clipping during server partitions. Clients never supply entropy-dependent object tags directly. Instead, the zero-knowledge circuit enforces that each tag is derived from canonical item data and a private client key. Servers never need real-time cross-hub coordination to validate ordinary operations. Each partition verifies local signatures, epoch membership, nullifier uniqueness within its shard, canonical serialization constraints, and succinct zero-knowledge proofs before ingesting state deltas for later server-to-server replication.

The result is a private OR-Set design whose safety does not depend on a synchronized global Merkle root, whose replay and duplicate-removal behavior is bounded by epoch-scoped nullifier rules, whose metadata cannot be linked through weak client randomness, and whose parser-facing surface is reduced to fixed-width canonical envelopes validated before state mutation.

## 2. INTRODUCTION & NETWORK TOPOLOGY

A bipartite delay-tolerant network separates the system into two actor classes: relatively trusted infrastructure partitions and untrusted mobile edge peers. The trusted infrastructure consists of regional hubs or server partitions that maintain durable storage, perform expensive cryptographic verification, issue authorization material, and eventually reconcile with other hubs. The mobile clients are not trusted to preserve history, submit well-formed payloads, maintain clocks, use strong randomness, or avoid replaying old traffic.

The defining operational constraint is that server partitions are not guaranteed to coordinate in real time. Hub A and Hub B may each be trusted to enforce the protocol they can observe locally, but they cannot assume a live quorum, consensus round, or global root update before accepting an operation from a nearby client. The clients move between partitions, connect at random intervals, and may carry stale state from one partition to another.

```text
                    Bipartite Delay-Tolerant Network

       Trusted Server Partition                         Trusted Server Partition
              Hub A                                             Hub B
      +-----------------------+                         +-----------------------+
      | Local state shard     |                         | Local state shard     |
      | Epoch authority       |                         | Epoch authority       |
      | BBS+ verification     |                         | BBS+ verification     |
      | Nullifier shard A     |                         | Nullifier shard B     |
      | Outbound sync queue   |                         | Outbound sync queue   |
      +-----------+-----------+                         +-----------+-----------+
                  |                                                 |
                  |       asynchronous server-to-server sync         |
                  |<----------------------------------------------->|
                  |       delayed, batched, retryable, ordered       |
                  |       only by causal metadata where needed       |
                  |                                                 |
        intermittent client sync                         intermittent client sync
                  |                                                 |
         +--------+--------+                               +--------+--------+
         |                 |                               |                 |
+--------v--------+ +------v---------+             +-------v---------+ +-----v----------+
| Untrusted       | | Untrusted      |             | Untrusted       | | Untrusted      |
| Mobile Peer 1   | | Mobile Peer 2  |             | Mobile Peer 1   | | Mobile Peer 2  |
| stale cache     | | forged history |             | replay attempt  | | fuzzed payload |
| weak entropy    | | double remove  |             | delayed submit  | | malformed op   |
+-----------------+ +----------------+             +-----------------+ +----------------+
```

### Actor Constraints and Trust Profiles

Trusted server partitions have stable storage, known software, stronger entropy sources, and enough compute budget to verify succinct proofs, BBS+ authorization material, canonical payload encodings, and local nullifier sets. They are trusted to apply the protocol correctly for the information available inside their partition. They are not trusted to coordinate instantly with other partitions because the topology explicitly permits network delay, asymmetric reachability, maintenance windows, tactical isolation, radio gaps, disaster recovery states, or transport censorship between hubs.

This means a server must be able to accept or reject a client operation without asking every other hub whether the global state root is current. A design requiring synchronous root freshness turns an eventually connected topology into a fragile online consensus system. The server partition may know its local epoch, local issuer key, local nullifier shard, and previously replicated state, but it cannot assume its view is globally complete.

Untrusted mobile clients are malicious by default. A client may forge local history, delete inconvenient operations before syncing, submit duplicate removals to multiple hubs, replay old proofs under new envelopes, mutate witnesses to create structurally related nullifiers, attempt to link identities through low-entropy tags, submit variable-width payloads to stress parsers, or fuzz integer fields to trigger overflows. The protocol must treat every client-provided byte as adversarial until it passes deterministic parsing, range validation, cryptographic verification, and state-transition checks.

The architecture therefore places no safety requirement on client honesty. Clients may cache helpful data, compile proofs, and carry encrypted deltas, but they do not decide whether an operation is canonical, unique, current for an epoch, or admissible.

## 3. THREAT VECTOR ANALYSIS & ARCHITECTURAL FAILURE MODES

Merkle-tree-based private CRDTs usually model state as a commitment tree and require a client to prove that a private operation is valid relative to a known root. That is attractive in synchronous systems because the root gives a compact authenticated snapshot. In a delay-tolerant bipartite network, the root becomes a moving target that mobile clients cannot reliably observe and partitioned servers cannot globally stabilize before accepting operations. The cryptographic proof may be sound relative to an old root while still being operationally invalid for the accepting hub, or valid for Hub A while Hub B has already accepted a conflicting state transition that has not yet replicated.

The failure is architectural rather than incidental. A single global root compresses all unrelated objects into one state dependency. If any concurrent operation changes the root, every outstanding proof against the prior root becomes stale even when it mutates a disjoint object. In a DTN, this makes normal latency look like adversarial invalidation. Attackers can exploit the same property deliberately by submitting harmless root-changing operations ahead of a victim operation, causing the victim proof to fail or forcing repeated reproving.

### Failure Mode 1: State Front-Running and Root Invalidation

State front-running occurs when the validity of one client's private operation depends on a global state root that another client can change first. In a private CRDT, the victim may have compiled a proof against root `R_i`. Before the victim reaches a server, an attacker submits an unrelated operation that advances the server to root `R_{i+1}`. The victim's proof no longer verifies because the public root input is stale.

This problem is amplified by partitioning. Hub A and Hub B can each advance their own roots independently. A client that moves from Hub A to Hub B may carry a proof that was current for Hub A but unrecognizable to Hub B. The server can either reject correct work, accept stale roots with complicated exception logic, or run a root-translation protocol. All three options weaken the design. Rejection creates denial-of-service leverage. Stale-root acceptance expands the attack surface. Root translation becomes a hidden cross-partition consensus problem.

A ZK-CRDT that claims delay tolerance cannot make unrelated writes invalidate each other. The root dependency must be removed from the per-object validity predicate.

### Failure Mode 2: Nullifier Soundness Flaws

Nullifiers are intended to prevent double spends, duplicate removals, or repeated consumption of the same private object. A flawed circuit may prove that "some authorized item was removed" without forcing the nullifier to be uniquely and deterministically bound to the exact item tag, epoch, and client secret. If the witness can be mutated while preserving apparent validity, a malicious client can generate more than one removal token for the same logical object or craft structurally related tokens that evade deduplication.

In OR-Set terms, an add operation creates an add-dot and a remove operation tombstones one or more add-dots. If the remove tombstone is not cryptographically bound to the add-dot, a client can attempt double-removals, remove objects it never had authority over, or submit removal tokens to different partitions that only become visibly inconsistent after asynchronous replication. Soundness therefore requires the nullifier equation itself to be inside the circuit and over fixed public inputs.

The server must not accept a client-supplied nullifier as a mere opaque identifier. The proof must establish that the nullifier equals the protocol-defined function over the hidden tag and public epoch.

### Failure Mode 3: Metadata Leakage and Randomness Exploits

Many private systems rely on clients to generate random tags, salts, or identifiers. On mobile clients, especially browsers and constrained edge environments, entropy quality and call discipline are inconsistent. A reused seed, a predictable PRNG state, a timestamp-derived salt, or a platform-specific random failure can create linkable tags. Even if payloads are encrypted and proofs are zero-knowledge, weak tags become metadata beacons.

The risk is not only that an attacker guesses a tag. The larger risk is correlation. If a user's device generates tags with a bias, monotonically related values, or repeated prefixes, different hubs can later correlate operations during replication. A malicious client can also intentionally generate weak tags to frame another identity domain, poison deduplication indexes, or create collisions that stress server behavior.

The remedy is to remove edge randomness from object identity. The unique tag must be deterministically derived from private client material and canonical item data inside the circuit. The client may still use randomness for proof blinding, transport encryption, and ephemeral sessions, but the CRDT object identity must not depend on client-provided entropy that the server cannot audit.

### Failure Mode 4: Payload Fuzzing and State Corruption

Zero-knowledge verification does not protect a server that crashes before it reaches verification. If the server parses variable-width payloads, recursively allocated arrays, ambiguous JSON numbers, unbounded strings, or platform-dependent integer encodings before applying strict limits, an attacker can fuzz the runtime into integer overflow, memory exhaustion, type confusion, or malformed-state ingestion.

Payload fuzzing is especially dangerous in DTNs because clients can store attacks offline and submit them opportunistically to isolated hubs. A single partition crash may prevent later reconciliation or create asymmetric state views. The cryptographic layer must therefore be paired with a narrow canonical envelope. Every field that enters state transition logic must have a fixed type, fixed maximum width, fixed byte order, and deterministic domain separator. Variable application data must be hashed or committed behind length-checked canonical serialization before it reaches consensus-critical code.

The R1CS circuit and the server parser should agree on the same type discipline. The parser rejects malformed envelopes before allocation-heavy work. The circuit proves that committed data obeys the same fixed-width interpretation. This removes fuzzed payloads from the state mutation path.

## 4. CRYPTOGRAPHIC FRAMEWORK MITIGATION STRATEGIES

### Structural Stack Comparison

```text
Standard Merkle ZK-CRDT                    Zero-Surface ZK-CRDT

+------------------------------+           +--------------------------------------+
| Application CRDT operation   |           | Application CRDT operation           |
+------------------------------+           +--------------------------------------+
| Proof against global root    |           | Proof against object-local output     |
+------------------------------+           +--------------------------------------+
| Mutable Merkle state root    |           | State-disjoint UTXO commitments       |
+------------------------------+           +--------------------------------------+
| Client-generated random tag  |           | Poseidon-derived deterministic tag    |
+------------------------------+           +--------------------------------------+
| Global nullifier set         |           | Epoch-sharded nullifier sets          |
+------------------------------+           +--------------------------------------+
| Server must track root order |           | Server verifies local admissibility   |
+------------------------------+           +--------------------------------------+
| Variable payload risk        |           | Fixed-width canonical envelope        |
+------------------------------+           +--------------------------------------+
| Cross-hub freshness coupling |           | Asynchronous union and compaction     |
+------------------------------+           +--------------------------------------+
```

### A. Eliminating Global State via Disjoint UTXOs

The core mitigation is to replace a mutable global root with independent state outputs. An add operation creates an output:

```text
AddOutput = {
  op_type: ADD,
  version: 1,
  region_id,
  epoch_id,
  tag_commitment,
  item_commitment,
  issuer_public_key_id,
  bbs_authorization,
  proof_commitment
}
```

The output is not valid because it appears under a global root. It is valid because it carries a locally verifiable authorization, a canonical commitment, and a zero-knowledge proof that the hidden tag and hidden item data satisfy the protocol equations.

A remove operation consumes the logical output by publishing a nullifier tombstone:

```text
RemoveTombstone = {
  op_type: REMOVE,
  version: 1,
  region_id,
  epoch_id,
  nullifier,
  consumed_output_commitment,
  proof_commitment
}
```

CRDT convergence is then set union over add outputs and remove tombstones. The visible set is computed by including every valid add output whose tag is not consumed by a valid tombstone. Concurrent duplicate removals of the same object converge idempotently because all replicas eventually observe the same consumed output commitment and tombstone class.

This disjoint model removes front-running. An unrelated add does not alter the validity predicate for another add. A removal does not require a live global root. It requires a proof of knowledge of the hidden tag and client secret that derive the nullifier for the active epoch and consumed output.

### B. Algebraic Blind Signatures with BBS+

BBS+ signatures provide an algebraic authorization layer for hidden attributes. A regional hub can authorize an addition over a blinded tag and committed item metadata without learning the tag itself. The issuer signs a structured attribute vector:

```text
M = [
  domain_separator,
  protocol_version,
  region_id,
  epoch_id,
  tag_commitment,
  item_type,
  item_schema_hash,
  capability_class
]
```

The client obtains a blind BBS+ signature over `M`. Later, when submitting an add output to any server partition that trusts the regional issuer key, the client presents a selective disclosure proof showing possession of a valid signature over the required public attributes while keeping the tag and private item data hidden.

This avoids global database lookups for basic authorization. Hub B does not need to ask Hub A whether the client was authorized if Hub B trusts the issuer public key and the disclosed region, epoch, schema, and capability fields satisfy policy. The signature is algebraic, compact, and compatible with selective disclosure. The authorization predicate is local: verify issuer key, verify epoch policy, verify disclosed attributes, and bind the signature proof to the submitted operation commitment.

### C. PRF Tag Derivation with Poseidon

The design forbids client-selected object tags. The tag `t` is derived inside the proof circuit:

```text
item_hash = Poseidon("ZKCRDT_ITEM_V1", canonical_item_fields)
t = Poseidon("ZKCRDT_TAG_V1", client_private_key, item_hash, item_type)
tag_commitment = Poseidon("ZKCRDT_TAG_COMMIT_V1", t, region_id, schema_hash)
```

The server sees `tag_commitment`, not `t`. The zero-knowledge proof enforces that the commitment came from a tag derived by the protocol equation. A malicious client cannot choose a weak tag, reuse a timestamp salt, or inject a random identifier with linkable entropy. Two identical items under the same private key and item type deliberately derive the same tag unless the item schema includes a canonical disambiguator. If distinct duplicate entries are required, the disambiguator must be a server-issued nonce or a BBS+ signed issuance counter, not unaudited client randomness.

Poseidon is used because it is efficient inside arithmetic circuits. The deterministic PRF is keyed by client-private material and domain-separated by protocol labels so tags cannot be confused with nullifiers, commitments, or session challenges.

### D. Epoch-Based Nullifier Binding

Nullifiers are bound to server-defined epochs:

```text
nullifier = Poseidon(
  "ZKCRDT_NULLIFIER_V1",
  t,
  epoch_id,
  client_secret,
  consumed_output_commitment
)
```

The `epoch_id` is issued by the accepting server partition during session initiation. The server accepts nullifiers only for an active epoch window, for example `[current_epoch - 1, current_epoch, current_epoch + drift_allowance]` depending on clock discipline and DTN policy. Each partition maintains a local nullifier shard keyed by `(epoch_id, nullifier)` and later replicates shard summaries to other hubs.

Epoch binding clips replay windows. A proof captured in one epoch cannot be replayed indefinitely because the server challenge and active epoch are public inputs to the proof. During partition, Hub A and Hub B can each reject duplicates locally within their shard. After replication, duplicate or stale tombstones converge idempotently or are marked expired according to the epoch acceptance policy.

Epoch binding does not replace CRDT convergence. It bounds operational replay while the OR-Set tombstone model provides eventual removal convergence.

## 5. COMPLETE DESIGN SPECIFICATION: THE PRIVATE OR-SET

### OR-Set Primitive Mapping

| Standard OR-Set Primitive | Standard Meaning | Zero-Surface Cryptographic Equivalent | Server Storage |
|---|---|---|---|
| Add Set | Set of add-dots, each uniquely identifying an observed add | `AddOutput` containing `item_commitment`, `tag_commitment`, issuer proof, epoch, region, and ZK proof | Append-only authenticated add-output set partitioned by region and epoch |
| Remove Set Tombstones | Set of dots removed by an operation | `RemoveTombstone` containing deterministic `nullifier`, `consumed_output_commitment`, epoch, and ZK proof | Epoch-sharded nullifier set plus compact tombstone index |
| State Delta | Incremental CRDT operation exchanged between replicas | Canonical envelope containing one or more verified add outputs or tombstones | Signed, length-bounded replication batch with causal metadata |
| Lookup / Membership | Determine whether item is present | Include valid adds whose consumed output commitment has no accepted tombstone | Derived view, never trusted as submitted client state |
| Merge | Union of add set and remove set | Union of valid add outputs and valid tombstones, followed by deterministic visibility derivation | Idempotent append and compaction |

### Formal Model

Let `F_p` be the prime field used by the proof system. Let `Poseidon_D(...)` denote Poseidon with domain separator `D`. Let each item have canonical fixed-width fields:

```text
ItemData = (f_0, f_1, ..., f_n)
```

Each field `f_i` is represented as a bounded integer or fixed-length byte array decomposed into bits inside the circuit. The client has private key material:

```text
client_private_key = sk_c
client_secret = s_c
```

The public operation inputs are:

```text
region_id
epoch_id
schema_hash
item_type
tag_commitment
item_commitment
consumed_output_commitment
nullifier
server_challenge
```

The witness contains:

```text
canonical_item_fields
t
sk_c
s_c
bbs_signature_witness_or_authorization_witness
```

The proof binds the operation to `server_challenge` so that an old proof cannot be replayed under a new session envelope.

### Mandatory R1CS Constraint 1: Tag Integrity

The circuit computes:

```text
item_hash = Poseidon_ITEM(canonical_item_fields)
t' = Poseidon_TAG(sk_c, item_hash, item_type)
tag_commitment' = Poseidon_TAG_COMMIT(t', region_id, schema_hash)
```

R1CS equality constraints enforce:

```text
t = t'
tag_commitment = tag_commitment'
```

At the arithmetic level, for each equality:

```text
(t - t') * 1 = 0
(tag_commitment - tag_commitment') * 1 = 0
```

The Poseidon permutation itself is expanded into R1CS constraints using its round constants, S-box constraints, MDS matrix multiplication, and field additions. For an S-box exponent of `5`, each S-box element `x` is constrained as:

```text
x2 = x * x
x4 = x2 * x2
x5 = x4 * x
```

This neutralizes weak edge entropy and metadata linkage. The client cannot choose `t`. The tag must be derived from private key material and canonical item data. If a browser RNG fails, the object identity remains unaffected because no random client tag enters the equation.

### Mandatory R1CS Constraint 2: Commitment Veracity

The circuit computes:

```text
item_commitment' = Poseidon_ITEM_COMMIT(
  item_hash,
  tag_commitment,
  region_id,
  epoch_id,
  schema_hash
)

op_commitment' = Poseidon_OP_COMMIT(
  op_type,
  item_commitment',
  tag_commitment,
  server_challenge
)
```

For add operations, the public `item_commitment` must match:

```text
(item_commitment - item_commitment') * 1 = 0
```

For remove operations, the `consumed_output_commitment` must be structurally bound:

```text
expected_consumed = Poseidon_CONSUMED_OUTPUT(
  item_commitment',
  tag_commitment,
  issuer_public_key_id,
  original_add_epoch
)

(consumed_output_commitment - expected_consumed) * 1 = 0
```

This neutralizes payload substitution and proof-envelope replay. The proof is not merely "a valid proof about some hidden item." It is a proof about the exact public commitment submitted to the server, the exact epoch, and the exact session challenge. A copied proof cannot be attached to a different operation commitment without failing equality constraints.

### Mandatory R1CS Constraint 3: Nullifier Structural Uniqueness

For remove operations, the circuit computes:

```text
nullifier' = Poseidon_NULLIFIER(
  t,
  epoch_id,
  s_c,
  consumed_output_commitment
)
```

The public nullifier must match:

```text
(nullifier - nullifier') * 1 = 0
```

The circuit also enforces nonzero secret material:

```text
sk_c * inv_sk_c = 1
s_c * inv_s_c = 1
```

where `inv_sk_c` and `inv_s_c` are witness inverses. This prevents the all-zero key class from being valid if the implementation reserves zero as invalid.

This neutralizes nullifier soundness flaws. A malicious client cannot mutate the witness to emit a second unrelated nullifier for the same tag and epoch because the nullifier is fully determined by `t`, `epoch_id`, `s_c`, and the consumed output commitment. Duplicate removals within a shard collide on the same `(epoch_id, nullifier)` key and are rejected or treated as idempotent duplicates. Cross-partition duplicates converge when shards replicate.

### Mandatory R1CS Constraint 4: Serialization and Fixed-Type Bit Width Restrictions

Every public and private field that contributes to a hash is range-constrained before hashing. For an unsigned `k`-bit field `x`:

```text
x = sum_{i=0}^{k-1} 2^i b_i
b_i * (b_i - 1) = 0 for every bit b_i
0 <= x < 2^k is implied by decomposition
```

For fixed-length byte arrays, each byte `y_j` is constrained:

```text
y_j = sum_{i=0}^{7} 2^i b_{j,i}
b_{j,i} * (b_{j,i} - 1) = 0
```

For enumerations with allowed values `E = {e_0, e_1, ..., e_m}`, the circuit uses one-hot selection:

```text
selector_i * (selector_i - 1) = 0
sum selector_i = 1
enum_value = sum selector_i * e_i
```

For fixed-schema optional fields, presence is represented by a boolean bit `present`, and absent values must be zeroed:

```text
present * (present - 1) = 0
(1 - present) * field_value = 0
```

This neutralizes payload fuzzing and state corruption. The server envelope parser accepts only canonical byte lengths and fixed field order. The circuit proves that the committed item obeys the same fixed-width interpretation. An attacker cannot smuggle a variable-width integer, alternate JSON representation, oversized string, negative length, NaN-like number, or memory-layout-dependent value into the consensus state.

## 6. EXECUTION ARCHITECTURE & NETWORK PROTOCOL SEQUENCE

### Sequence Chart

```text
Untrusted Client                                      Partitioned Server Hub
       |                                                        |
       | 1. Session initiation                                 |
       |------------------------------------------------------->|
       | client_hello, supported_versions, issuer_key_hint      |
       |                                                        |
       | 2. Challenge issuance                                 |
       |<-------------------------------------------------------|
       | server_nonce, active_epoch_id, schema_hash, policy     |
       |                                                        |
       | 3. Localized proof compilation                         |
       | client derives t = Poseidon(item, sk_c)                 |
       | client computes commitment and nullifier if needed      |
       | client folds session challenge into Nova IVC proof      |
       |                                                        |
       | 4. Payload submission                                  |
       |------------------------------------------------------->|
       | canonical_envelope { proof, op_commit, nullifier,       |
       | add_output_or_remove_tombstone, BBS+ disclosure proof } |
       |                                                        |
       | 5. Server-side execution and ingestion                  |
       | parse fixed envelope                                   |
       | validate epoch window                                  |
       | check local nullifier shard                            |
       | verify BBS+ authorization                              |
       | verify succinct ZK proof                               |
       | append valid state delta                               |
       |                                                        |
       | 6. State consolidation                                 |
       | mark shard for async replication                        |
       | compact visible OR-Set view                             |
       | enqueue regional sync batch                             |
       |<-------------------------------------------------------|
       | ack { accepted, epoch_id, delta_digest, replication_id }|
       |                                                        |
```

### Step 1: Session Initiation

The client opens a session with a nearby hub and sends a minimal `client_hello` containing supported protocol versions, proof-system identifiers, issuer key hints, and maximum envelope size. It does not send private item data, raw tags, client secrets, or historical state claims as trusted input.

The server performs only bounded parsing at this stage. Any unsupported version, oversized field, duplicate field, noncanonical encoding, or unknown proof identifier is rejected before allocation-heavy work.

### Step 2: Challenge Issuance

The server returns:

```text
server_nonce
active_epoch_id
accepted_epoch_window
region_id
schema_hash
issuer_key_set_digest
proof_verification_key_id
max_batch_items
```

The nonce is ephemeral and unique within the server's session cache. The epoch is server-defined. The schema hash pins canonical serialization. The verification key identifier prevents proof confusion across circuit versions.

### Step 3: Localized Proof Compilation

The client compiles a localized proof. For long-running clients or large batches, the architecture uses an incrementally verifiable computation folding scheme such as Nova. Each operation step folds the session challenge, canonical item commitment, tag derivation, and nullifier equation into an accumulated proof state.

The important property is not that Nova is mandatory for every deployment. The important property is that the proof is session-bound and operation-local. The final proof's public inputs include the server challenge and active epoch, preventing a proof compiled for a previous session from being replayed as a fresh operation.

### Step 4: Payload Submission

The client submits a canonical envelope:

```text
Envelope = {
  magic: "ZKCRDT",
  version: 1,
  op_type,
  region_id,
  epoch_id,
  verification_key_id,
  issuer_key_id,
  op_commitment,
  tag_commitment,
  item_commitment,
  nullifier_or_zero,
  consumed_output_commitment_or_zero,
  bbs_disclosure_proof,
  zk_proof,
  envelope_digest
}
```

The envelope uses deterministic field order, fixed-width integer encoding, fixed maximum proof sizes, and length-prefixed byte arrays where variable proof blobs are unavoidable. Application payload data is never parsed as a dynamic object before commitment validation. It is either fixed-width canonical data or an opaque byte string whose length and hash are constrained.

### Step 5: Server-Side Execution and Ingestion

The server applies the validation ladder:

1. Parse the canonical envelope with strict bounds.
2. Verify `version`, `op_type`, `region_id`, `verification_key_id`, and `schema_hash`.
3. Verify `epoch_id` is inside the accepted epoch window.
4. For removals, check the local nullifier shard for `(epoch_id, nullifier)`.
5. Verify the BBS+ disclosure proof against trusted issuer keys and disclosed policy fields.
6. Verify the succinct ZK proof against the operation public inputs.
7. Insert the add output or tombstone into local append-only storage.
8. Mark the nullifier as observed in the local shard.
9. Derive the visible OR-Set view by deterministic add-minus-tombstone evaluation.

With recursive proof compression and preloaded verification keys, the target server verification path is sub-millisecond for the succinct proof check on server-class hardware, excluding network I/O, disk flush, and optional BBS+ pairing verification. Deployments that verify BBS+ proofs inline should budget separately for pairing cost or batch pairing verification across submissions.

### Step 6: State Consolidation

Accepted operations are appended to a regional shard and marked for outbound asynchronous replication. Server-to-server replication sends batches containing canonical envelopes, verification results, issuer key identifiers, epoch metadata, and shard digests. Receiving hubs do not trust the sending hub blindly for parsing; they re-check canonical envelope hashes, issuer policy, epoch admissibility for replication, and nullifier consistency before merging.

The merge rule is deterministic:

```text
MergedAdds = union(valid_add_outputs)
MergedTombstones = union(valid_remove_tombstones)
VisibleSet = {
  add in MergedAdds
  where not exists tombstone in MergedTombstones
  such that tombstone.consumed_output_commitment == add.output_commitment
}
```

Compaction may replace old epoch nullifier shards with authenticated summaries once every trusted partition has acknowledged the epoch closure. The compacted summary must preserve enough information to reject stale replays and derive the same visible OR-Set state.

## 7. CONCLUSION

This architecture removes the fragile global-root dependency that makes Merkle-tree private CRDTs brittle in delay-tolerant bipartite networks. By modeling state as disjoint UTXO-like objects, unrelated operations no longer invalidate each other, and server partitions can verify client submissions locally without live cross-hub coordination.

BBS+ blind signatures provide authorization without exposing private tags. Poseidon-derived deterministic tags remove weak edge entropy from object identity. Epoch-bound nullifiers make duplicate removals locally detectable and bound replay attempts to server-defined windows. Fixed-width canonical serialization and matching R1CS range constraints keep malformed payloads out of the state mutation path.

The resulting private OR-Set is structurally suited to tactical, disconnected, mobile, and decentralized data environments: trusted partitions can accept valid work while isolated, untrusted clients can never define validity by assertion, and eventual convergence is achieved through idempotent union of authenticated additions and tombstones rather than through a globally synchronized mutable root.
