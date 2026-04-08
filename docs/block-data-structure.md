# Block Data Structure

This document defines the canonical MoonBlokz block layout used by
`moonblokz-chain-types`.

> "Bad programmers worry about the code. Good programmers worry about data
> structures and their relationships." — Linus Torvalds

## Overview

Every block has two parts: a **fixed-size header** and a **variable-size
payload**. The total size of a block is capped by a configuration parameter
(`MAX_BLOCK_SIZE`).

- A `Block` stores serialized bytes in a fixed `[u8; MAX_BLOCK_SIZE]` buffer.
- The logical block length is tracked internally and exposed via `serialized_bytes()`.
- Blocks are immutable after creation.
- `version == 0` is invalid for real blocks and reserved for storage empty-slot markers.

No timestamps are used anywhere in the block structure. MoonBlokz avoids
relying on any central time-synchronization infrastructure (e.g. NTP) to keep
the network fully decentralized and to eliminate clock-related security
vulnerabilities.

## Constants

- `MAX_BLOCK_SIZE = 2016`
- `HEADER_SIZE = 122`
- `MAX_PAYLOAD_SIZE = MAX_BLOCK_SIZE - HEADER_SIZE`

## Header Layout (Little Endian)

The header has ten fields:

| Field | Type | Offset | Description |
|---|---|---:|---|
| `version` | `u8` | 0 | Protocol version number. Currently fixed at `1`. `0` is reserved for storage empty-slot markers. |
| `sequence` | `u32` | 1 | Sequence number of the block, starting from zero. Sequences 0 and 1 are the genesis blocks. Max chain length is 2³² ≈ 4 billion. |
| `creator` | `u32` | 5 | The node identifier of the block creator. |
| `mined_amount` | `u32` | 9 | Reward given to miners (excluding transaction fees). Stored explicitly to facilitate balance calculations after the `snake_chain` consumes the beginning of the chain. |
| `payload_type` | `u8` | 13 | Payload type discriminator: `1` = transaction, `2` = balance, `3` = chain configuration, `4` = approval (evidence). |
| `consumed_votes` | `u32` | 14 | Number of votes consumed by the creator to create this block. Stored for the same reason as `mined_amount`. |
| `first_voted_node` | `u32` | 18 | The node that had the most votes when this block was created. Normally equals the creator; if not, the approval process starts. |
| `consumed_votes_from_first_voted_node` | `u32` | 22 | Votes consumed from the `first_voted_node`. Usually `0`; non-zero only when the creator is not the node with the most votes. |
| `previous_hash` | `[u8; 32]` | 26 | SHA-256 hash of the previous block (header + payload). Together with the signature, ensures chain immutability. |
| `signature` | `[u8; 64]` | 58 | Creator's digital (Schnorr) signature for the entire block. Together with `previous_hash` in the next block, ensures immutability. |

Payload starts at offset `HEADER_SIZE` (`122`).

## Payload Types

### 1 — Transaction Block

The most complex block type with many possible layouts.

**Top-level structure:**

| Field | Type | Description |
|---|---|---|
| `transaction_count` | `u16` | Number of transactions. Max 65 535, limited in practice by `MAX_BLOCK_SIZE`. |

Followed by a list of transactions. Each transaction has a common header:

| Field | Type | Description |
|---|---|---|
| `type` | `u8` | `1` = node transfer, `2` = registration, `3` = complex. |
| `vote` | `u32` | Node to vote for. A node cannot vote for itself. |

The remaining fields depend on the transaction type.

#### Node Transfer (type 1)

Fixed size: **96 bytes**. The least expensive transaction type.

| Field | Type | Description |
|---|---|---|
| `anchor_sequence` | `u32` | Sequence number at the time the transaction was created. Serves as a timestamp substitute and replaces nonces. A transaction cannot appear in blocks with sequence ≤ `anchor_sequence`. |
| `initializer` | `u32` | The node that started the transaction and pays the fee. |
| `receiver` | `u32` | The node that receives the transfer. |
| `amount` | `u64` | Amount of money to transfer. Only valid if the initializer has sufficient balance. |
| `fee` | `u32` | Transaction fee paid by the initializer. Min/max limits can be configured; priced per byte. |
| `comment` | `u64` | Flexible field — can represent a reference number, counter, etc. Also used for transaction uniqueness. |
| `signature` | `[u8; 64]` | Digital signature of the entire transaction by the initializer. |

> **Transaction uniqueness:** The network rejects entirely identical
> transactions. If an initializer wants to send multiple transactions with the
> same data and the same `anchor_sequence`, it must use different `comment`
> values.

#### Registration (type 2)

Registers a new node identifier and public key on the network.

| Field | Type | Description |
|---|---|---|
| `initializer` | `u32` | The existing node that initiates (and pays for) the registration. |
| `new_node_id` | `u32` | Identifier of the new node (max existing node_id + 1). Generated when the transaction is added to a block. |
| `registration_price` | `u64` | Cost of registering a new public key. Configurable, depends on dynamic factors (e.g. total number of nodes). Nobody receives this fee — the network absorbs it. |
| `fee` | `u64` | Transaction fee paid by the initializer. |
| `new_public_key` | `[u8; 32]` | Public key of the newly registered node. Must be unique across the network. |
| `new_key_signature` | `[u8; 64]` | Proof that the registrant possesses the private key corresponding to `new_public_key` (Schnorr signature of the public key). |
| `signature` | `[u8; 64]` | Digital signature of the entire transaction by the initializer. |

No `anchor_sequence` or `comment` fields are needed because the public key
alone ensures uniqueness.

#### Complex Transaction (type 3)

Variable-size transactions with optional and repeatable elements. Fees are
calculated based on the transaction's byte size.

| Field | Type | Description |
|---|---|---|
| `input_count` | `u8` | Number of inputs (0–255; 0 = special snake-chain re-add case). |
| `output_count` | `u8` | Number of outputs (1–255). |

Followed by inputs and outputs. Each starts with a `type: u8` field.

**UTXO Input (input type 0):**

| Field | Type | Description |
|---|---|---|
| `tr_hash` | `[u8; 32]` | Hash identifying the complex transaction that contains the UTXO output to spend. Hashes are used instead of sequence numbers for stability across chain direction changes. |
| `output_index` | `u8` | Index of the specific UTXO output within the referenced transaction. |
| `signature` | `[u8; 64]` | Signature of this input & all outputs, signed with the private key corresponding to the UTXO's public key. |

**Balance Input (input type 1):**

Same fields as a node transfer (`anchor_sequence`, `initializer`, `amount`,
`comment`, `signature`), except the signature covers the balance input and all
outputs.

**UTXO Output (output type 0):**

| Field | Type | Description |
|---|---|---|
| `address` | `[u8; 32]` | Public key of the UTXO. |
| `amount` | `u64` | Amount of money. |

**Balance Output (output type 1):**

| Field | Type | Description |
|---|---|---|
| `receiver` | `u32` | Identifier of the receiver node. |
| `amount` | `u64` | Amount of money. |

> **Fee rule:** A complex transaction is valid only if total inputs ≥ total
> outputs. The difference is the transaction fee.

### 2 — Balance Block

Simpler structure than transactions, allowing more entries per block.

**Payload header:**

| Field | Type | Description |
|---|---|---|
| `nodeinfo_count` | `u16` | Number of balance entries. The two-byte representation implicitly caps `MAX_BLOCK_SIZE` at ~3 MB (48 × 65 535). |
| `max_node_id` | `u32` | Highest node identifier — helps nodes verify they have information for every node. Also represents the total node count since ids are sequential. |

**Per NodeInfo entry (48 bytes):**

| Field | Type | Description |
|---|---|---|
| `owner` | `u32` | Node identifier. |
| `balance` | `u64` | The owner's amount of money. |
| `vote_count` | `u32` | Total number of votes for this node. |
| `public_key` | `[u8; 32]` | Node's public key, used to validate signatures. |

### 3 — Chain Configuration

Outlines a list of configuration parameters. The available configuration points
and dynamic formulas used as configuration values are covered in a separate
article.

### 4 — Approval (Evidence)

Multi-signature payload created by multiple nodes, accompanied by a list of
supporting nodes. Details are covered in a separate article.

## Construction Paths

- `Block::from_bytes(&[u8])`:
  - Validates `HEADER_SIZE <= len <= MAX_BLOCK_SIZE`
  - Validates structural invariants, including non-zero version

- `BlockBuilder`:
  - Starts from default header/payload state
  - Allows explicit `header(...)` and `payload(...)`
  - Enforces payload size and non-zero version on `build()`

## Serialization

Blocks are stored and transferred in binary format, placing data-structure
elements sequentially. All multi-byte fields use **little-endian**
representation.

- `Block` is already stored in serialized form internally.
- `serialized_bytes()` returns the canonical byte slice.

## Hashing

- Hashing is provided by `calculate_hash(&[u8]) -> [u8; HASH_SIZE]` (SHA-256).
- `previous_hash` is the hash of the previous block including header and payload.
- Callers typically hash `block.serialized_bytes()`.

## Radio Packetization

Block messages often exceed the typical physical packet size of the radio layer
(e.g. LoRa maximum ≈ 256 bytes). The radio layer implements packetization logic
to break blocks into smaller, manageable messages. The packet size depends on
the radio technology and is managed as a compile-time parameter in the radio
module.
