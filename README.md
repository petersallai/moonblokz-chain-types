# moonblokz-chain-types

Canonical MoonBlokz `no_std` chain data structures and hash contract.

## API Overview

- `Block`: immutable block wrapper over fixed-size internal storage.
- `BlockBuilder`: typed builder for constructing `Block` instances.
- `BlockHeader`: parsed fixed header view.
- `calculate_hash`: canonical SHA-256 helper used by storage and chain logic.
- Constants:
  - `MAX_BLOCK_SIZE`
  - `HEADER_SIZE`
  - `MAX_PAYLOAD_SIZE`
  - `HASH_SIZE`

## Documentation

- `docs/block-data-structure.md`: canonical binary layout, invariants, and construction rules.

## Version Invariant

- `version == 0` is reserved for storage empty-slot markers.
- Valid MoonBlokz blocks must use a non-zero version value.

## Basic Example

```rust
use moonblokz_chain_types::{BlockBuilder, BlockHeader, calculate_hash, HASH_SIZE};

let header = BlockHeader {
    version: 1,
    sequence: 1,
    creator: 10,
    mined_amount: 0,
    payload_type: 0,
    consumed_votes: 0,
    first_voted_node: 0,
    consumed_votes_from_first_voted_node: 0,
    previous_hash: [0; 32],
    signature: [0; 64],
};

let block = BlockBuilder::new()
    .header(header)
    .payload(&[1, 2, 3])
    .unwrap()
    .build()
    .unwrap();

let hash = calculate_hash(block.serialized_bytes());
assert_eq!(hash.len(), HASH_SIZE);
```
