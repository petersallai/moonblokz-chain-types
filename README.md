# moonblokz-chain-types

Canonical MoonBlokz `no_std` chain data structures and hash contract.

## Integration and Distribution

Current recommended integration model is Git dependency. Future crates.io
release model is documented below for later phase adoption.

### Current: Git Dependency

```toml
[dependencies]
moonblokz-chain-types = { git = "https://github.com/petersallai/moonblokz-chain-types" }
```

### Future: crates.io Dependency

After crates.io publication, dependency wiring should switch to versioned crates:

```toml
[dependencies]
moonblokz-chain-types = "0.1"
```

Release expectations for crates.io phase:
- Keep `no_std` compatibility unchanged.
- Preserve canonical block binary layout unless a documented breaking release is made.
- Publish semver-compatible updates with changelog notes for API/contract changes.

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
- `docs/release-process.md`: versioning, changelog, tagging, and release checklist.
- `CHANGELOG.md`: user-visible release history.

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
    .build()
    .unwrap();

let hash = calculate_hash(block.serialized_bytes());
assert_eq!(hash.len(), HASH_SIZE);
```
