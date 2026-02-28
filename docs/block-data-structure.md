# Block Data Structure

This document defines the canonical MoonBlokz block layout used by
`moonblokz-chain-types`.

## Overview

- A `Block` stores serialized bytes in a fixed `[u8; MAX_BLOCK_SIZE]` buffer.
- The logical block length is tracked internally and exposed via `as_bytes()`.
- Blocks are immutable after creation.
- `version == 0` is invalid for real blocks and reserved for storage empty-slot markers.

## Constants

- `MAX_BLOCK_SIZE = 2016`
- `HEADER_SIZE = 122`
- `MAX_PAYLOAD_SIZE = MAX_BLOCK_SIZE - HEADER_SIZE`

## Header Layout (Little Endian)

- `version: u8` at offset `0`
- `sequence: u32` at offset `1`
- `creator: u32` at offset `5`
- `mined_amount: u32` at offset `9`
- `payload_type: u8` at offset `13`
- `consumed_votes: u32` at offset `14`
- `first_voted_node: u32` at offset `18`
- `consumed_votes_from_first_voted_node: u32` at offset `22`
- `previous_hash: [u8; 32]` at offset `26`
- `signature: [u8; 64]` at offset `58`
- Payload starts at offset `HEADER_SIZE` (`122`)

## Construction Paths

- `Block::from_bytes(&[u8])`:
- Validates `HEADER_SIZE <= len <= MAX_BLOCK_SIZE`
- Validates structural invariants, including non-zero version

- `BlockBuilder`:
- Starts from default header/payload state
- Allows explicit `header(...)` and `payload(...)`
- Enforces payload size and non-zero version on `build()`

## Serialization

- `Block` is already stored in serialized form internally.
- `serialized_bytes()` returns the same canonical byte slice as `as_bytes()`.

## Hashing

- Hashing is provided by `calculate_hash(&[u8]) -> [u8; HASH_SIZE]`.
- Callers typically hash `block.serialized_bytes()`.
