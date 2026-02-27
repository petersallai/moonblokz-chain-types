/*! Canonical MoonBlokz chain types crate.

This crate provides immutable block types and validation-focused constructors
for deterministic integration with MoonBlokz storage and chain logic.
*/

#![no_std]

pub mod block;
pub mod error;
pub mod hash;

pub use block::{Block, BlockBuilder, BlockHeader, HEADER_SIZE, MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE};
pub use error::BlockError;
pub use hash::{HASH_SIZE, calculate_hash};
