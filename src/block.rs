/*! Block type and builder for MoonBlokz chain types.

This module provides an immutable `Block` with internal fixed-size byte storage
and a `BlockBuilder` for validated construction.

Block versioning invariant:
- `version == 0` is reserved for storage empty-slot markers.
- Valid MoonBlokz blocks must use a non-zero version value.

# Design note — embedded target

This is an embedded (`no_std`) library optimised for minimal binary size.
Trait implementations such as `Debug`, `Display`, `Clone`, and `PartialEq`
are intentionally omitted from public types to avoid pulling formatting
machinery and extra code into the final binary. Derive them downstream
via newtype wrappers if needed for diagnostics or testing.
*/

use crate::error::BlockError;

/// Maximum encoded block size in bytes.
pub const MAX_BLOCK_SIZE: usize = 2016;

/// Fixed header size in bytes for the current MoonBlokz block format.
pub const HEADER_SIZE: usize = 122;

const VERSION_OFFSET: usize = 0;
const SEQUENCE_OFFSET: usize = 1;
const CREATOR_OFFSET: usize = 5;
const MINED_AMOUNT_OFFSET: usize = 9;
const PAYLOAD_TYPE_OFFSET: usize = 13;
const CONSUMED_VOTES_OFFSET: usize = 14;
const FIRST_VOTED_NODE_OFFSET: usize = 18;
const CONSUMED_VOTES_FROM_FIRST_OFFSET: usize = 22;
const PREVIOUS_HASH_OFFSET: usize = 26;
const SIGNATURE_OFFSET: usize = 58;
const PAYLOAD_OFFSET: usize = HEADER_SIZE;

/// Maximum payload bytes that can fit in a block.
pub const MAX_PAYLOAD_SIZE: usize = MAX_BLOCK_SIZE - HEADER_SIZE;

/// Parsed view of the fixed block header.
///
/// `Debug`, `Clone`, and `PartialEq` are intentionally omitted to minimise
/// binary size on embedded targets.
pub struct BlockHeader {
    /// Block version.
    ///
    /// `0` is reserved for storage empty-slot markers.
    /// Valid MoonBlokz blocks must use a non-zero version value.
    pub version: u8,
    /// Sequence number.
    pub sequence: u32,
    /// Creator node id.
    pub creator: u32,
    /// Mined amount.
    pub mined_amount: u32,
    /// Payload type discriminator.
    pub payload_type: u8,
    /// Consumed votes.
    pub consumed_votes: u32,
    /// First voted node id.
    pub first_voted_node: u32,
    /// Consumed votes from first voted node.
    pub consumed_votes_from_first_voted_node: u32,
    /// Previous block hash.
    pub previous_hash: [u8; 32],
    /// Block signature.
    pub signature: [u8; 64],
}

/// Immutable canonical block representation.
///
/// `Debug`, `Clone`, and `PartialEq` are intentionally omitted to minimise
/// binary size on embedded targets.
pub struct Block {
    data: [u8; MAX_BLOCK_SIZE],
    len: usize,
}

impl Block {
    /// Creates a block from encoded bytes.
    ///
    /// Parameters:
    /// - `bytes`: encoded block bytes.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::Block;
    ///
    /// let mut bytes = [0u8; moonblokz_chain_types::HEADER_SIZE];
    /// bytes[0] = 1;
    /// let block_result = Block::from_bytes(&bytes);
    /// assert!(block_result.is_ok());
    /// let block = match block_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.len(), moonblokz_chain_types::HEADER_SIZE);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockError> {
        if bytes.len() < HEADER_SIZE {
            return Err(BlockError::InputTooSmall {
                min: HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        if bytes.len() > MAX_BLOCK_SIZE {
            return Err(BlockError::InputTooLarge {
                max: MAX_BLOCK_SIZE,
                actual: bytes.len(),
            });
        }

        let mut data = [0u8; MAX_BLOCK_SIZE];
        data[..bytes.len()].copy_from_slice(bytes);

        let block = Self { data, len: bytes.len() };

        block.validate_structure()?;

        Ok(block)
    }

    /// Returns the canonical serialized bytes for this block.
    ///
    /// Parameters:
    /// - none.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockBuilder, BlockHeader};
    ///
    /// let header = BlockHeader {
    ///     version: 1,
    ///     sequence: 0,
    ///     creator: 0,
    ///     mined_amount: 0,
    ///     payload_type: 0,
    ///     consumed_votes: 0,
    ///     first_voted_node: 0,
    ///     consumed_votes_from_first_voted_node: 0,
    ///     previous_hash: [0; 32],
    ///     signature: [0; 64],
    /// };
    ///
    /// let block_result = BlockBuilder::new().header(header).build();
    /// assert!(block_result.is_ok());
    /// let block = match block_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert!(!block.serialized_bytes().is_empty());
    /// ```
    pub fn serialized_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Returns the encoded length in bytes.
    ///
    /// Parameters:
    /// - none.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::Block;
    ///
    /// let mut bytes = [0u8; moonblokz_chain_types::HEADER_SIZE];
    /// bytes[0] = 1;
    /// let block_result = Block::from_bytes(&bytes);
    /// assert!(block_result.is_ok());
    /// let block = match block_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.len(), moonblokz_chain_types::HEADER_SIZE);
    /// ```
    //
    // A `Block` always has at least `HEADER_SIZE` bytes, so it can never be
    // empty. An `is_empty()` method would be misleading.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Parses and returns the fixed-size header.
    ///
    /// Parameters:
    /// - none.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockBuilder, BlockHeader};
    ///
    /// let header = BlockHeader {
    ///     version: 1,
    ///     sequence: 42,
    ///     creator: 0,
    ///     mined_amount: 0,
    ///     payload_type: 0,
    ///     consumed_votes: 0,
    ///     first_voted_node: 0,
    ///     consumed_votes_from_first_voted_node: 0,
    ///     previous_hash: [0; 32],
    ///     signature: [0; 64],
    /// };
    ///
    /// let block_result = BlockBuilder::new().header(header).build();
    /// assert!(block_result.is_ok());
    /// let block = match block_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.header().sequence, 42);
    /// ```
    pub fn header(&self) -> BlockHeader {
        let mut previous_hash = [0u8; 32];
        previous_hash.copy_from_slice(&self.data[PREVIOUS_HASH_OFFSET..PREVIOUS_HASH_OFFSET + 32]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&self.data[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 64]);

        BlockHeader {
            version: self.data[VERSION_OFFSET],
            sequence: read_u32_le(&self.data, SEQUENCE_OFFSET),
            creator: read_u32_le(&self.data, CREATOR_OFFSET),
            mined_amount: read_u32_le(&self.data, MINED_AMOUNT_OFFSET),
            payload_type: self.data[PAYLOAD_TYPE_OFFSET],
            consumed_votes: read_u32_le(&self.data, CONSUMED_VOTES_OFFSET),
            first_voted_node: read_u32_le(&self.data, FIRST_VOTED_NODE_OFFSET),
            consumed_votes_from_first_voted_node: read_u32_le(&self.data, CONSUMED_VOTES_FROM_FIRST_OFFSET),
            previous_hash,
            signature,
        }
    }

    /// Returns the payload slice.
    ///
    /// Parameters:
    /// - none.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockBuilder, BlockHeader};
    ///
    /// let header = BlockHeader {
    ///     version: 1,
    ///     sequence: 0,
    ///     creator: 0,
    ///     mined_amount: 0,
    ///     payload_type: 0,
    ///     consumed_votes: 0,
    ///     first_voted_node: 0,
    ///     consumed_votes_from_first_voted_node: 0,
    ///     previous_hash: [0; 32],
    ///     signature: [0; 64],
    /// };
    ///
    /// let builder_result = BlockBuilder::new().header(header).payload(&[1, 2, 3]);
    /// assert!(builder_result.is_ok());
    /// let builder = match builder_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// let block_result = builder.build();
    /// assert!(block_result.is_ok());
    /// let block = match block_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.payload(), &[1, 2, 3]);
    /// ```
    pub fn payload(&self) -> &[u8] {
        &self.data[PAYLOAD_OFFSET..self.len]
    }

    fn validate_structure(&self) -> Result<(), BlockError> {
        if self.len < HEADER_SIZE {
            return Err(BlockError::MalformedBlock("block shorter than header"));
        }
        if self.data[VERSION_OFFSET] == 0 {
            return Err(BlockError::MalformedBlock("block version must be non-zero"));
        }
        Ok(())
    }
}

/// Builder for immutable `Block` values.
pub struct BlockBuilder {
    header: BlockHeader,
    payload: [u8; MAX_PAYLOAD_SIZE],
    payload_len: usize,
}

impl BlockBuilder {
    /// Creates a new builder with zeroed/default header and empty payload.
    ///
    /// Note:
    /// - Default header version is `0`.
    /// - Before building a valid MoonBlokz block, set a non-zero version via
    ///   `header(...)`.
    ///
    /// Parameters:
    /// - none.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::BlockBuilder;
    ///
    /// let _builder = BlockBuilder::new();
    /// ```
    //
    // `Default` is intentionally not implemented: construction through an
    // explicit `new()` call makes the zero-version starting state visible
    // to callers and avoids accidental default-construction.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            header: BlockHeader {
                version: 0,
                sequence: 0,
                creator: 0,
                mined_amount: 0,
                payload_type: 0,
                consumed_votes: 0,
                first_voted_node: 0,
                consumed_votes_from_first_voted_node: 0,
                previous_hash: [0; 32],
                signature: [0; 64],
            },
            payload: [0u8; MAX_PAYLOAD_SIZE],
            payload_len: 0,
        }
    }

    /// Sets the full fixed header for the block under construction.
    ///
    /// Parameters:
    /// - `header`: parsed header fields to encode.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockBuilder, BlockHeader};
    ///
    /// let header = BlockHeader {
    ///     version: 1,
    ///     sequence: 0,
    ///     creator: 0,
    ///     mined_amount: 0,
    ///     payload_type: 0,
    ///     consumed_votes: 0,
    ///     first_voted_node: 0,
    ///     consumed_votes_from_first_voted_node: 0,
    ///     previous_hash: [0; 32],
    ///     signature: [0; 64],
    /// };
    /// let _builder = BlockBuilder::new().header(header);
    /// ```
    pub fn header(mut self, header: BlockHeader) -> Self {
        self.header = header;
        self
    }

    /// Sets payload bytes for the block under construction.
    ///
    /// Parameters:
    /// - `payload`: payload bytes to store after the fixed header.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::BlockBuilder;
    ///
    /// let builder_result = BlockBuilder::new().payload(&[1, 2, 3]);
    /// assert!(builder_result.is_ok());
    /// let builder = match builder_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// let _use_builder = builder;
    /// ```
    pub fn payload(mut self, payload: &[u8]) -> Result<Self, BlockError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: payload.len(),
            });
        }

        self.payload[..payload.len()].copy_from_slice(payload);
        self.payload_len = payload.len();
        Ok(self)
    }

    /// Builds the immutable block.
    ///
    /// Parameters:
    /// - none.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{BlockBuilder, BlockHeader};
    ///
    /// let header = BlockHeader {
    ///     version: 1,
    ///     sequence: 0,
    ///     creator: 0,
    ///     mined_amount: 0,
    ///     payload_type: 0,
    ///     consumed_votes: 0,
    ///     first_voted_node: 0,
    ///     consumed_votes_from_first_voted_node: 0,
    ///     previous_hash: [0; 32],
    ///     signature: [0; 64],
    /// };
    ///
    /// let block_result = BlockBuilder::new().header(header).build();
    /// assert!(block_result.is_ok());
    /// let block = match block_result {
    ///     Ok(value) => value,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.len(), moonblokz_chain_types::HEADER_SIZE);
    /// ```
    pub fn build(self) -> Result<Block, BlockError> {
        if self.header.version == 0 {
            return Err(BlockError::MalformedBlock("block version must be non-zero"));
        }

        let len = HEADER_SIZE + self.payload_len;
        if len > MAX_BLOCK_SIZE {
            return Err(BlockError::InputTooLarge {
                max: MAX_BLOCK_SIZE,
                actual: len,
            });
        }

        let mut data = [0u8; MAX_BLOCK_SIZE];

        data[VERSION_OFFSET] = self.header.version;
        data[SEQUENCE_OFFSET..SEQUENCE_OFFSET + 4].copy_from_slice(&self.header.sequence.to_le_bytes());
        data[CREATOR_OFFSET..CREATOR_OFFSET + 4].copy_from_slice(&self.header.creator.to_le_bytes());
        data[MINED_AMOUNT_OFFSET..MINED_AMOUNT_OFFSET + 4].copy_from_slice(&self.header.mined_amount.to_le_bytes());
        data[PAYLOAD_TYPE_OFFSET] = self.header.payload_type;
        data[CONSUMED_VOTES_OFFSET..CONSUMED_VOTES_OFFSET + 4].copy_from_slice(&self.header.consumed_votes.to_le_bytes());
        data[FIRST_VOTED_NODE_OFFSET..FIRST_VOTED_NODE_OFFSET + 4].copy_from_slice(&self.header.first_voted_node.to_le_bytes());
        data[CONSUMED_VOTES_FROM_FIRST_OFFSET..CONSUMED_VOTES_FROM_FIRST_OFFSET + 4]
            .copy_from_slice(&self.header.consumed_votes_from_first_voted_node.to_le_bytes());
        data[PREVIOUS_HASH_OFFSET..PREVIOUS_HASH_OFFSET + 32].copy_from_slice(&self.header.previous_hash);
        data[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 64].copy_from_slice(&self.header.signature);

        if self.payload_len > 0 {
            data[PAYLOAD_OFFSET..PAYLOAD_OFFSET + self.payload_len].copy_from_slice(&self.payload[..self.payload_len]);
        }

        Ok(Block { data, len })
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        self.serialized_bytes()
    }
}

fn read_u32_le(bytes: &[u8; MAX_BLOCK_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> BlockHeader {
        BlockHeader {
            version: 2,
            sequence: 42,
            creator: 7,
            mined_amount: 11,
            payload_type: 3,
            consumed_votes: 101,
            first_voted_node: 19,
            consumed_votes_from_first_voted_node: 17,
            previous_hash: [9u8; 32],
            signature: [5u8; 64],
        }
    }

    #[test]
    fn builder_round_trip_from_bytes() {
        let builder_result = BlockBuilder::new().header(sample_header()).payload(&[1, 2, 3, 4]);
        assert!(builder_result.is_ok());
        let build_result = builder_result.unwrap_or_else(|_| unreachable!()).build();
        assert!(build_result.is_ok());
        let block = build_result.unwrap_or_else(|_| unreachable!());

        let parsed_result = Block::from_bytes(block.serialized_bytes());
        assert!(parsed_result.is_ok());
        let parsed = parsed_result.unwrap_or_else(|_| unreachable!());

        let parsed_header = parsed.header();
        let expected = sample_header();
        assert_eq!(parsed_header.version, expected.version);
        assert_eq!(parsed_header.sequence, expected.sequence);
        assert_eq!(parsed_header.creator, expected.creator);
        assert_eq!(parsed_header.mined_amount, expected.mined_amount);
        assert_eq!(parsed_header.payload_type, expected.payload_type);
        assert_eq!(parsed_header.consumed_votes, expected.consumed_votes);
        assert_eq!(parsed_header.first_voted_node, expected.first_voted_node);
        assert_eq!(
            parsed_header.consumed_votes_from_first_voted_node,
            expected.consumed_votes_from_first_voted_node
        );
        assert_eq!(parsed_header.previous_hash, expected.previous_hash);
        assert_eq!(parsed_header.signature, expected.signature);
        assert_eq!(parsed.payload(), &[1, 2, 3, 4]);
    }

    #[test]
    fn from_bytes_rejects_oversize() {
        let bytes = [0u8; MAX_BLOCK_SIZE + 1];
        let result = Block::from_bytes(&bytes);
        assert!(matches!(result, Err(BlockError::InputTooLarge { .. })));
    }

    #[test]
    fn from_bytes_rejects_too_small() {
        let bytes = [0u8; HEADER_SIZE - 1];
        let result = Block::from_bytes(&bytes);
        assert!(matches!(result, Err(BlockError::InputTooSmall { .. })));
    }

    #[test]
    fn from_bytes_rejects_zero_version() {
        let bytes = [0u8; HEADER_SIZE];
        let result = Block::from_bytes(&bytes);
        assert!(matches!(result, Err(BlockError::MalformedBlock("block version must be non-zero"))));
    }

    #[test]
    fn build_rejects_zero_version() {
        let result = BlockBuilder::new().build();
        assert!(matches!(result, Err(BlockError::MalformedBlock("block version must be non-zero"))));
    }

    #[test]
    fn accessors_return_expected_values() {
        let mut prev = [0u8; 32];
        prev[0] = 99;
        let mut sig = [0u8; 64];
        sig[63] = 88;

        let header = BlockHeader {
            previous_hash: prev,
            signature: sig,
            ..sample_header()
        };

        let builder_result = BlockBuilder::new().header(header).payload(&[42]);
        assert!(builder_result.is_ok());
        let build_result = builder_result.unwrap_or_else(|_| unreachable!()).build();
        assert!(build_result.is_ok());
        let block = build_result.unwrap_or_else(|_| unreachable!());

        let h = block.header();
        assert_eq!(h.version, 2);
        assert_eq!(h.sequence, 42);
        assert_eq!(h.creator, 7);
        assert_eq!(h.mined_amount, 11);
        assert_eq!(h.payload_type, 3);
        assert_eq!(h.consumed_votes, 101);
        assert_eq!(h.first_voted_node, 19);
        assert_eq!(h.consumed_votes_from_first_voted_node, 17);
        assert_eq!(h.previous_hash[0], 99);
        assert_eq!(h.signature[63], 88);
        assert_eq!(block.payload(), &[42]);
    }

    #[test]
    fn max_payload_size_accepted() {
        let payload = [0xABu8; MAX_PAYLOAD_SIZE];
        let builder_result = BlockBuilder::new().header(sample_header()).payload(&payload);
        assert!(builder_result.is_ok());
        let build_result = builder_result.unwrap_or_else(|_| unreachable!()).build();
        assert!(build_result.is_ok());
        let block = build_result.unwrap_or_else(|_| unreachable!());
        assert_eq!(block.len(), MAX_BLOCK_SIZE);
        assert_eq!(block.payload().len(), MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn header_only_block_has_empty_payload() {
        let build_result = BlockBuilder::new().header(sample_header()).build();
        assert!(build_result.is_ok());
        let block = build_result.unwrap_or_else(|_| unreachable!());
        assert!(block.payload().is_empty());
        assert_eq!(block.len(), HEADER_SIZE);
    }

    #[test]
    fn serialized_bytes_matches_expected_layout() {
        let header = BlockHeader {
            version: 1,
            sequence: 0x04030201,
            creator: 0x08070605,
            mined_amount: 0x0C0B0A09,
            payload_type: 0x0D,
            consumed_votes: 0x11100F0E,
            first_voted_node: 0x15141312,
            consumed_votes_from_first_voted_node: 0x19181716,
            previous_hash: [0xAA; 32],
            signature: [0xBB; 64],
        };

        let build_result = BlockBuilder::new().header(header).build();
        assert!(build_result.is_ok());
        let block = build_result.unwrap_or_else(|_| unreachable!());
        let bytes = block.serialized_bytes();

        assert_eq!(bytes[0], 1); // version
        assert_eq!(&bytes[1..5], &[0x01, 0x02, 0x03, 0x04]); // sequence LE
        assert_eq!(&bytes[5..9], &[0x05, 0x06, 0x07, 0x08]); // creator LE
        assert_eq!(&bytes[9..13], &[0x09, 0x0A, 0x0B, 0x0C]); // mined_amount LE
        assert_eq!(bytes[13], 0x0D); // payload_type
        assert_eq!(&bytes[14..18], &[0x0E, 0x0F, 0x10, 0x11]); // consumed_votes LE
        assert_eq!(&bytes[18..22], &[0x12, 0x13, 0x14, 0x15]); // first_voted_node LE
        assert_eq!(&bytes[22..26], &[0x16, 0x17, 0x18, 0x19]); // consumed_votes_from_first LE
        assert_eq!(&bytes[26..58], &[0xAA; 32]); // previous_hash
        assert_eq!(&bytes[58..122], &[0xBB; 64]); // signature
        assert_eq!(bytes.len(), HEADER_SIZE);
    }
}
