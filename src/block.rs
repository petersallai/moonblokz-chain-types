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

use crate::balance::{BALANCE_HEADER_SIZE, BalanceBlockPayloadView, NodeInfo};
use crate::error::BlockError;
use crate::transaction::{ComplexTransaction, NodeTransfer, Registration, TransactionBlockPayloadView};

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

/// Payload type: transaction block.
pub const PAYLOAD_TYPE_TRANSACTION: u8 = 1;
/// Payload type: balance block.
pub const PAYLOAD_TYPE_BALANCE: u8 = 2;
/// Payload type: chain configuration block.
pub const PAYLOAD_TYPE_CHAIN_CONFIG: u8 = 3;
/// Payload type: approval (evidence) block.
pub const PAYLOAD_TYPE_APPROVAL: u8 = 4;

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

    /// Block version. `0` is reserved for storage empty-slot markers.
    pub fn version(&self) -> u8 {
        self.data[VERSION_OFFSET]
    }

    /// Block sequence number.
    pub fn sequence(&self) -> u32 {
        read_u32_le(&self.data, SEQUENCE_OFFSET)
    }

    /// Creator node id.
    pub fn creator(&self) -> u32 {
        read_u32_le(&self.data, CREATOR_OFFSET)
    }

    /// Mined amount (excluding transaction fees).
    pub fn mined_amount(&self) -> u32 {
        read_u32_le(&self.data, MINED_AMOUNT_OFFSET)
    }

    /// Payload type discriminator.
    pub fn payload_type(&self) -> u8 {
        self.data[PAYLOAD_TYPE_OFFSET]
    }

    /// Consumed votes.
    pub fn consumed_votes(&self) -> u32 {
        read_u32_le(&self.data, CONSUMED_VOTES_OFFSET)
    }

    /// First voted node id.
    pub fn first_voted_node(&self) -> u32 {
        read_u32_le(&self.data, FIRST_VOTED_NODE_OFFSET)
    }

    /// Consumed votes from first voted node.
    pub fn consumed_votes_from_first_voted_node(&self) -> u32 {
        read_u32_le(&self.data, CONSUMED_VOTES_FROM_FIRST_OFFSET)
    }

    /// Previous block hash (32 bytes, borrowed).
    pub fn previous_hash(&self) -> &[u8] {
        &self.data[PREVIOUS_HASH_OFFSET..PREVIOUS_HASH_OFFSET + 32]
    }

    /// Block signature (64 bytes, borrowed).
    pub fn signature(&self) -> &[u8] {
        &self.data[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 64]
    }

    /// Returns the payload slice.
    ///
    /// Parameters:
    /// - none.
    ///
    /// Example:
    /// ```
    /// use moonblokz_chain_types::{Block, HEADER_SIZE};
    ///
    /// let mut bytes = [0u8; HEADER_SIZE + 3];
    /// bytes[0] = 1;
    /// bytes[HEADER_SIZE] = 1;
    /// bytes[HEADER_SIZE + 1] = 2;
    /// bytes[HEADER_SIZE + 2] = 3;
    /// let block = match Block::from_bytes(&bytes) {
    ///     Ok(b) => b,
    ///     Err(_) => return,
    /// };
    /// assert_eq!(block.payload(), &[1, 2, 3]);
    /// ```
    pub fn payload(&self) -> &[u8] {
        &self.data[PAYLOAD_OFFSET..self.len]
    }

    /// Returns a transaction block payload view if `payload_type() == 1`.
    pub fn transactions(&self) -> Option<TransactionBlockPayloadView<'_>> {
        if self.data[PAYLOAD_TYPE_OFFSET] != PAYLOAD_TYPE_TRANSACTION {
            return None;
        }
        TransactionBlockPayloadView::new(self.payload())
    }

    /// Returns a balance block payload view if `payload_type() == 2`.
    pub fn balances(&self) -> Option<BalanceBlockPayloadView<'_>> {
        if self.data[PAYLOAD_TYPE_OFFSET] != PAYLOAD_TYPE_BALANCE {
            return None;
        }
        BalanceBlockPayloadView::new(self.payload())
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
    item_count: u16,
    max_node_id: u32,
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
            item_count: 0,
            max_node_id: 0,
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

    // -- Type-safe add methods --

    /// Adds a node-transfer transaction to the block payload.
    ///
    /// The payload type is automatically set to `PAYLOAD_TYPE_TRANSACTION` on the
    /// first call. Subsequent calls must be consistent (only transaction types).
    pub fn add_node_transfer(&mut self, tx: &NodeTransfer) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_TRANSACTION)?;
        self.append_item(tx.as_bytes())
    }

    /// Adds a registration transaction to the block payload.
    pub fn add_registration(&mut self, tx: &Registration) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_TRANSACTION)?;
        self.append_item(tx.as_bytes())
    }

    /// Adds a complex transaction to the block payload.
    pub fn add_complex_transaction(&mut self, tx: &ComplexTransaction) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_TRANSACTION)?;
        self.append_item(tx.as_bytes())
    }

    /// Adds a transaction from its raw binary form to the block payload.
    pub fn add_transaction_bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_TRANSACTION)?;
        self.append_item(bytes)
    }

    /// Adds a node-info balance entry to the block payload.
    ///
    /// The payload type is automatically set to `PAYLOAD_TYPE_BALANCE` on the
    /// first call. Subsequent calls must be consistent (only balance entries).
    /// The `max_node_id` is tracked automatically from the added entries;
    /// use `set_max_node_id` to override.
    pub fn add_node_info(&mut self, ni: &NodeInfo) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_BALANCE)?;
        let bytes = ni.as_bytes();
        let new_len = self.payload_len + bytes.len();
        if new_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: new_len,
            });
        }
        self.payload[self.payload_len..new_len].copy_from_slice(bytes);
        self.payload_len = new_len;
        self.item_count += 1;
        self.payload[0..2].copy_from_slice(&self.item_count.to_le_bytes());
        let owner = ni.owner();
        if owner > self.max_node_id {
            self.max_node_id = owner;
            self.payload[2..6].copy_from_slice(&self.max_node_id.to_le_bytes());
        }
        Ok(self)
    }

    /// Sets the `max_node_id` for a balance block.
    ///
    /// This overrides the auto-tracked value. Only valid for balance payloads.
    pub fn set_max_node_id(&mut self, max_node_id: u32) -> Result<&mut Self, BlockError> {
        self.ensure_managed_payload(PAYLOAD_TYPE_BALANCE)?;
        self.max_node_id = max_node_id;
        self.payload[2..6].copy_from_slice(&self.max_node_id.to_le_bytes());
        Ok(self)
    }

    fn ensure_managed_payload(&mut self, expected_type: u8) -> Result<(), BlockError> {
        if self.payload_len == 0 {
            if self.header.payload_type != 0 && self.header.payload_type != expected_type {
                return Err(BlockError::MalformedBlock("payload type mismatch"));
            }
            self.header.payload_type = expected_type;
            match expected_type {
                PAYLOAD_TYPE_TRANSACTION => {
                    self.payload[0..2].copy_from_slice(&0u16.to_le_bytes());
                    self.payload_len = 2;
                }
                PAYLOAD_TYPE_BALANCE => {
                    self.payload[0..2].copy_from_slice(&0u16.to_le_bytes());
                    self.payload[2..6].copy_from_slice(&0u32.to_le_bytes());
                    self.payload_len = BALANCE_HEADER_SIZE;
                }
                _ => {}
            }
        } else if self.header.payload_type != expected_type {
            return Err(BlockError::MalformedBlock("payload type mismatch"));
        }
        Ok(())
    }

    fn append_item(&mut self, bytes: &[u8]) -> Result<&mut Self, BlockError> {
        let new_len = self.payload_len + bytes.len();
        if new_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: new_len,
            });
        }
        self.payload[self.payload_len..new_len].copy_from_slice(bytes);
        self.payload_len = new_len;
        self.item_count += 1;
        self.payload[0..2].copy_from_slice(&self.item_count.to_le_bytes());
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

pub(crate) fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

pub(crate) fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
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
        let sig = [0xAA; 64];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt).unwrap();
        let block = builder.build().unwrap();

        let parsed = Block::from_bytes(block.serialized_bytes()).unwrap();

        assert_eq!(parsed.version(), 2);
        assert_eq!(parsed.sequence(), 42);
        assert_eq!(parsed.creator(), 7);
        assert_eq!(parsed.mined_amount(), 11);
        assert_eq!(parsed.payload_type(), PAYLOAD_TYPE_TRANSACTION);
        assert_eq!(parsed.consumed_votes(), 101);
        assert_eq!(parsed.first_voted_node(), 19);
        assert_eq!(parsed.consumed_votes_from_first_voted_node(), 17);
        assert_eq!(parsed.previous_hash(), &[9u8; 32][..]);
        assert_eq!(parsed.signature(), &[5u8; 64][..]);
        let tx = parsed.transactions().unwrap().iter().next().unwrap();
        assert_eq!(tx.as_node_transfer().unwrap().amount(), 1000);
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

        let block = BlockBuilder::new().header(header).build().unwrap();

        assert_eq!(block.version(), 2);
        assert_eq!(block.sequence(), 42);
        assert_eq!(block.creator(), 7);
        assert_eq!(block.mined_amount(), 11);
        assert_eq!(block.payload_type(), 3);
        assert_eq!(block.consumed_votes(), 101);
        assert_eq!(block.first_voted_node(), 19);
        assert_eq!(block.consumed_votes_from_first_voted_node(), 17);
        assert_eq!(block.previous_hash()[0], 99);
        assert_eq!(block.signature()[63], 88);
        assert!(block.payload().is_empty());
    }

    #[test]
    fn max_block_size_accepted() {
        let mut bytes = [0u8; MAX_BLOCK_SIZE];
        bytes[0] = 1;
        let block = Block::from_bytes(&bytes).unwrap();
        assert_eq!(block.len(), MAX_BLOCK_SIZE);
        assert_eq!(block.payload().len(), MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn header_only_block_has_empty_payload() {
        let block = BlockBuilder::new().header(sample_header()).build().unwrap();
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

        let block = BlockBuilder::new().header(header).build().unwrap();
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

    // -- Add method tests --

    #[test]
    fn block_builder_add_node_transfer() {
        let sig = [0xAA; 64];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt).unwrap();
        let block = builder.build().unwrap();
        assert_eq!(block.payload_type(), PAYLOAD_TYPE_TRANSACTION);
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 1);
        let tx = txp.iter().next().unwrap();
        assert_eq!(tx.vote(), 99);
        let nv = tx.as_node_transfer().unwrap();
        assert_eq!(nv.amount(), 1000);
    }

    #[test]
    fn block_builder_add_two_node_transfers() {
        let sig = [0xAA; 64];
        let nt1 = NodeTransfer::new(1, 10, 1, 2, 100, 1, 0, &sig);
        let nt2 = NodeTransfer::new(2, 20, 3, 4, 200, 2, 1, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt1).unwrap();
        builder.add_node_transfer(&nt2).unwrap();
        let block = builder.build().unwrap();
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 2);
        let mut iter = txp.iter();
        assert_eq!(iter.next().unwrap().as_node_transfer().unwrap().amount(), 100);
        assert_eq!(iter.next().unwrap().as_node_transfer().unwrap().amount(), 200);
        assert!(iter.next().is_none());
    }

    #[test]
    fn block_builder_add_transaction_bytes() {
        let sig = [0xAA; 64];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_transaction_bytes(nt.as_bytes()).unwrap();
        let block = builder.build().unwrap();
        assert_eq!(block.payload_type(), PAYLOAD_TYPE_TRANSACTION);
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 1);
        let tx = txp.iter().next().unwrap();
        assert_eq!(tx.as_node_transfer().unwrap().amount(), 1000);
    }

    #[test]
    fn block_builder_add_node_info() {
        let pub_key = [0xBB; 32];
        let ni = NodeInfo::new(5, 2000, 3, &pub_key);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_info(&ni).unwrap();
        let block = builder.build().unwrap();
        assert_eq!(block.payload_type(), PAYLOAD_TYPE_BALANCE);
        let bp = block.balances().unwrap();
        assert_eq!(bp.count(), 1);
        assert_eq!(bp.max_node_id(), 5);
        let entry = bp.iter().next().unwrap();
        assert_eq!(entry.owner(), 5);
        assert_eq!(entry.balance(), 2000);
    }

    #[test]
    fn block_builder_set_max_node_id() {
        let pub_key = [0; 32];
        let ni = NodeInfo::new(3, 100, 0, &pub_key);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_info(&ni).unwrap();
        builder.set_max_node_id(999).unwrap();
        let block = builder.build().unwrap();
        let bp = block.balances().unwrap();
        assert_eq!(bp.max_node_id(), 999);
    }

    #[test]
    fn block_builder_rejects_type_mismatch() {
        let sig = [0xAA; 64];
        let nt = NodeTransfer::new(0, 0, 0, 0, 0, 0, 0, &sig);
        let pub_key = [0; 32];
        let ni = NodeInfo::new(0, 0, 0, &pub_key);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_transfer(&nt).unwrap();
        let result = builder.add_node_info(&ni);
        assert!(matches!(result, Err(BlockError::MalformedBlock("payload type mismatch"))));
    }

    #[test]
    fn from_bytes_with_truncated_payload() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0] = 1;
        bytes[PAYLOAD_TYPE_OFFSET] = PAYLOAD_TYPE_BALANCE;
        let block = Block::from_bytes(&bytes).unwrap();
        assert!(block.payload().is_empty());
        assert!(block.balances().is_none());
    }

    #[test]
    fn set_max_node_id_lower_than_auto_tracked() {
        let pub_key = [0; 32];
        let ni = NodeInfo::new(100, 500, 0, &pub_key);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        builder.add_node_info(&ni).unwrap();
        builder.set_max_node_id(50).unwrap();
        let block = builder.build().unwrap();
        let bp = block.balances().unwrap();
        assert_eq!(bp.max_node_id(), 50);
    }

    #[test]
    fn add_methods_reject_at_max_payload() {
        let sig = [0xAA; 64];
        let nt = NodeTransfer::new(0, 0, 0, 0, 0, 0, 0, &sig);
        let mut builder = BlockBuilder::new().header(BlockHeader {
            payload_type: 0,
            ..sample_header()
        });
        // NODE_TRANSFER_SIZE = 101. Payload header = 2. Available = 1894 - 2 = 1892.
        // 18 * 101 = 1818 <= 1892, 19 * 101 = 1919 > 1892.
        for _ in 0..18 {
            builder.add_node_transfer(&nt).unwrap();
        }
        let result = builder.add_node_transfer(&nt);
        assert!(matches!(result, Err(BlockError::PayloadTooLarge { .. })));
    }
}
