/*! Zero-copy view and builder types for MoonBlokz balance block payloads.

View types (`*View`) borrow directly from the underlying block buffer.
The `NodeInfo` builder type contains an owned byte array for constructing
balance entries before adding them to a block.
*/

use crate::block::{read_u32_le, read_u64_le};

/// Size of a single balance entry (node info) in bytes.
pub const NODE_INFO_SIZE: usize = 48;

/// Size of the balance payload header: nodeinfo_count(2) + max_node_id(4).
pub(crate) const BALANCE_HEADER_SIZE: usize = 6;

// =======================================================================
// View types
// =======================================================================

/// Zero-copy view over a balance block payload.
pub struct BalanceBlockPayloadView<'a> {
    data: &'a [u8],
}

impl<'a> BalanceBlockPayloadView<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < BALANCE_HEADER_SIZE {
            return None;
        }
        Some(Self { data })
    }

    /// Number of node-info entries.
    pub fn count(&self) -> u16 {
        u16::from_le_bytes([self.data[0], self.data[1]])
    }

    /// Highest node id known to the network at block creation time.
    pub fn max_node_id(&self) -> u32 {
        read_u32_le(self.data, 2)
    }

    /// Returns an iterator over the node-info entries.
    pub fn iter(&self) -> BalanceIterator<'a> {
        BalanceIterator {
            data: self.data,
            offset: BALANCE_HEADER_SIZE,
            remaining: self.count(),
        }
    }
}

/// Zero-copy iterator over balance entries.
pub struct BalanceIterator<'a> {
    data: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> Iterator for BalanceIterator<'a> {
    type Item = NodeInfoView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.offset + NODE_INFO_SIZE > self.data.len() {
            return None;
        }
        let entry = NodeInfoView {
            data: &self.data[self.offset..self.offset + NODE_INFO_SIZE],
        };
        self.offset += NODE_INFO_SIZE;
        self.remaining -= 1;
        Some(entry)
    }
}

/// Zero-copy view of a single node-info balance entry (48 bytes).
pub struct NodeInfoView<'a> {
    data: &'a [u8],
}

impl<'a> NodeInfoView<'a> {
    pub fn owner(&self) -> u32 {
        read_u32_le(self.data, 0)
    }
    pub fn balance(&self) -> u64 {
        read_u64_le(self.data, 4)
    }
    pub fn vote_count(&self) -> u32 {
        read_u32_le(self.data, 12)
    }
    pub fn public_key(&self) -> &[u8] {
        &self.data[16..48]
    }
}

// =======================================================================
// Builder types
// =======================================================================

/// Owned node-info balance entry for block construction (48 bytes).
pub struct NodeInfo {
    data: [u8; NODE_INFO_SIZE],
}

impl NodeInfo {
    /// Creates a node-info entry with all required fields.
    pub fn new(owner: u32, balance: u64, vote_count: u32, public_key: &[u8; 32]) -> Self {
        let mut data = [0u8; NODE_INFO_SIZE];
        data[0..4].copy_from_slice(&owner.to_le_bytes());
        data[4..12].copy_from_slice(&balance.to_le_bytes());
        data[12..16].copy_from_slice(&vote_count.to_le_bytes());
        data[16..48].copy_from_slice(public_key);
        Self { data }
    }

    /// Returns the serialized entry bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the owner node id.
    pub fn owner(&self) -> u32 {
        read_u32_le(&self.data, 0)
    }
}

// =======================================================================
// Tests
// =======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockBuilder, BlockHeader};

    fn sample_balance_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            sequence: 0,
            creator: 0,
            mined_amount: 0,
            payload_type: 0,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0; 32],
            signature: [0; 64],
        }
    }

    // -- View tests --

    #[test]
    fn balance_view_round_trip() {
        let pub_key = [0xBB; 32];
        let ni = NodeInfo::new(5, 2000, 3, &pub_key);
        let mut builder = BlockBuilder::new().header(sample_balance_header());
        builder.add_node_info(&ni).unwrap();
        builder.set_max_node_id(100).unwrap();
        let block = builder.build().unwrap();

        let bp = block.balances().unwrap();
        assert_eq!(bp.count(), 1);
        assert_eq!(bp.max_node_id(), 100);

        let view = bp.iter().next().unwrap();
        assert_eq!(view.owner(), 5);
        assert_eq!(view.balance(), 2000);
        assert_eq!(view.vote_count(), 3);
        assert_eq!(view.public_key(), &[0xBB; 32]);
    }

    #[test]
    fn wrong_type_returns_none() {
        let header = BlockHeader {
            payload_type: 1,
            ..sample_balance_header()
        };
        let block = BlockBuilder::new().header(header).build().unwrap();
        assert!(block.balances().is_none());
    }

    #[test]
    fn multiple_entries_iterate() {
        let pub_key = [0xBB; 32];
        let ni1 = NodeInfo::new(1, 100, 0, &pub_key);
        let ni2 = NodeInfo::new(2, 200, 1, &pub_key);
        let mut builder = BlockBuilder::new().header(sample_balance_header());
        builder.add_node_info(&ni1).unwrap();
        builder.add_node_info(&ni2).unwrap();
        builder.set_max_node_id(50).unwrap();
        let block = builder.build().unwrap();

        let bp = block.balances().unwrap();
        assert_eq!(bp.count(), 2);

        let mut iter = bp.iter();
        assert_eq!(iter.next().unwrap().balance(), 100);
        assert_eq!(iter.next().unwrap().balance(), 200);
        assert!(iter.next().is_none());
    }

    // -- Builder tests --

    #[test]
    fn node_info_builder_round_trip() {
        let pub_key = [0xBB; 32];
        let ni = NodeInfo::new(5, 2000, 3, &pub_key);
        assert_eq!(ni.as_bytes().len(), NODE_INFO_SIZE);
        assert_eq!(ni.owner(), 5);

        let view = NodeInfoView { data: ni.as_bytes() };
        assert_eq!(view.owner(), 5);
        assert_eq!(view.balance(), 2000);
        assert_eq!(view.vote_count(), 3);
        assert_eq!(view.public_key(), &[0xBB; 32]);
    }

    #[test]
    fn empty_balance_block() {
        let mut bytes = [0u8; crate::HEADER_SIZE + BALANCE_HEADER_SIZE];
        bytes[0] = 1; // version
        bytes[13] = 2; // payload_type = balance
        let block = crate::block::Block::from_bytes(&bytes).unwrap();
        let bp = block.balances().unwrap();
        assert_eq!(bp.count(), 0);
        assert_eq!(bp.max_node_id(), 0);
        assert!(bp.iter().next().is_none());
    }
}
