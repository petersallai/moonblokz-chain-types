/*! Zero-copy view and builder types for MoonBlokz transaction block payloads.

View types (`*View`) borrow directly from the underlying block buffer.
Builder types (`NodeTransfer`, `Registration`, `ComplexTransaction`) contain
owned byte arrays for constructing transactions before adding them to a block.
*/

use crate::block::{read_u32_le, read_u64_le, MAX_PAYLOAD_SIZE};
use crate::error::BlockError;

// Transaction type discriminators.
const TX_TYPE_NODE_TRANSFER: u8 = 1;
const TX_TYPE_REGISTRATION: u8 = 2;
const TX_TYPE_COMPLEX: u8 = 3;

// Transaction common header: type(1) + vote(4) = 5 bytes.
const TX_HEADER_SIZE: usize = 5;

// Body sizes (after common header).
const NODE_TRANSFER_BODY_SIZE: usize = 96;
const REGISTRATION_BODY_SIZE: usize = 184;

/// Total encoded size of a node-transfer transaction (header + body).
pub const NODE_TRANSFER_SIZE: usize = TX_HEADER_SIZE + NODE_TRANSFER_BODY_SIZE;

/// Total encoded size of a registration transaction (header + body).
pub const REGISTRATION_SIZE: usize = TX_HEADER_SIZE + REGISTRATION_BODY_SIZE;

// Input sizes (including type byte).
const UTXO_INPUT_SIZE: usize = 98;
const BALANCE_INPUT_SIZE: usize = 89;

// Output sizes (including type byte).
const UTXO_OUTPUT_SIZE: usize = 41;
const BALANCE_OUTPUT_SIZE: usize = 13;

// Input type discriminators.
const INPUT_TYPE_UTXO: u8 = 0;
const INPUT_TYPE_BALANCE: u8 = 1;

// Output type discriminators.
const OUTPUT_TYPE_UTXO: u8 = 0;
const OUTPUT_TYPE_BALANCE: u8 = 1;

// =======================================================================
// View types
// =======================================================================

/// Zero-copy view over a transaction block payload.
pub struct TransactionBlockPayloadView<'a> {
    data: &'a [u8],
}

impl<'a> TransactionBlockPayloadView<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        Some(Self { data })
    }

    /// Number of transactions in this block.
    pub fn count(&self) -> u16 {
        u16::from_le_bytes([self.data[0], self.data[1]])
    }

    /// Returns an iterator over the transactions.
    pub fn iter(&self) -> TransactionIterator<'a> {
        TransactionIterator {
            data: self.data,
            offset: 2,
            remaining: self.count(),
        }
    }
}

/// Zero-copy iterator over transactions in a block payload.
pub struct TransactionIterator<'a> {
    data: &'a [u8],
    offset: usize,
    remaining: u16,
}

impl<'a> Iterator for TransactionIterator<'a> {
    type Item = TransactionView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let rest = self.data.get(self.offset..)?;
        let size = transaction_size(rest)?;
        let tx = TransactionView {
            data: &self.data[self.offset..self.offset + size],
        };
        self.offset += size;
        self.remaining -= 1;
        Some(tx)
    }
}

/// Zero-copy view of a single transaction.
pub struct TransactionView<'a> {
    data: &'a [u8],
}

impl<'a> TransactionView<'a> {
    /// Transaction type discriminator (`1` = node transfer, `2` = registration, `3` = complex).
    pub fn tx_type(&self) -> u8 {
        self.data[0]
    }

    /// Voted node id.
    pub fn vote(&self) -> u32 {
        read_u32_le(self.data, 1)
    }

    /// Returns a node-transfer view if `tx_type() == 1`.
    pub fn as_node_transfer(&self) -> Option<NodeTransferView<'a>> {
        if self.data[0] != TX_TYPE_NODE_TRANSFER {
            return None;
        }
        Some(NodeTransferView {
            data: &self.data[TX_HEADER_SIZE..],
        })
    }

    /// Returns a registration view if `tx_type() == 2`.
    pub fn as_registration(&self) -> Option<RegistrationView<'a>> {
        if self.data[0] != TX_TYPE_REGISTRATION {
            return None;
        }
        Some(RegistrationView {
            data: &self.data[TX_HEADER_SIZE..],
        })
    }

    /// Returns a complex-transaction view if `tx_type() == 3`.
    pub fn as_complex(&self) -> Option<ComplexTransactionView<'a>> {
        if self.data[0] != TX_TYPE_COMPLEX {
            return None;
        }
        Some(ComplexTransactionView {
            data: &self.data[TX_HEADER_SIZE..],
        })
    }
}

/// Zero-copy view of a node-transfer transaction body (96 bytes).
pub struct NodeTransferView<'a> {
    data: &'a [u8],
}

impl<'a> NodeTransferView<'a> {
    pub fn anchor_sequence(&self) -> u32 {
        read_u32_le(self.data, 0)
    }
    pub fn initializer(&self) -> u32 {
        read_u32_le(self.data, 4)
    }
    pub fn receiver(&self) -> u32 {
        read_u32_le(self.data, 8)
    }
    pub fn amount(&self) -> u64 {
        read_u64_le(self.data, 12)
    }
    pub fn fee(&self) -> u32 {
        read_u32_le(self.data, 20)
    }
    pub fn comment(&self) -> u64 {
        read_u64_le(self.data, 24)
    }
    pub fn signature(&self) -> &[u8] {
        &self.data[32..96]
    }
}

/// Zero-copy view of a registration transaction body (184 bytes).
pub struct RegistrationView<'a> {
    data: &'a [u8],
}

impl<'a> RegistrationView<'a> {
    pub fn initializer(&self) -> u32 {
        read_u32_le(self.data, 0)
    }
    pub fn new_node_id(&self) -> u32 {
        read_u32_le(self.data, 4)
    }
    pub fn registration_price(&self) -> u64 {
        read_u64_le(self.data, 8)
    }
    pub fn fee(&self) -> u64 {
        read_u64_le(self.data, 16)
    }
    pub fn new_public_key(&self) -> &[u8] {
        &self.data[24..56]
    }
    pub fn new_key_signature(&self) -> &[u8] {
        &self.data[56..120]
    }
    pub fn signature(&self) -> &[u8] {
        &self.data[120..184]
    }
}

/// Zero-copy view of a complex transaction body.
pub struct ComplexTransactionView<'a> {
    data: &'a [u8],
}

impl<'a> ComplexTransactionView<'a> {
    pub fn input_count(&self) -> u8 {
        self.data[0]
    }
    pub fn output_count(&self) -> u8 {
        self.data[1]
    }

    /// Returns an iterator over the inputs.
    pub fn inputs(&self) -> InputIterator<'a> {
        InputIterator {
            data: self.data,
            offset: 2,
            remaining: self.data[0],
        }
    }

    /// Returns an iterator over the outputs, skipping past all inputs.
    pub fn outputs(&self) -> OutputIterator<'a> {
        let mut offset = 2usize;
        for _ in 0..self.data[0] {
            if offset >= self.data.len() {
                return OutputIterator {
                    data: self.data,
                    offset,
                    remaining: 0,
                };
            }
            let size = match self.data[offset] {
                INPUT_TYPE_UTXO => UTXO_INPUT_SIZE,
                INPUT_TYPE_BALANCE => BALANCE_INPUT_SIZE,
                _ => {
                    return OutputIterator {
                        data: self.data,
                        offset,
                        remaining: 0,
                    };
                }
            };
            offset += size;
        }
        OutputIterator {
            data: self.data,
            offset,
            remaining: self.data[1],
        }
    }
}

/// Zero-copy view of a single transaction input.
pub struct InputView<'a> {
    data: &'a [u8],
}

impl<'a> InputView<'a> {
    /// Input type discriminator (`0` = UTXO, `1` = balance).
    pub fn input_type(&self) -> u8 {
        self.data[0]
    }

    /// Returns a UTXO input view if `input_type() == 0`.
    pub fn as_utxo(&self) -> Option<UtxoInputView<'a>> {
        if self.data[0] != INPUT_TYPE_UTXO {
            return None;
        }
        Some(UtxoInputView {
            data: &self.data[1..],
        })
    }

    /// Returns a balance input view if `input_type() == 1`.
    pub fn as_balance(&self) -> Option<BalanceInputView<'a>> {
        if self.data[0] != INPUT_TYPE_BALANCE {
            return None;
        }
        Some(BalanceInputView {
            data: &self.data[1..],
        })
    }
}

/// Zero-copy iterator over inputs in a complex transaction.
pub struct InputIterator<'a> {
    data: &'a [u8],
    offset: usize,
    remaining: u8,
}

impl<'a> Iterator for InputIterator<'a> {
    type Item = InputView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.offset >= self.data.len() {
            return None;
        }
        let size = match self.data[self.offset] {
            INPUT_TYPE_UTXO => UTXO_INPUT_SIZE,
            INPUT_TYPE_BALANCE => BALANCE_INPUT_SIZE,
            _ => return None,
        };
        if self.offset + size > self.data.len() {
            return None;
        }
        let input = InputView {
            data: &self.data[self.offset..self.offset + size],
        };
        self.offset += size;
        self.remaining -= 1;
        Some(input)
    }
}

/// Zero-copy view of a single transaction output.
pub struct OutputView<'a> {
    data: &'a [u8],
}

impl<'a> OutputView<'a> {
    /// Output type discriminator (`0` = UTXO, `1` = balance).
    pub fn output_type(&self) -> u8 {
        self.data[0]
    }

    /// Returns a UTXO output view if `output_type() == 0`.
    pub fn as_utxo(&self) -> Option<UtxoOutputView<'a>> {
        if self.data[0] != OUTPUT_TYPE_UTXO {
            return None;
        }
        Some(UtxoOutputView {
            data: &self.data[1..],
        })
    }

    /// Returns a balance output view if `output_type() == 1`.
    pub fn as_balance(&self) -> Option<BalanceOutputView<'a>> {
        if self.data[0] != OUTPUT_TYPE_BALANCE {
            return None;
        }
        Some(BalanceOutputView {
            data: &self.data[1..],
        })
    }
}

/// Zero-copy iterator over outputs in a complex transaction.
pub struct OutputIterator<'a> {
    data: &'a [u8],
    offset: usize,
    remaining: u8,
}

impl<'a> Iterator for OutputIterator<'a> {
    type Item = OutputView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.offset >= self.data.len() {
            return None;
        }
        let size = match self.data[self.offset] {
            OUTPUT_TYPE_UTXO => UTXO_OUTPUT_SIZE,
            OUTPUT_TYPE_BALANCE => BALANCE_OUTPUT_SIZE,
            _ => return None,
        };
        if self.offset + size > self.data.len() {
            return None;
        }
        let output = OutputView {
            data: &self.data[self.offset..self.offset + size],
        };
        self.offset += size;
        self.remaining -= 1;
        Some(output)
    }
}

/// Zero-copy view of a UTXO input body (97 bytes, excluding type byte).
pub struct UtxoInputView<'a> {
    data: &'a [u8],
}

impl<'a> UtxoInputView<'a> {
    pub fn tr_hash(&self) -> &[u8] {
        &self.data[0..32]
    }
    pub fn output_index(&self) -> u8 {
        self.data[32]
    }
    pub fn signature(&self) -> &[u8] {
        &self.data[33..97]
    }
}

/// Zero-copy view of a balance input body (88 bytes, excluding type byte).
pub struct BalanceInputView<'a> {
    data: &'a [u8],
}

impl<'a> BalanceInputView<'a> {
    pub fn anchor_sequence(&self) -> u32 {
        read_u32_le(self.data, 0)
    }
    pub fn initializer(&self) -> u32 {
        read_u32_le(self.data, 4)
    }
    pub fn amount(&self) -> u64 {
        read_u64_le(self.data, 8)
    }
    pub fn comment(&self) -> u64 {
        read_u64_le(self.data, 16)
    }
    pub fn signature(&self) -> &[u8] {
        &self.data[24..88]
    }
}

/// Zero-copy view of a UTXO output body (40 bytes, excluding type byte).
pub struct UtxoOutputView<'a> {
    data: &'a [u8],
}

impl<'a> UtxoOutputView<'a> {
    pub fn address(&self) -> &[u8] {
        &self.data[0..32]
    }
    pub fn amount(&self) -> u64 {
        read_u64_le(self.data, 32)
    }
}

/// Zero-copy view of a balance output body (12 bytes, excluding type byte).
pub struct BalanceOutputView<'a> {
    data: &'a [u8],
}

impl<'a> BalanceOutputView<'a> {
    pub fn receiver(&self) -> u32 {
        read_u32_le(self.data, 0)
    }
    pub fn amount(&self) -> u64 {
        read_u64_le(self.data, 4)
    }
}

// =======================================================================
// Builder types
// =======================================================================

/// Owned node-transfer transaction for block construction (101 bytes).
pub struct NodeTransfer {
    data: [u8; NODE_TRANSFER_SIZE],
}

impl NodeTransfer {
    /// Creates a node-transfer transaction with all required fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vote: u32,
        anchor_sequence: u32,
        initializer: u32,
        receiver: u32,
        amount: u64,
        fee: u32,
        comment: u64,
        signature: &[u8; 64],
    ) -> Self {
        let mut data = [0u8; NODE_TRANSFER_SIZE];
        data[0] = TX_TYPE_NODE_TRANSFER;
        data[1..5].copy_from_slice(&vote.to_le_bytes());
        data[5..9].copy_from_slice(&anchor_sequence.to_le_bytes());
        data[9..13].copy_from_slice(&initializer.to_le_bytes());
        data[13..17].copy_from_slice(&receiver.to_le_bytes());
        data[17..25].copy_from_slice(&amount.to_le_bytes());
        data[25..29].copy_from_slice(&fee.to_le_bytes());
        data[29..37].copy_from_slice(&comment.to_le_bytes());
        data[37..101].copy_from_slice(signature);
        Self { data }
    }

    /// Returns the serialized transaction bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Owned registration transaction for block construction (189 bytes).
pub struct Registration {
    data: [u8; REGISTRATION_SIZE],
}

impl Registration {
    /// Creates a registration transaction with all required fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vote: u32,
        initializer: u32,
        new_node_id: u32,
        registration_price: u64,
        fee: u64,
        new_public_key: &[u8; 32],
        new_key_signature: &[u8; 64],
        signature: &[u8; 64],
    ) -> Self {
        let mut data = [0u8; REGISTRATION_SIZE];
        data[0] = TX_TYPE_REGISTRATION;
        data[1..5].copy_from_slice(&vote.to_le_bytes());
        data[5..9].copy_from_slice(&initializer.to_le_bytes());
        data[9..13].copy_from_slice(&new_node_id.to_le_bytes());
        data[13..21].copy_from_slice(&registration_price.to_le_bytes());
        data[21..29].copy_from_slice(&fee.to_le_bytes());
        data[29..61].copy_from_slice(new_public_key);
        data[61..125].copy_from_slice(new_key_signature);
        data[125..189].copy_from_slice(signature);
        Self { data }
    }

    /// Returns the serialized transaction bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Owned complex transaction builder for block construction.
///
/// Inputs must be added before outputs.
pub struct ComplexTransaction {
    data: [u8; MAX_PAYLOAD_SIZE],
    len: usize,
    outputs_started: bool,
}

impl ComplexTransaction {
    /// Creates an empty complex transaction with the given vote target.
    pub fn new(vote: u32) -> Self {
        let mut data = [0u8; MAX_PAYLOAD_SIZE];
        data[0] = TX_TYPE_COMPLEX;
        data[1..5].copy_from_slice(&vote.to_le_bytes());
        data[5] = 0; // input_count
        data[6] = 0; // output_count
        Self {
            data,
            len: TX_HEADER_SIZE + 2,
            outputs_started: false,
        }
    }

    /// Adds a UTXO input. Must be called before any output is added.
    pub fn add_utxo_input(
        &mut self,
        tr_hash: &[u8; 32],
        output_index: u8,
        signature: &[u8; 64],
    ) -> Result<&mut Self, BlockError> {
        if self.outputs_started {
            return Err(BlockError::MalformedBlock(
                "cannot add inputs after outputs",
            ));
        }
        let new_len = self.len + UTXO_INPUT_SIZE;
        if new_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: new_len,
            });
        }
        let p = self.len;
        self.data[p] = INPUT_TYPE_UTXO;
        self.data[p + 1..p + 33].copy_from_slice(tr_hash);
        self.data[p + 33] = output_index;
        self.data[p + 34..p + 98].copy_from_slice(signature);
        self.len = new_len;
        self.data[5] += 1;
        Ok(self)
    }

    /// Adds a balance input. Must be called before any output is added.
    pub fn add_balance_input(
        &mut self,
        anchor_sequence: u32,
        initializer: u32,
        amount: u64,
        comment: u64,
        signature: &[u8; 64],
    ) -> Result<&mut Self, BlockError> {
        if self.outputs_started {
            return Err(BlockError::MalformedBlock(
                "cannot add inputs after outputs",
            ));
        }
        let new_len = self.len + BALANCE_INPUT_SIZE;
        if new_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: new_len,
            });
        }
        let p = self.len;
        self.data[p] = INPUT_TYPE_BALANCE;
        self.data[p + 1..p + 5].copy_from_slice(&anchor_sequence.to_le_bytes());
        self.data[p + 5..p + 9].copy_from_slice(&initializer.to_le_bytes());
        self.data[p + 9..p + 17].copy_from_slice(&amount.to_le_bytes());
        self.data[p + 17..p + 25].copy_from_slice(&comment.to_le_bytes());
        self.data[p + 25..p + 89].copy_from_slice(signature);
        self.len = new_len;
        self.data[5] += 1;
        Ok(self)
    }

    /// Adds a UTXO output.
    pub fn add_utxo_output(
        &mut self,
        address: &[u8; 32],
        amount: u64,
    ) -> Result<&mut Self, BlockError> {
        let new_len = self.len + UTXO_OUTPUT_SIZE;
        if new_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: new_len,
            });
        }
        self.outputs_started = true;
        let p = self.len;
        self.data[p] = OUTPUT_TYPE_UTXO;
        self.data[p + 1..p + 33].copy_from_slice(address);
        self.data[p + 33..p + 41].copy_from_slice(&amount.to_le_bytes());
        self.len = new_len;
        self.data[6] += 1;
        Ok(self)
    }

    /// Adds a balance output.
    pub fn add_balance_output(
        &mut self,
        receiver: u32,
        amount: u64,
    ) -> Result<&mut Self, BlockError> {
        let new_len = self.len + BALANCE_OUTPUT_SIZE;
        if new_len > MAX_PAYLOAD_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_PAYLOAD_SIZE,
                actual: new_len,
            });
        }
        self.outputs_started = true;
        let p = self.len;
        self.data[p] = OUTPUT_TYPE_BALANCE;
        self.data[p + 1..p + 5].copy_from_slice(&receiver.to_le_bytes());
        self.data[p + 5..p + 13].copy_from_slice(&amount.to_le_bytes());
        self.len = new_len;
        self.data[6] += 1;
        Ok(self)
    }

    /// Returns the serialized transaction bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

// =======================================================================
// Helpers
// =======================================================================

/// Calculates the total byte size of a transaction starting at data[0].
fn transaction_size(data: &[u8]) -> Option<usize> {
    if data.len() < TX_HEADER_SIZE {
        return None;
    }
    match data[0] {
        TX_TYPE_NODE_TRANSFER => {
            let size = TX_HEADER_SIZE + NODE_TRANSFER_BODY_SIZE;
            if data.len() >= size {
                Some(size)
            } else {
                None
            }
        }
        TX_TYPE_REGISTRATION => {
            let size = TX_HEADER_SIZE + REGISTRATION_BODY_SIZE;
            if data.len() >= size {
                Some(size)
            } else {
                None
            }
        }
        TX_TYPE_COMPLEX => {
            if data.len() < TX_HEADER_SIZE + 2 {
                return None;
            }
            let input_count = data[TX_HEADER_SIZE] as usize;
            let output_count = data[TX_HEADER_SIZE + 1] as usize;
            let mut pos = TX_HEADER_SIZE + 2;
            for _ in 0..input_count {
                if pos >= data.len() {
                    return None;
                }
                let s = match data[pos] {
                    INPUT_TYPE_UTXO => UTXO_INPUT_SIZE,
                    INPUT_TYPE_BALANCE => BALANCE_INPUT_SIZE,
                    _ => return None,
                };
                pos += s;
                if pos > data.len() {
                    return None;
                }
            }
            for _ in 0..output_count {
                if pos >= data.len() {
                    return None;
                }
                let s = match data[pos] {
                    OUTPUT_TYPE_UTXO => UTXO_OUTPUT_SIZE,
                    OUTPUT_TYPE_BALANCE => BALANCE_OUTPUT_SIZE,
                    _ => return None,
                };
                pos += s;
                if pos > data.len() {
                    return None;
                }
            }
            Some(pos)
        }
        _ => None,
    }
}

// =======================================================================
// Tests
// =======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockBuilder, BlockHeader};

    fn build_tx_block(transactions: &[&[u8]]) -> crate::block::Block {
        let header = BlockHeader {
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
        };
        let mut builder = BlockBuilder::new().header(header);
        for tx in transactions {
            builder.add_transaction_bytes(tx).unwrap();
        }
        builder.build().unwrap()
    }

    fn make_node_transfer_bytes(anchor_seq: u32, initializer: u32, receiver: u32, amount: u64, fee: u32, comment: u64, vote: u32) -> [u8; 101] {
        let mut buf = [0u8; 101];
        buf[0] = TX_TYPE_NODE_TRANSFER;
        buf[1..5].copy_from_slice(&vote.to_le_bytes());
        buf[5..9].copy_from_slice(&anchor_seq.to_le_bytes());
        buf[9..13].copy_from_slice(&initializer.to_le_bytes());
        buf[13..17].copy_from_slice(&receiver.to_le_bytes());
        buf[17..25].copy_from_slice(&amount.to_le_bytes());
        buf[25..29].copy_from_slice(&fee.to_le_bytes());
        buf[29..37].copy_from_slice(&comment.to_le_bytes());
        buf[37..101].fill(0xAA);
        buf
    }

    // -- View tests --

    #[test]
    fn node_transfer_view_round_trip() {
        let tx_bytes = make_node_transfer_bytes(10, 1, 2, 1000, 5, 42, 99);

        let block = build_tx_block(&[&tx_bytes[..]]);
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 1);

        let tx = txp.iter().next().unwrap();
        assert_eq!(tx.tx_type(), 1);
        assert_eq!(tx.vote(), 99);

        let nt = tx.as_node_transfer().unwrap();
        assert_eq!(nt.anchor_sequence(), 10);
        assert_eq!(nt.initializer(), 1);
        assert_eq!(nt.receiver(), 2);
        assert_eq!(nt.amount(), 1000);
        assert_eq!(nt.fee(), 5);
        assert_eq!(nt.comment(), 42);
        assert_eq!(nt.signature().len(), 64);

        assert!(tx.as_registration().is_none());
        assert!(tx.as_complex().is_none());
    }

    #[test]
    fn wrong_payload_type_returns_none() {
        let header = BlockHeader {
            version: 1,
            sequence: 0,
            creator: 0,
            mined_amount: 0,
            payload_type: 2,
            consumed_votes: 0,
            first_voted_node: 0,
            consumed_votes_from_first_voted_node: 0,
            previous_hash: [0; 32],
            signature: [0; 64],
        };
        let block = BlockBuilder::new().header(header).build().unwrap();
        assert!(block.transactions().is_none());
    }

    #[test]
    fn multiple_transactions_iterate() {
        let tx1 = make_node_transfer_bytes(1, 1, 2, 100, 1, 0, 10);
        let tx2 = make_node_transfer_bytes(2, 3, 4, 200, 2, 1, 20);

        let block = build_tx_block(&[&tx1[..], &tx2[..]]);
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 2);

        let mut iter = txp.iter();
        let first = iter.next().unwrap();
        assert_eq!(first.as_node_transfer().unwrap().amount(), 100);
        let second = iter.next().unwrap();
        assert_eq!(second.as_node_transfer().unwrap().amount(), 200);
        assert!(iter.next().is_none());
    }

    #[test]
    fn registration_view_round_trip() {
        let mut tx_bytes = [0u8; REGISTRATION_SIZE];
        tx_bytes[0] = TX_TYPE_REGISTRATION;
        tx_bytes[1..5].copy_from_slice(&50u32.to_le_bytes());
        tx_bytes[5..9].copy_from_slice(&1u32.to_le_bytes());
        tx_bytes[9..13].copy_from_slice(&42u32.to_le_bytes());
        tx_bytes[13..21].copy_from_slice(&1000u64.to_le_bytes());
        tx_bytes[21..29].copy_from_slice(&10u64.to_le_bytes());
        tx_bytes[29..61].fill(0xCC);
        tx_bytes[61..125].fill(0xDD);
        tx_bytes[125..189].fill(0xEE);

        let block = build_tx_block(&[&tx_bytes[..]]);
        let tx = block.transactions().unwrap().iter().next().unwrap();
        assert_eq!(tx.tx_type(), 2);
        assert_eq!(tx.vote(), 50);

        let reg = tx.as_registration().unwrap();
        assert_eq!(reg.initializer(), 1);
        assert_eq!(reg.new_node_id(), 42);
        assert_eq!(reg.registration_price(), 1000);
        assert_eq!(reg.fee(), 10);
        assert_eq!(reg.new_public_key(), &[0xCC; 32]);
        assert_eq!(reg.new_key_signature(), &[0xDD; 64]);
        assert_eq!(reg.signature(), &[0xEE; 64]);
    }

    #[test]
    fn complex_view_utxo_round_trip() {
        let mut tx_bytes = [0u8; 146];
        tx_bytes[0] = TX_TYPE_COMPLEX;
        tx_bytes[1..5].copy_from_slice(&77u32.to_le_bytes());
        tx_bytes[5] = 1;
        tx_bytes[6] = 1;
        tx_bytes[7] = INPUT_TYPE_UTXO;
        tx_bytes[8..40].fill(0xAB);
        tx_bytes[40] = 3;
        tx_bytes[41..105].fill(0xCD);
        tx_bytes[105] = OUTPUT_TYPE_UTXO;
        tx_bytes[106..138].fill(0xEF);
        tx_bytes[138..146].copy_from_slice(&5000u64.to_le_bytes());

        let block = build_tx_block(&[&tx_bytes[..]]);
        let tx = block.transactions().unwrap().iter().next().unwrap();
        assert_eq!(tx.tx_type(), 3);

        let cx = tx.as_complex().unwrap();
        assert_eq!(cx.input_count(), 1);
        assert_eq!(cx.output_count(), 1);

        let inp = cx.inputs().next().unwrap();
        assert_eq!(inp.input_type(), 0);
        let utxo_in = inp.as_utxo().unwrap();
        assert_eq!(utxo_in.tr_hash(), &[0xAB; 32]);
        assert_eq!(utxo_in.output_index(), 3);
        assert_eq!(utxo_in.signature().len(), 64);

        let out = cx.outputs().next().unwrap();
        assert_eq!(out.output_type(), 0);
        let utxo_out = out.as_utxo().unwrap();
        assert_eq!(utxo_out.address(), &[0xEF; 32]);
        assert_eq!(utxo_out.amount(), 5000);
    }

    #[test]
    fn complex_view_balance_io() {
        let mut tx_bytes = [0u8; 109];
        tx_bytes[0] = TX_TYPE_COMPLEX;
        tx_bytes[1..5].copy_from_slice(&0u32.to_le_bytes());
        tx_bytes[5] = 1;
        tx_bytes[6] = 1;
        let mut pos = 7;
        tx_bytes[pos] = INPUT_TYPE_BALANCE; pos += 1;
        tx_bytes[pos..pos + 4].copy_from_slice(&100u32.to_le_bytes()); pos += 4;
        tx_bytes[pos..pos + 4].copy_from_slice(&7u32.to_le_bytes()); pos += 4;
        tx_bytes[pos..pos + 8].copy_from_slice(&3000u64.to_le_bytes()); pos += 8;
        tx_bytes[pos..pos + 8].copy_from_slice(&99u64.to_le_bytes()); pos += 8;
        tx_bytes[pos..pos + 64].fill(0x11); pos += 64;
        tx_bytes[pos] = OUTPUT_TYPE_BALANCE; pos += 1;
        tx_bytes[pos..pos + 4].copy_from_slice(&8u32.to_le_bytes()); pos += 4;
        tx_bytes[pos..pos + 8].copy_from_slice(&2500u64.to_le_bytes());

        let block = build_tx_block(&[&tx_bytes[..]]);
        let tx = block.transactions().unwrap().iter().next().unwrap();
        let cx = tx.as_complex().unwrap();

        let inp = cx.inputs().next().unwrap();
        let bi = inp.as_balance().unwrap();
        assert_eq!(bi.anchor_sequence(), 100);
        assert_eq!(bi.initializer(), 7);
        assert_eq!(bi.amount(), 3000);
        assert_eq!(bi.comment(), 99);
        assert_eq!(bi.signature().len(), 64);

        let out = cx.outputs().next().unwrap();
        let bo = out.as_balance().unwrap();
        assert_eq!(bo.receiver(), 8);
        assert_eq!(bo.amount(), 2500);
    }

    // -- Builder tests --

    #[test]
    fn node_transfer_builder_round_trip() {
        let sig = [0xAA; 64];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let bytes = nt.as_bytes();
        assert_eq!(bytes.len(), NODE_TRANSFER_SIZE);

        let view = TransactionView { data: bytes };
        assert_eq!(view.tx_type(), 1);
        assert_eq!(view.vote(), 99);
        let nv = view.as_node_transfer().unwrap();
        assert_eq!(nv.anchor_sequence(), 10);
        assert_eq!(nv.initializer(), 1);
        assert_eq!(nv.receiver(), 2);
        assert_eq!(nv.amount(), 1000);
        assert_eq!(nv.fee(), 5);
        assert_eq!(nv.comment(), 42);
        assert_eq!(nv.signature(), &[0xAA; 64]);
    }

    #[test]
    fn registration_builder_round_trip() {
        let pub_key = [0xCC; 32];
        let key_sig = [0xDD; 64];
        let sig = [0xEE; 64];
        let reg = Registration::new(50, 1, 42, 1000, 10, &pub_key, &key_sig, &sig);
        let bytes = reg.as_bytes();
        assert_eq!(bytes.len(), REGISTRATION_SIZE);

        let view = TransactionView { data: bytes };
        assert_eq!(view.tx_type(), 2);
        assert_eq!(view.vote(), 50);
        let rv = view.as_registration().unwrap();
        assert_eq!(rv.initializer(), 1);
        assert_eq!(rv.new_node_id(), 42);
        assert_eq!(rv.registration_price(), 1000);
        assert_eq!(rv.fee(), 10);
        assert_eq!(rv.new_public_key(), &[0xCC; 32]);
        assert_eq!(rv.new_key_signature(), &[0xDD; 64]);
        assert_eq!(rv.signature(), &[0xEE; 64]);
    }

    #[test]
    fn complex_builder_utxo_round_trip() {
        let mut cx = ComplexTransaction::new(77);
        let tr_hash = [0xAB; 32];
        let in_sig = [0xCD; 64];
        let address = [0xEF; 32];
        cx.add_utxo_input(&tr_hash, 3, &in_sig).unwrap();
        cx.add_utxo_output(&address, 5000).unwrap();

        let bytes = cx.as_bytes();
        let view = TransactionView { data: bytes };
        assert_eq!(view.tx_type(), 3);
        assert_eq!(view.vote(), 77);

        let cv = view.as_complex().unwrap();
        assert_eq!(cv.input_count(), 1);
        assert_eq!(cv.output_count(), 1);

        let inp = cv.inputs().next().unwrap();
        let ui = inp.as_utxo().unwrap();
        assert_eq!(ui.tr_hash(), &[0xAB; 32]);
        assert_eq!(ui.output_index(), 3);

        let out = cv.outputs().next().unwrap();
        let uo = out.as_utxo().unwrap();
        assert_eq!(uo.address(), &[0xEF; 32]);
        assert_eq!(uo.amount(), 5000);
    }

    #[test]
    fn complex_builder_balance_io() {
        let mut cx = ComplexTransaction::new(0);
        let sig = [0x11; 64];
        cx.add_balance_input(100, 7, 3000, 99, &sig).unwrap();
        cx.add_balance_output(8, 2500).unwrap();

        let bytes = cx.as_bytes();
        let view = TransactionView { data: bytes };
        let cv = view.as_complex().unwrap();

        let bi = cv.inputs().next().unwrap().as_balance().unwrap();
        assert_eq!(bi.anchor_sequence(), 100);
        assert_eq!(bi.initializer(), 7);
        assert_eq!(bi.amount(), 3000);
        assert_eq!(bi.comment(), 99);

        let bo = cv.outputs().next().unwrap().as_balance().unwrap();
        assert_eq!(bo.receiver(), 8);
        assert_eq!(bo.amount(), 2500);
    }

    #[test]
    fn complex_builder_rejects_input_after_output() {
        let mut cx = ComplexTransaction::new(0);
        let address = [0; 32];
        cx.add_utxo_output(&address, 100).unwrap();

        let tr_hash = [0; 32];
        let sig = [0; 64];
        let result = cx.add_utxo_input(&tr_hash, 0, &sig);
        assert!(matches!(result, Err(BlockError::MalformedBlock(_))));
    }

    // -- Coverage tests --

    #[test]
    fn complex_mixed_input_types() {
        let mut cx = ComplexTransaction::new(10);
        let utxo_sig = [0xCD; 64];
        let bal_sig = [0x11; 64];
        cx.add_utxo_input(&[0xAB; 32], 0, &utxo_sig).unwrap();
        cx.add_balance_input(50, 3, 1000, 7, &bal_sig).unwrap();
        cx.add_utxo_output(&[0xEF; 32], 800).unwrap();
        cx.add_balance_output(5, 200).unwrap();

        let bytes = cx.as_bytes();
        let view = TransactionView { data: bytes };
        let cv = view.as_complex().unwrap();
        assert_eq!(cv.input_count(), 2);
        assert_eq!(cv.output_count(), 2);

        let mut inputs = cv.inputs();
        let i1 = inputs.next().unwrap();
        assert_eq!(i1.input_type(), 0);
        assert_eq!(i1.as_utxo().unwrap().tr_hash(), &[0xAB; 32]);
        let i2 = inputs.next().unwrap();
        assert_eq!(i2.input_type(), 1);
        assert_eq!(i2.as_balance().unwrap().initializer(), 3);
        assert!(inputs.next().is_none());

        let mut outputs = cv.outputs();
        let o1 = outputs.next().unwrap();
        assert_eq!(o1.output_type(), 0);
        assert_eq!(o1.as_utxo().unwrap().amount(), 800);
        let o2 = outputs.next().unwrap();
        assert_eq!(o2.output_type(), 1);
        assert_eq!(o2.as_balance().unwrap().receiver(), 5);
        assert!(outputs.next().is_none());
    }

    #[test]
    fn complex_multiple_inputs_and_outputs() {
        let mut cx = ComplexTransaction::new(0);
        let sig1 = [0xAA; 64];
        let sig2 = [0xBB; 64];
        cx.add_utxo_input(&[0x01; 32], 0, &sig1).unwrap();
        cx.add_utxo_input(&[0x02; 32], 1, &sig2).unwrap();
        cx.add_balance_output(1, 500).unwrap();
        cx.add_balance_output(2, 300).unwrap();
        cx.add_utxo_output(&[0xCC; 32], 200).unwrap();

        let bytes = cx.as_bytes();
        let view = TransactionView { data: bytes };
        let cv = view.as_complex().unwrap();
        assert_eq!(cv.input_count(), 2);
        assert_eq!(cv.output_count(), 3);

        let mut inputs = cv.inputs();
        assert_eq!(inputs.next().unwrap().as_utxo().unwrap().tr_hash(), &[0x01; 32]);
        assert_eq!(inputs.next().unwrap().as_utxo().unwrap().output_index(), 1);
        assert!(inputs.next().is_none());

        let mut outputs = cv.outputs();
        assert_eq!(outputs.next().unwrap().as_balance().unwrap().receiver(), 1);
        assert_eq!(outputs.next().unwrap().as_balance().unwrap().amount(), 300);
        assert_eq!(outputs.next().unwrap().as_utxo().unwrap().amount(), 200);
        assert!(outputs.next().is_none());
    }

    #[test]
    fn empty_transaction_block() {
        let mut bytes = [0u8; crate::HEADER_SIZE + 2];
        bytes[0] = 1; // version
        bytes[13] = 1; // payload_type = transaction
        let block = crate::block::Block::from_bytes(&bytes).unwrap();
        let txp = block.transactions().unwrap();
        assert_eq!(txp.count(), 0);
        assert!(txp.iter().next().is_none());
    }
}
