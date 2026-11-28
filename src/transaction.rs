/*! Zero-copy view and builder types for MoonBlokz transaction block payloads.

View types (`*View`) borrow directly from the underlying block buffer.
Builder types (`NodeTransfer`, `Registration`, `ComplexTransaction`) contain
owned byte arrays for constructing transactions before adding them to a block.
*/

use crate::block::{MAX_PAYLOAD_SIZE, read_u32_le, read_u64_le};
use crate::error::BlockError;
use crate::hash::{HASH_SIZE, calculate_hash};
use moonblokz_crypto::{CryptoTrait, PUBLIC_KEY_SIZE, SIGNATURE_SIZE, SignatureTrait};

// Transaction type discriminators.
const TX_TYPE_NODE_TRANSFER: u8 = 1;
const TX_TYPE_REGISTRATION: u8 = 2;
const TX_TYPE_COMPLEX: u8 = 3;

// Transaction common header: type(1) + vote(4) = 5 bytes.
const TX_HEADER_SIZE: usize = 5;

// Body sizes (after common header), derived from the scheme's sizes (DEC-251): the
// signatures close each record, so every fixed field keeps its offset.
// Node transfer: anchor_sequence u32 ‖ initializer u32 ‖ receiver u32 ‖ amount u64 ‖
// fee u32 ‖ comment u64 ‖ signature.
const NODE_TRANSFER_BODY_SIZE: usize = 32 + SIGNATURE_SIZE;
// Registration: anchor_sequence u32 ‖ initializer u32 ‖ new_node_id u32 ‖
// registration_price u64 ‖ fee u64 ‖ new_public_key ‖ new_key_signature (the proof of
// possession) ‖ signature. The anchor opens the body as in the node transfer (DEC-356).
const REGISTRATION_BODY_SIZE: usize = 28 + PUBLIC_KEY_SIZE + 2 * SIGNATURE_SIZE;

const NODE_TRANSFER_SIGNATURE_OFFSET: usize = TX_HEADER_SIZE + 32;
const REGISTRATION_NEW_KEY_OFFSET: usize = TX_HEADER_SIZE + 28;
const REGISTRATION_NEW_KEY_SIGNATURE_OFFSET: usize = REGISTRATION_NEW_KEY_OFFSET + PUBLIC_KEY_SIZE;
const REGISTRATION_SIGNATURE_OFFSET: usize = REGISTRATION_NEW_KEY_SIGNATURE_OFFSET + SIGNATURE_SIZE;

/// Total encoded size of a node-transfer transaction (header + body).
pub const NODE_TRANSFER_SIZE: usize = TX_HEADER_SIZE + NODE_TRANSFER_BODY_SIZE;

/// Total encoded size of a registration transaction (header + body).
pub const REGISTRATION_SIZE: usize = TX_HEADER_SIZE + REGISTRATION_BODY_SIZE;

// UTXO input body layout (ADR-016, DEC-131):
// block_sequence u32 LE ‖ output_index u16 LE ‖ amount u64 LE ‖ signature.
// `output_index` is a `u16` (DEC-222): it indexes the referenced block's whole
// UTXO-output stream, whose size is chain parameter ID 4 (`u16`).
const UTXO_INPUT_BLOCK_SEQUENCE_OFFSET: usize = 0;
const UTXO_INPUT_OUTPUT_INDEX_OFFSET: usize = UTXO_INPUT_BLOCK_SEQUENCE_OFFSET + 4;
const UTXO_INPUT_AMOUNT_OFFSET: usize = UTXO_INPUT_OUTPUT_INDEX_OFFSET + 2;
const UTXO_INPUT_SIGNATURE_OFFSET: usize = UTXO_INPUT_AMOUNT_OFFSET + 8;
const UTXO_INPUT_SIGNATURE_SIZE: usize = SIGNATURE_SIZE;
const UTXO_INPUT_BODY_SIZE: usize = UTXO_INPUT_SIGNATURE_OFFSET + UTXO_INPUT_SIGNATURE_SIZE;

// Input sizes (including type byte).
const UTXO_INPUT_SIZE: usize = 1 + UTXO_INPUT_BODY_SIZE;
// Balance input: type ‖ anchor_sequence u32 ‖ initializer u32 ‖ amount u64 ‖ comment u64 ‖
// signature.
const BALANCE_INPUT_SIGNATURE_OFFSET: usize = 24;
const BALANCE_INPUT_SIZE: usize = 1 + BALANCE_INPUT_SIGNATURE_OFFSET + SIGNATURE_SIZE;

// Output sizes (including type byte).
// UTXO output: type ‖ address (the owner's public key, DEC-253) ‖ amount u64.
const UTXO_OUTPUT_SIZE: usize = 1 + PUBLIC_KEY_SIZE + 8;
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
    /// Constructs a borrowed view over standalone transaction bytes
    /// (e.g., mempool entries that don't live inside a block payload).
    ///
    /// Validates the structural invariant — `tx_type` is one of the known
    /// discriminators, and `bytes.len()` matches the fixed-size kinds —
    /// without copying. Returns `None` on malformed input.
    pub fn from_bytes(bytes: &'a [u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        match bytes[0] {
            TX_TYPE_NODE_TRANSFER if bytes.len() == NODE_TRANSFER_SIZE => {
                Some(Self { data: bytes })
            }
            TX_TYPE_REGISTRATION if bytes.len() == REGISTRATION_SIZE => Some(Self { data: bytes }),
            TX_TYPE_COMPLEX if transaction_size(bytes) == Some(bytes.len()) => {
                Some(Self { data: bytes })
            }
            _ => None,
        }
    }

    /// Returns the borrowed serialized transaction bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the canonical transaction hash.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        calculate_hash(self.data)
    }

    /// Returns the serialized transaction length in bytes.
    //
    // A valid `TransactionView` always spans at least `TX_HEADER_SIZE` bytes,
    // so it can never be empty. An `is_empty()` method would be misleading.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

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

    /// The DEC-196 input-signature preimage of a complex transaction, written
    /// into `buf`: the transaction's full serialized bytes — type, `vote`,
    /// counts, every input and every output — with **every input's signature
    /// field set to zero**. Every input, UTXO or balance, signs these same bytes
    /// with its own key, so each signer commits to all inputs, all outputs and
    /// the `vote` field (FR6). The one definition shared by signers and the
    /// verifier (DEC-331), as [`crate::BlockView::signing_preimage`] is for the
    /// block preimage.
    ///
    /// Returns `None` for a transaction that is not complex, whose inputs do not
    /// frame, or when `buf` is shorter than the transaction
    /// ([`MAX_TRANSACTION_SIZE`] always suffices).
    pub fn input_signing_preimage<'b>(&self, buf: &'b mut [u8]) -> Option<&'b [u8]> {
        if self.tx_type() != TX_TYPE_COMPLEX {
            return None;
        }
        let out = buf.get_mut(..self.data.len())?;
        out.copy_from_slice(self.data);
        let mut offset = TX_HEADER_SIZE + 2;
        for _ in 0..out[TX_HEADER_SIZE] {
            let (size, signature) = input_layout(out, offset)?;
            out.get_mut(signature)?.fill(0);
            offset += size;
        }
        Some(out)
    }
}

/// Size and signature-field range of the complex-transaction input that starts
/// at `offset` of the full transaction bytes `tx`; `None` for an unknown input
/// type or one that runs past `tx`.
fn input_layout(tx: &[u8], offset: usize) -> Option<(usize, core::ops::Range<usize>)> {
    let (size, signature_at) = match *tx.get(offset)? {
        INPUT_TYPE_UTXO => (UTXO_INPUT_SIZE, 1 + UTXO_INPUT_SIGNATURE_OFFSET),
        INPUT_TYPE_BALANCE => (BALANCE_INPUT_SIZE, 1 + BALANCE_INPUT_SIGNATURE_OFFSET),
        _ => return None,
    };
    if offset + size > tx.len() {
        return None;
    }
    let start = offset + signature_at;
    Some((size, start..start + SIGNATURE_SIZE))
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
        &self.data[32..32 + SIGNATURE_SIZE]
    }
}

/// Zero-copy view of a registration transaction body (`REGISTRATION_SIZE` minus the
/// common header).
pub struct RegistrationView<'a> {
    data: &'a [u8],
}

impl<'a> RegistrationView<'a> {
    /// The window anchor (DEC-356): a registration is includable in a block of
    /// sequence `s` only while `max(0, s − W) ≤ anchor < s`.
    pub fn anchor_sequence(&self) -> u32 {
        read_u32_le(self.data, 0)
    }
    pub fn initializer(&self) -> u32 {
        read_u32_le(self.data, 4)
    }
    pub fn new_node_id(&self) -> u32 {
        read_u32_le(self.data, 8)
    }
    pub fn registration_price(&self) -> u64 {
        read_u64_le(self.data, 12)
    }
    pub fn fee(&self) -> u64 {
        read_u64_le(self.data, 20)
    }
    pub fn new_public_key(&self) -> &[u8] {
        &self.data[28..28 + PUBLIC_KEY_SIZE]
    }
    pub fn new_key_signature(&self) -> &[u8] {
        &self.data[28 + PUBLIC_KEY_SIZE..28 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE]
    }
    pub fn signature(&self) -> &[u8] {
        &self.data[28 + PUBLIC_KEY_SIZE + SIGNATURE_SIZE..REGISTRATION_BODY_SIZE]
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

/// Zero-copy view of a UTXO input body (`14 + SIGNATURE_SIZE` bytes, excluding the
/// type byte: 78 / 62 / 110 with Schnorr / `bls-min-sig` / `bls-min-pk`).
///
/// The input references the spent output by the sequence of the block that
/// holds it and its position in that block's UTXO-output stream (ADR-016),
/// and declares the output's amount (DEC-131).
pub struct UtxoInputView<'a> {
    data: &'a [u8],
}

impl<'a> UtxoInputView<'a> {
    pub fn block_sequence(&self) -> u32 {
        read_u32_le(self.data, UTXO_INPUT_BLOCK_SEQUENCE_OFFSET)
    }
    pub fn output_index(&self) -> u16 {
        u16::from_le_bytes([
            self.data[UTXO_INPUT_OUTPUT_INDEX_OFFSET],
            self.data[UTXO_INPUT_OUTPUT_INDEX_OFFSET + 1],
        ])
    }
    pub fn amount(&self) -> u64 {
        read_u64_le(self.data, UTXO_INPUT_AMOUNT_OFFSET)
    }
    pub fn signature(&self) -> &[u8] {
        &self.data[UTXO_INPUT_SIGNATURE_OFFSET..UTXO_INPUT_BODY_SIZE]
    }
}

/// Zero-copy view of a balance input body (`24 + SIGNATURE_SIZE` bytes, excluding
/// the type byte: 88 / 72 / 120 with Schnorr / `bls-min-sig` / `bls-min-pk`).
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
        &self.data[BALANCE_INPUT_SIGNATURE_OFFSET..BALANCE_INPUT_SIGNATURE_OFFSET + SIGNATURE_SIZE]
    }
}

/// Zero-copy view of a UTXO output body (`PUBLIC_KEY_SIZE + 8` bytes, excluding the
/// type byte: 40 / 104 / 56 with Schnorr / `bls-min-sig` / `bls-min-pk`).
pub struct UtxoOutputView<'a> {
    data: &'a [u8],
}

impl<'a> UtxoOutputView<'a> {
    pub fn address(&self) -> &[u8] {
        &self.data[0..PUBLIC_KEY_SIZE]
    }
    pub fn amount(&self) -> u64 {
        read_u64_le(self.data, PUBLIC_KEY_SIZE)
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
        signature: &[u8; SIGNATURE_SIZE],
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
        data[NODE_TRANSFER_SIGNATURE_OFFSET..NODE_TRANSFER_SIZE].copy_from_slice(signature);
        Self { data }
    }

    /// Creates and signs a node-transfer transaction.
    ///
    /// The signing input is the complete transaction byte sequence with the
    /// signature field zero-filled. The returned owned transaction stores the
    /// signer-produced signature (`SIGNATURE_SIZE` bytes) in its signature field.
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed<Crypto: CryptoTrait>(
        vote: u32,
        anchor_sequence: u32,
        initializer: u32,
        receiver: u32,
        amount: u64,
        fee: u32,
        comment: u64,
        crypto: &Crypto,
    ) -> Self {
        let zero_signature = [0u8; SIGNATURE_SIZE];
        let mut tx = Self::new(
            vote,
            anchor_sequence,
            initializer,
            receiver,
            amount,
            fee,
            comment,
            &zero_signature,
        );
        let signature = crypto.sign(&tx.data);
        tx.data[NODE_TRANSFER_SIGNATURE_OFFSET..NODE_TRANSFER_SIZE]
            .copy_from_slice(signature.serialize());
        tx
    }

    /// Returns the serialized transaction bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the canonical transaction hash.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        calculate_hash(&self.data)
    }
}

/// Owned registration transaction for block construction (`REGISTRATION_SIZE` bytes).
pub struct Registration {
    data: [u8; REGISTRATION_SIZE],
}

impl Registration {
    /// Creates a registration transaction with all required fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vote: u32,
        anchor_sequence: u32,
        initializer: u32,
        new_node_id: u32,
        registration_price: u64,
        fee: u64,
        new_public_key: &[u8; PUBLIC_KEY_SIZE],
        new_key_signature: &[u8; SIGNATURE_SIZE],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Self {
        let mut data = [0u8; REGISTRATION_SIZE];
        data[0] = TX_TYPE_REGISTRATION;
        data[1..5].copy_from_slice(&vote.to_le_bytes());
        data[5..9].copy_from_slice(&anchor_sequence.to_le_bytes());
        data[9..13].copy_from_slice(&initializer.to_le_bytes());
        data[13..17].copy_from_slice(&new_node_id.to_le_bytes());
        data[17..25].copy_from_slice(&registration_price.to_le_bytes());
        data[25..33].copy_from_slice(&fee.to_le_bytes());
        data[REGISTRATION_NEW_KEY_OFFSET..REGISTRATION_NEW_KEY_SIGNATURE_OFFSET]
            .copy_from_slice(new_public_key);
        data[REGISTRATION_NEW_KEY_SIGNATURE_OFFSET..REGISTRATION_SIGNATURE_OFFSET]
            .copy_from_slice(new_key_signature);
        data[REGISTRATION_SIGNATURE_OFFSET..REGISTRATION_SIZE].copy_from_slice(signature);
        Self { data }
    }

    /// Creates and signs a registration transaction.
    ///
    /// The new-key signature is `crypto`'s proof of possession
    /// (`CryptoTrait::prove_possession`, DEC-248): a signature in a domain of its
    /// own over `crypto`'s public key, which is meant to be `new_public_key`. The
    /// transaction signature then signs the complete transaction bytes with the
    /// transaction signature field zero-filled and the new-key signature already
    /// present.
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed<Crypto: CryptoTrait>(
        vote: u32,
        anchor_sequence: u32,
        initializer: u32,
        new_node_id: u32,
        registration_price: u64,
        fee: u64,
        new_public_key: &[u8; PUBLIC_KEY_SIZE],
        crypto: &Crypto,
    ) -> Self {
        let zero_signature = [0u8; SIGNATURE_SIZE];
        let mut tx = Self::new(
            vote,
            anchor_sequence,
            initializer,
            new_node_id,
            registration_price,
            fee,
            new_public_key,
            &zero_signature,
            &zero_signature,
        );
        let new_key_signature = crypto.prove_possession();
        tx.data[REGISTRATION_NEW_KEY_SIGNATURE_OFFSET..REGISTRATION_SIGNATURE_OFFSET]
            .copy_from_slice(new_key_signature.serialize());
        let signature = crypto.sign(&tx.data);
        tx.data[REGISTRATION_SIGNATURE_OFFSET..REGISTRATION_SIZE]
            .copy_from_slice(signature.serialize());
        tx
    }

    /// Returns the serialized transaction bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the canonical transaction hash.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        calculate_hash(&self.data)
    }
}

/// The largest encoded transaction this build can hold (DEC-223).
///
/// A transaction is bounded by the protocol, not by the block: its input and
/// output counts are `u8`, so the largest is a complex transaction with 255
/// balance inputs and 255 UTXO outputs. A block's payload, less its 2-byte
/// transaction count, bounds it further on small tiers. Sizes the
/// [`ComplexTransaction`] builder; not a validity rule.
pub const MAX_TRANSACTION_SIZE: usize = {
    let protocol = TX_HEADER_SIZE + 2 + 255 * BALANCE_INPUT_SIZE + 255 * UTXO_OUTPUT_SIZE;
    let payload = MAX_PAYLOAD_SIZE - 2;
    if protocol < payload {
        protocol
    } else {
        payload
    }
};
// The formula above uses the largest input and output kinds.
const _: () = assert!(BALANCE_INPUT_SIZE >= UTXO_INPUT_SIZE);
const _: () = assert!(UTXO_OUTPUT_SIZE >= BALANCE_OUTPUT_SIZE);
const _: () = assert!(NODE_TRANSFER_SIZE <= MAX_TRANSACTION_SIZE);
const _: () = assert!(REGISTRATION_SIZE <= MAX_TRANSACTION_SIZE);
// The builders' signature offsets and the body sizes are written independently;
// the signature is the last field of both fixed-size transactions.
const _: () = assert!(NODE_TRANSFER_SIGNATURE_OFFSET + SIGNATURE_SIZE == NODE_TRANSFER_SIZE);
const _: () = assert!(REGISTRATION_SIGNATURE_OFFSET + SIGNATURE_SIZE == REGISTRATION_SIZE);
const _: () = assert!(1 + UTXO_INPUT_SIGNATURE_OFFSET + SIGNATURE_SIZE == UTXO_INPUT_SIZE);

/// Owned complex transaction builder for block construction.
///
/// Inputs must be added before outputs.
pub struct ComplexTransaction {
    data: [u8; MAX_TRANSACTION_SIZE],
    len: usize,
    outputs_started: bool,
}

impl ComplexTransaction {
    /// Creates an empty complex transaction with the given vote target.
    pub fn new(vote: u32) -> Self {
        let mut data = [0u8; MAX_TRANSACTION_SIZE];
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
        block_sequence: u32,
        output_index: u16,
        amount: u64,
        signature: &[u8; UTXO_INPUT_SIGNATURE_SIZE],
    ) -> Result<&mut Self, BlockError> {
        if self.outputs_started {
            return Err(BlockError::MalformedBlock(
                "cannot add inputs after outputs",
            ));
        }
        let input_count = self.next_input_count()?;
        let new_len = self.len + UTXO_INPUT_SIZE;
        if new_len > MAX_TRANSACTION_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_TRANSACTION_SIZE,
                actual: new_len,
            });
        }
        let body = self.len + 1;
        self.data[self.len] = INPUT_TYPE_UTXO;
        self.data[body + UTXO_INPUT_BLOCK_SEQUENCE_OFFSET..body + UTXO_INPUT_OUTPUT_INDEX_OFFSET]
            .copy_from_slice(&block_sequence.to_le_bytes());
        self.data[body + UTXO_INPUT_OUTPUT_INDEX_OFFSET..body + UTXO_INPUT_AMOUNT_OFFSET]
            .copy_from_slice(&output_index.to_le_bytes());
        self.data[body + UTXO_INPUT_AMOUNT_OFFSET..body + UTXO_INPUT_SIGNATURE_OFFSET]
            .copy_from_slice(&amount.to_le_bytes());
        self.data[body + UTXO_INPUT_SIGNATURE_OFFSET..body + UTXO_INPUT_BODY_SIZE]
            .copy_from_slice(signature);
        self.data[5] = input_count;
        self.len = new_len;
        Ok(self)
    }

    /// Adds a balance input. Must be called before any output is added.
    pub fn add_balance_input(
        &mut self,
        anchor_sequence: u32,
        initializer: u32,
        amount: u64,
        comment: u64,
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<&mut Self, BlockError> {
        if self.outputs_started {
            return Err(BlockError::MalformedBlock(
                "cannot add inputs after outputs",
            ));
        }
        let input_count = self.next_input_count()?;
        let new_len = self.len + BALANCE_INPUT_SIZE;
        if new_len > MAX_TRANSACTION_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_TRANSACTION_SIZE,
                actual: new_len,
            });
        }
        let p = self.len;
        self.data[p] = INPUT_TYPE_BALANCE;
        self.data[p + 1..p + 5].copy_from_slice(&anchor_sequence.to_le_bytes());
        self.data[p + 5..p + 9].copy_from_slice(&initializer.to_le_bytes());
        self.data[p + 9..p + 17].copy_from_slice(&amount.to_le_bytes());
        self.data[p + 17..p + 25].copy_from_slice(&comment.to_le_bytes());
        self.data[p + 1 + BALANCE_INPUT_SIGNATURE_OFFSET..p + BALANCE_INPUT_SIZE]
            .copy_from_slice(signature);
        self.data[5] = input_count;
        self.len = new_len;
        Ok(self)
    }

    /// Adds a UTXO output.
    pub fn add_utxo_output(
        &mut self,
        address: &[u8; PUBLIC_KEY_SIZE],
        amount: u64,
    ) -> Result<&mut Self, BlockError> {
        let output_count = self.next_output_count()?;
        let new_len = self.len + UTXO_OUTPUT_SIZE;
        if new_len > MAX_TRANSACTION_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_TRANSACTION_SIZE,
                actual: new_len,
            });
        }
        self.outputs_started = true;
        let p = self.len;
        self.data[p] = OUTPUT_TYPE_UTXO;
        self.data[p + 1..p + 1 + PUBLIC_KEY_SIZE].copy_from_slice(address);
        self.data[p + 1 + PUBLIC_KEY_SIZE..p + UTXO_OUTPUT_SIZE]
            .copy_from_slice(&amount.to_le_bytes());
        self.data[6] = output_count;
        self.len = new_len;
        Ok(self)
    }

    /// Adds a balance output.
    pub fn add_balance_output(
        &mut self,
        receiver: u32,
        amount: u64,
    ) -> Result<&mut Self, BlockError> {
        let output_count = self.next_output_count()?;
        let new_len = self.len + BALANCE_OUTPUT_SIZE;
        if new_len > MAX_TRANSACTION_SIZE {
            return Err(BlockError::PayloadTooLarge {
                max: MAX_TRANSACTION_SIZE,
                actual: new_len,
            });
        }
        self.outputs_started = true;
        let p = self.len;
        self.data[p] = OUTPUT_TYPE_BALANCE;
        self.data[p + 1..p + 5].copy_from_slice(&receiver.to_le_bytes());
        self.data[p + 5..p + 13].copy_from_slice(&amount.to_le_bytes());
        self.data[6] = output_count;
        self.len = new_len;
        Ok(self)
    }

    /// Puts `signature` into input `index`'s signature field. A signer builds the
    /// complete transaction first (signature fields zero), takes its
    /// [`TransactionView::input_signing_preimage`], signs it with each input's
    /// key and fills every input with this call (DEC-196, DEC-331).
    pub fn set_input_signature(
        &mut self,
        index: u8,
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<&mut Self, BlockError> {
        const NO_SUCH_INPUT: &str = "no such input";
        if index >= self.data[TX_HEADER_SIZE] {
            return Err(BlockError::MalformedBlock(NO_SUCH_INPUT));
        }
        let tx = &mut self.data[..self.len];
        let mut offset = TX_HEADER_SIZE + 2;
        for _ in 0..index {
            offset += input_layout(tx, offset)
                .ok_or(BlockError::MalformedBlock(NO_SUCH_INPUT))?
                .0;
        }
        let (_, range) =
            input_layout(tx, offset).ok_or(BlockError::MalformedBlock(NO_SUCH_INPUT))?;
        tx[range].copy_from_slice(signature);
        Ok(self)
    }

    /// The input count after one more input. A `u8` per transaction (a protocol
    /// bound of 255), so the 256th input is refused rather than wrapped.
    fn next_input_count(&self) -> Result<u8, BlockError> {
        self.data[5]
            .checked_add(1)
            .ok_or(BlockError::MalformedBlock("too many inputs"))
    }

    /// The output count after one more output; the 256th is refused.
    fn next_output_count(&self) -> Result<u8, BlockError> {
        self.data[6]
            .checked_add(1)
            .ok_or(BlockError::MalformedBlock("too many outputs"))
    }

    /// Returns the serialized transaction bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Returns the canonical transaction hash.
    pub fn hash(&self) -> [u8; HASH_SIZE] {
        calculate_hash(&self.data[..self.len])
    }
}

// =======================================================================
// Helpers
// =======================================================================

/// Structural byte length of a transaction-block payload's content — the
/// declared count walked transaction by transaction, with no reliance on where
/// the caller's slice happens to end.
///
/// Exists so a block read back from durable storage — which arrives zero-padded
/// to a fixed slot with no recorded length — can recover the exact byte sequence
/// that was originally signed (FR59). Returns `None` on any incoherence: a
/// declared count that over-runs the buffer, or an unknown transaction
/// discriminant. It never guesses, and it is deliberately **not** a
/// trailing-zero scan: a payload's last real byte may legitimately be zero.
pub(crate) fn payload_content_len(payload: &[u8]) -> Option<usize> {
    // The 2-byte transaction count, matching `TransactionBlockPayloadView`.
    if payload.len() < 2 {
        return None;
    }
    let count = u16::from_le_bytes([payload[0], payload[1]]);
    let mut offset = 2usize;
    for _ in 0..count {
        // `transaction_size` bounds-checks against the slice it is handed, so
        // the running offset can never pass the end of the payload here.
        let size = transaction_size(payload.get(offset..)?)?;
        offset += size;
    }
    Some(offset)
}

/// Calculates the total byte size of a transaction starting at data[0].
fn transaction_size(data: &[u8]) -> Option<usize> {
    if data.len() < TX_HEADER_SIZE {
        return None;
    }
    match data[0] {
        TX_TYPE_NODE_TRANSFER => {
            let size = TX_HEADER_SIZE + NODE_TRANSFER_BODY_SIZE;
            if data.len() >= size { Some(size) } else { None }
        }
        TX_TYPE_REGISTRATION => {
            let size = TX_HEADER_SIZE + REGISTRATION_BODY_SIZE;
            if data.len() >= size { Some(size) } else { None }
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
    use moonblokz_crypto::{Crypto, CryptoTrait, PRIVATE_KEY_SIZE};
    use moonblokz_crypto::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE};

    fn test_crypto() -> Crypto {
        Crypto::new([1u8; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key should be accepted")
    }

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
            signature: [0; SIGNATURE_SIZE],
        };
        let mut builder = BlockBuilder::new().header(header);
        for tx in transactions {
            builder.add_transaction_bytes(tx).unwrap();
        }
        builder.build_signed(&test_crypto()).unwrap()
    }

    fn make_node_transfer_bytes(
        anchor_seq: u32,
        initializer: u32,
        receiver: u32,
        amount: u64,
        fee: u32,
        comment: u64,
        vote: u32,
    ) -> [u8; NODE_TRANSFER_SIZE] {
        let mut buf = [0u8; NODE_TRANSFER_SIZE];
        buf[0] = TX_TYPE_NODE_TRANSFER;
        buf[1..5].copy_from_slice(&vote.to_le_bytes());
        buf[5..9].copy_from_slice(&anchor_seq.to_le_bytes());
        buf[9..13].copy_from_slice(&initializer.to_le_bytes());
        buf[13..17].copy_from_slice(&receiver.to_le_bytes());
        buf[17..25].copy_from_slice(&amount.to_le_bytes());
        buf[25..29].copy_from_slice(&fee.to_le_bytes());
        buf[29..37].copy_from_slice(&comment.to_le_bytes());
        buf[NODE_TRANSFER_SIGNATURE_OFFSET..].fill(0xAA);
        buf
    }

    // -- View tests --

    #[test]
    fn transaction_view_from_bytes_rejects_malformed_complex() {
        let too_short_for_counts = [TX_TYPE_COMPLEX, 0, 0, 0, 0];
        assert!(TransactionView::from_bytes(&too_short_for_counts).is_none());

        let missing_declared_input = [TX_TYPE_COMPLEX, 0, 0, 0, 0, 1, 0];
        assert!(TransactionView::from_bytes(&missing_declared_input).is_none());

        let valid_empty_complex = ComplexTransaction::new(42);
        assert!(TransactionView::from_bytes(valid_empty_complex.as_bytes()).is_some());
    }

    #[test]
    fn transaction_hash_methods_use_canonical_bytes() {
        let sig = [0xAA; SIGNATURE_SIZE];
        let nt = NodeTransfer::new(99, 10, 1, 2, 1000, 5, 42, &sig);
        let nt_view = TransactionView::from_bytes(nt.as_bytes()).unwrap();
        assert_eq!(nt.hash(), calculate_hash(nt.as_bytes()));
        assert_eq!(nt_view.hash(), nt.hash());

        let public_key = [0xBB; PUBLIC_KEY_SIZE];
        let key_sig = [0xCC; SIGNATURE_SIZE];
        let reg = Registration::new(50, 7, 1, 42, 1000, 10, &public_key, &key_sig, &sig);
        let reg_view = TransactionView::from_bytes(reg.as_bytes()).unwrap();
        assert_eq!(reg.hash(), calculate_hash(reg.as_bytes()));
        assert_eq!(reg_view.hash(), reg.hash());

        let mut complex = ComplexTransaction::new(7);
        complex.add_balance_input(10, 1, 1000, 0, &sig).unwrap();
        complex.add_balance_output(2, 900).unwrap();
        let complex_view = TransactionView::from_bytes(complex.as_bytes()).unwrap();
        assert_eq!(complex.hash(), calculate_hash(complex.as_bytes()));
        assert_eq!(complex_view.hash(), complex.hash());
    }

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
        assert_eq!(nt.signature().len(), SIGNATURE_SIZE);

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
            signature: [0; SIGNATURE_SIZE],
        };
        let block = BlockBuilder::new()
            .header(header)
            .build_signed(&test_crypto())
            .unwrap();
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
        tx_bytes[5..9].copy_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        tx_bytes[9..13].copy_from_slice(&1u32.to_le_bytes());
        tx_bytes[13..17].copy_from_slice(&42u32.to_le_bytes());
        tx_bytes[17..25].copy_from_slice(&1000u64.to_le_bytes());
        tx_bytes[25..33].copy_from_slice(&10u64.to_le_bytes());
        tx_bytes[REGISTRATION_NEW_KEY_OFFSET..REGISTRATION_NEW_KEY_SIGNATURE_OFFSET].fill(0xCC);
        tx_bytes[REGISTRATION_NEW_KEY_SIGNATURE_OFFSET..REGISTRATION_SIGNATURE_OFFSET].fill(0xDD);
        tx_bytes[REGISTRATION_SIGNATURE_OFFSET..].fill(0xEE);

        let block = build_tx_block(&[&tx_bytes[..]]);
        let tx = block.transactions().unwrap().iter().next().unwrap();
        assert_eq!(tx.tx_type(), 2);
        assert_eq!(tx.vote(), 50);

        let reg = tx.as_registration().unwrap();
        assert_eq!(reg.anchor_sequence(), 0xA1B2_C3D4);
        assert_eq!(reg.initializer(), 1);
        assert_eq!(reg.new_node_id(), 42);
        assert_eq!(reg.registration_price(), 1000);
        assert_eq!(reg.fee(), 10);
        assert_eq!(reg.new_public_key(), &[0xCC; PUBLIC_KEY_SIZE]);
        assert_eq!(reg.new_key_signature(), &[0xDD; SIGNATURE_SIZE]);
        assert_eq!(reg.signature(), &[0xEE; SIGNATURE_SIZE]);
    }

    #[test]
    fn complex_view_utxo_round_trip() {
        const LEN: usize = TX_HEADER_SIZE + 2 + UTXO_INPUT_SIZE + UTXO_OUTPUT_SIZE;
        const OUT: usize = TX_HEADER_SIZE + 2 + UTXO_INPUT_SIZE;
        let mut tx_bytes = [0u8; LEN];
        tx_bytes[0] = TX_TYPE_COMPLEX;
        tx_bytes[1..5].copy_from_slice(&77u32.to_le_bytes());
        tx_bytes[5] = 1;
        tx_bytes[6] = 1;
        tx_bytes[7] = INPUT_TYPE_UTXO;
        tx_bytes[8..12].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        tx_bytes[12..14].copy_from_slice(&3u16.to_le_bytes());
        tx_bytes[14..22].copy_from_slice(&5000u64.to_le_bytes());
        tx_bytes[22..OUT].fill(0xCD);
        tx_bytes[OUT] = OUTPUT_TYPE_UTXO;
        tx_bytes[OUT + 1..OUT + 1 + PUBLIC_KEY_SIZE].fill(0xEF);
        tx_bytes[OUT + 1 + PUBLIC_KEY_SIZE..].copy_from_slice(&5000u64.to_le_bytes());

        let block = build_tx_block(&[&tx_bytes[..]]);
        let tx = block.transactions().unwrap().iter().next().unwrap();
        assert_eq!(tx.tx_type(), 3);

        let cx = tx.as_complex().unwrap();
        assert_eq!(cx.input_count(), 1);
        assert_eq!(cx.output_count(), 1);

        let inp = cx.inputs().next().unwrap();
        assert_eq!(inp.input_type(), 0);
        let utxo_in = inp.as_utxo().unwrap();
        assert_eq!(utxo_in.block_sequence(), 0x0102_0304);
        assert_eq!(utxo_in.output_index(), 3);
        assert_eq!(utxo_in.amount(), 5000);
        assert_eq!(utxo_in.signature(), &[0xCD; SIGNATURE_SIZE]);

        let out = cx.outputs().next().unwrap();
        assert_eq!(out.output_type(), 0);
        let utxo_out = out.as_utxo().unwrap();
        assert_eq!(utxo_out.address(), &[0xEF; PUBLIC_KEY_SIZE]);
        assert_eq!(utxo_out.amount(), 5000);
    }

    #[test]
    fn complex_view_balance_io() {
        let mut tx_bytes = [0u8; TX_HEADER_SIZE + 2 + BALANCE_INPUT_SIZE + BALANCE_OUTPUT_SIZE];
        tx_bytes[0] = TX_TYPE_COMPLEX;
        tx_bytes[1..5].copy_from_slice(&0u32.to_le_bytes());
        tx_bytes[5] = 1;
        tx_bytes[6] = 1;
        let mut pos = 7;
        tx_bytes[pos] = INPUT_TYPE_BALANCE;
        pos += 1;
        tx_bytes[pos..pos + 4].copy_from_slice(&100u32.to_le_bytes());
        pos += 4;
        tx_bytes[pos..pos + 4].copy_from_slice(&7u32.to_le_bytes());
        pos += 4;
        tx_bytes[pos..pos + 8].copy_from_slice(&3000u64.to_le_bytes());
        pos += 8;
        tx_bytes[pos..pos + 8].copy_from_slice(&99u64.to_le_bytes());
        pos += 8;
        tx_bytes[pos..pos + SIGNATURE_SIZE].fill(0x11);
        pos += SIGNATURE_SIZE;
        tx_bytes[pos] = OUTPUT_TYPE_BALANCE;
        pos += 1;
        tx_bytes[pos..pos + 4].copy_from_slice(&8u32.to_le_bytes());
        pos += 4;
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
        assert_eq!(bi.signature().len(), SIGNATURE_SIZE);

        let out = cx.outputs().next().unwrap();
        let bo = out.as_balance().unwrap();
        assert_eq!(bo.receiver(), 8);
        assert_eq!(bo.amount(), 2500);
    }

    // -- Builder tests --

    #[test]
    fn node_transfer_builder_round_trip() {
        let sig = [0xAA; SIGNATURE_SIZE];
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
        assert_eq!(nv.signature(), &[0xAA; SIGNATURE_SIZE]);
    }

    #[test]
    fn registration_builder_round_trip() {
        let pub_key = [0xCC; PUBLIC_KEY_SIZE];
        let key_sig = [0xDD; SIGNATURE_SIZE];
        let sig = [0xEE; SIGNATURE_SIZE];
        let reg = Registration::new(50, 0xA1B2_C3D4, 1, 42, 1000, 10, &pub_key, &key_sig, &sig);
        let bytes = reg.as_bytes();
        assert_eq!(bytes.len(), REGISTRATION_SIZE);

        let view = TransactionView { data: bytes };
        assert_eq!(view.tx_type(), 2);
        assert_eq!(view.vote(), 50);
        let rv = view.as_registration().unwrap();
        assert_eq!(rv.anchor_sequence(), 0xA1B2_C3D4);
        assert_eq!(rv.initializer(), 1);
        assert_eq!(rv.new_node_id(), 42);
        assert_eq!(rv.registration_price(), 1000);
        assert_eq!(rv.fee(), 10);
        assert_eq!(rv.new_public_key(), &[0xCC; PUBLIC_KEY_SIZE]);
        assert_eq!(rv.new_key_signature(), &[0xDD; SIGNATURE_SIZE]);
        assert_eq!(rv.signature(), &[0xEE; SIGNATURE_SIZE]);
    }

    #[test]
    fn complex_builder_utxo_round_trip() {
        let mut cx = ComplexTransaction::new(77);
        let in_sig = [0xCD; SIGNATURE_SIZE];
        let address = [0xEF; PUBLIC_KEY_SIZE];
        cx.add_utxo_input(41, 3, 5000, &in_sig).unwrap();
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
        assert_eq!(ui.block_sequence(), 41);
        assert_eq!(ui.output_index(), 3);
        assert_eq!(ui.amount(), 5000);
        assert_eq!(ui.signature(), &[0xCD; SIGNATURE_SIZE]);

        let out = cv.outputs().next().unwrap();
        let uo = out.as_utxo().unwrap();
        assert_eq!(uo.address(), &[0xEF; PUBLIC_KEY_SIZE]);
        assert_eq!(uo.amount(), 5000);
    }

    #[test]
    fn complex_builder_balance_io() {
        let mut cx = ComplexTransaction::new(0);
        let sig = [0x11; SIGNATURE_SIZE];
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
        let address = [0; PUBLIC_KEY_SIZE];
        cx.add_utxo_output(&address, 100).unwrap();

        let sig = [0; SIGNATURE_SIZE];
        let result = cx.add_utxo_input(0, 0, 0, &sig);
        assert!(matches!(result, Err(BlockError::MalformedBlock(_))));
    }

    #[test]
    fn wire_sizes_match_the_story_6_17_table_for_the_built_scheme() {
        // Written down independently of the formulas (Story 6.17 AC1, DEC-251), so a
        // formula error that shows under one scheme only cannot pass: header, node
        // transfer, registration, UTXO input, balance input, UTXO output, node info.
        #[cfg(feature = "schnorr")]
        const EXPECTED: [usize; 7] = [122, 101, 193, 79, 89, 41, 48];
        #[cfg(feature = "bls-min-sig")]
        const EXPECTED: [usize; 7] = [106, 85, 225, 63, 73, 105, 112];
        #[cfg(feature = "bls-min-pk")]
        const EXPECTED: [usize; 7] = [154, 133, 273, 111, 121, 57, 64];
        assert_eq!(
            [
                crate::HEADER_SIZE,
                NODE_TRANSFER_SIZE,
                REGISTRATION_SIZE,
                UTXO_INPUT_SIZE,
                BALANCE_INPUT_SIZE,
                UTXO_OUTPUT_SIZE,
                crate::NODE_INFO_SIZE,
            ],
            EXPECTED
        );
    }

    /// ADR-016 / DEC-131 / DEC-222 wire format: the entry is `type ‖
    /// block_sequence u32 LE ‖ output_index u16 LE ‖ amount u64 LE ‖
    /// signature`, 15 bytes plus the signature with the type byte (79 under Schnorr).
    #[test]
    fn utxo_input_entry_is_15_bytes_plus_the_signature_with_le_sequence_index_and_amount() {
        let mut cx = ComplexTransaction::new(0);
        let sig = [0x77; SIGNATURE_SIZE];
        cx.add_utxo_input(0xA1B2_C3D4, 0x0309, 0x0102_0304_0506_0708, &sig)
            .unwrap();

        let bytes = cx.as_bytes();
        let entry = &bytes[TX_HEADER_SIZE + 2..];
        assert_eq!(entry.len(), 15 + SIGNATURE_SIZE);
        #[cfg(feature = "schnorr")]
        assert_eq!(entry.len(), 79);
        assert_eq!(entry[0], INPUT_TYPE_UTXO);
        assert_eq!(&entry[1..5], &[0xD4, 0xC3, 0xB2, 0xA1]);
        assert_eq!(&entry[5..7], &[0x09, 0x03]);
        assert_eq!(&entry[7..15], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&entry[15..], &sig);

        // An index above `u8` round-trips; the bitfield refuses it later.
        let view = TransactionView { data: bytes };
        let input = view.as_complex().unwrap().inputs().next().unwrap();
        assert_eq!(input.as_utxo().unwrap().output_index(), 0x0309);
    }

    /// Input and output counts are `u8` per transaction: the 256th is refused,
    /// never wrapped to 0.
    #[test]
    fn the_256th_input_and_output_are_refused() {
        let mut cx = ComplexTransaction::new(0);
        cx.data[5] = u8::MAX;
        let input = cx.add_balance_input(1, 1, 1, 0, &[0; SIGNATURE_SIZE]);
        assert!(matches!(
            input,
            Err(BlockError::MalformedBlock("too many inputs"))
        ));
        let utxo = cx.add_utxo_input(1, 0, 1, &[0; SIGNATURE_SIZE]);
        assert!(matches!(
            utxo,
            Err(BlockError::MalformedBlock("too many inputs"))
        ));
        assert_eq!(cx.data[5], u8::MAX);
        assert_eq!(
            cx.as_bytes().len(),
            TX_HEADER_SIZE + 2,
            "nothing was written"
        );

        let mut cx = ComplexTransaction::new(0);
        cx.data[6] = u8::MAX;
        let output = cx.add_balance_output(1, 1);
        assert!(matches!(
            output,
            Err(BlockError::MalformedBlock("too many outputs"))
        ));
        let utxo = cx.add_utxo_output(&[0; PUBLIC_KEY_SIZE], 1);
        assert!(matches!(
            utxo,
            Err(BlockError::MalformedBlock("too many outputs"))
        ));
        assert_eq!(cx.data[6], u8::MAX);
        assert_eq!(
            cx.as_bytes().len(),
            TX_HEADER_SIZE + 2,
            "nothing was written"
        );
    }

    // -- Coverage tests --

    #[test]
    fn complex_mixed_input_types() {
        let mut cx = ComplexTransaction::new(10);
        let utxo_sig = [0xCD; SIGNATURE_SIZE];
        let bal_sig = [0x11; SIGNATURE_SIZE];
        cx.add_utxo_input(9, 0, 800, &utxo_sig).unwrap();
        cx.add_balance_input(50, 3, 1000, 7, &bal_sig).unwrap();
        cx.add_utxo_output(&[0xEF; PUBLIC_KEY_SIZE], 800).unwrap();
        cx.add_balance_output(5, 200).unwrap();

        let bytes = cx.as_bytes();
        let view = TransactionView { data: bytes };
        let cv = view.as_complex().unwrap();
        assert_eq!(cv.input_count(), 2);
        assert_eq!(cv.output_count(), 2);

        let mut inputs = cv.inputs();
        let i1 = inputs.next().unwrap();
        assert_eq!(i1.input_type(), 0);
        assert_eq!(i1.as_utxo().unwrap().block_sequence(), 9);
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
        let sig1 = [0xAA; SIGNATURE_SIZE];
        let sig2 = [0xBB; SIGNATURE_SIZE];
        cx.add_utxo_input(1, 0, 600, &sig1).unwrap();
        cx.add_utxo_input(2, 1, 400, &sig2).unwrap();
        cx.add_balance_output(1, 500).unwrap();
        cx.add_balance_output(2, 300).unwrap();
        cx.add_utxo_output(&[0xCC; PUBLIC_KEY_SIZE], 200).unwrap();

        let bytes = cx.as_bytes();
        let view = TransactionView { data: bytes };
        let cv = view.as_complex().unwrap();
        assert_eq!(cv.input_count(), 2);
        assert_eq!(cv.output_count(), 3);

        let mut inputs = cv.inputs();
        assert_eq!(
            inputs.next().unwrap().as_utxo().unwrap().block_sequence(),
            1
        );
        let second = inputs.next().unwrap().as_utxo().unwrap();
        assert_eq!(second.block_sequence(), 2);
        assert_eq!(second.output_index(), 1);
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

    // ---- DEC-196 input-signature preimage (Story 7.1, DEC-331) ----

    use moonblokz_crypto::PublicKeyTrait;

    fn key(seed: u8) -> Crypto {
        Crypto::new([seed; PRIVATE_KEY_SIZE])
            .ok()
            .expect("test private key should be accepted")
    }

    /// One UTXO input (key 1), one balance input (key 2), one output of each kind.
    fn unsigned_complex() -> ComplexTransaction {
        let zero = [0u8; SIGNATURE_SIZE];
        let mut tx = ComplexTransaction::new(4);
        tx.add_utxo_input(98, 3, 500, &zero).expect("utxo input");
        tx.add_balance_input(10, 7, 200, 9, &zero)
            .expect("balance input");
        tx.add_utxo_output(key(3).public_key().serialize(), 600)
            .expect("utxo output");
        tx.add_balance_output(4, 50).expect("balance output");
        tx
    }

    fn sign_all(tx: &mut ComplexTransaction, keys: &[Crypto]) {
        let mut buf = [0u8; MAX_TRANSACTION_SIZE];
        let preimage_len = {
            let view = TransactionView::from_bytes(tx.as_bytes()).unwrap();
            view.input_signing_preimage(&mut buf).unwrap().len()
        };
        for (i, k) in keys.iter().enumerate() {
            let signature = k.sign(&buf[..preimage_len]);
            tx.set_input_signature(i as u8, signature.serialize())
                .expect("input exists");
        }
    }

    fn verifies(preimage: &[u8], signature: &[u8], signer: &Crypto) -> bool {
        let signature = moonblokz_crypto::Signature::new(signature)
            .ok()
            .expect("well-formed signature bytes");
        signer.verify_signature(preimage, &signature, signer.public_key())
    }

    #[test]
    fn the_input_preimage_is_the_whole_transaction_with_every_input_signature_zeroed() {
        let unsigned = unsigned_complex();
        let mut tx = unsigned_complex();
        sign_all(&mut tx, &[key(1), key(2)]);
        assert_ne!(
            tx.as_bytes(),
            unsigned.as_bytes(),
            "the signatures were filled"
        );

        let view = TransactionView::from_bytes(tx.as_bytes()).unwrap();
        let mut buf = [0u8; MAX_TRANSACTION_SIZE];
        let preimage = view.input_signing_preimage(&mut buf).unwrap();
        // Exactly the unsigned bytes: type, vote, counts, inputs, outputs, with
        // only the two signature fields zero.
        assert_eq!(preimage, unsigned.as_bytes());
        assert_eq!(preimage.len(), tx.as_bytes().len());

        let cx = view.as_complex().unwrap();
        let mut inputs = cx.inputs();
        let utxo = inputs.next().unwrap().as_utxo().unwrap();
        let balance = inputs.next().unwrap().as_balance().unwrap();
        assert!(verifies(preimage, utxo.signature(), &key(1)));
        assert!(verifies(preimage, balance.signature(), &key(2)));
        // Each input verifies only against its own key.
        assert!(!verifies(preimage, utxo.signature(), &key(2)));
        assert!(!verifies(preimage, balance.signature(), &key(1)));
    }

    #[test]
    fn every_input_signature_commits_to_the_vote_and_the_outputs() {
        let mut tx = unsigned_complex();
        sign_all(&mut tx, &[key(1), key(2)]);
        let signed = {
            let mut a = [0u8; MAX_TRANSACTION_SIZE];
            a[..tx.as_bytes().len()].copy_from_slice(tx.as_bytes());
            (a, tx.as_bytes().len())
        };
        // Rewrite the vote (bytes 1..5) and, separately, the last output byte.
        for at in [1usize, signed.1 - 1] {
            let mut bytes = signed.0;
            bytes[at] ^= 1;
            let view = TransactionView::from_bytes(&bytes[..signed.1]).unwrap();
            let mut buf = [0u8; MAX_TRANSACTION_SIZE];
            let preimage = view.input_signing_preimage(&mut buf).unwrap();
            let cx = view.as_complex().unwrap();
            let mut inputs = cx.inputs();
            let utxo = inputs.next().unwrap().as_utxo().unwrap();
            let balance = inputs.next().unwrap().as_balance().unwrap();
            assert!(!verifies(preimage, utxo.signature(), &key(1)));
            assert!(!verifies(preimage, balance.signature(), &key(2)));
        }
    }

    #[test]
    fn the_input_preimage_refuses_a_short_buffer_and_a_non_complex_transaction() {
        let tx = unsigned_complex();
        let view = TransactionView::from_bytes(tx.as_bytes()).unwrap();
        let mut short = [0u8; 8];
        assert!(view.input_signing_preimage(&mut short).is_none());

        let nt = NodeTransfer::new(1, 10, 1, 2, 3, 4, 5, &[0u8; SIGNATURE_SIZE]);
        let nt_view = TransactionView::from_bytes(nt.as_bytes()).unwrap();
        let mut buf = [0u8; MAX_TRANSACTION_SIZE];
        assert!(nt_view.input_signing_preimage(&mut buf).is_none());

        // A zero-input transaction has nothing to zero: its preimage is its bytes.
        let mut empty = ComplexTransaction::new(0);
        empty.add_balance_output(1, 1).expect("output");
        let ev = TransactionView::from_bytes(empty.as_bytes()).unwrap();
        assert_eq!(
            ev.input_signing_preimage(&mut buf).unwrap(),
            empty.as_bytes()
        );
    }

    #[test]
    fn set_input_signature_refuses_a_missing_input() {
        let mut tx = unsigned_complex();
        assert!(tx.set_input_signature(2, &[7u8; SIGNATURE_SIZE]).is_err());
        assert!(tx.set_input_signature(1, &[7u8; SIGNATURE_SIZE]).is_ok());
    }
}
