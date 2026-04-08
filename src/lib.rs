/*! Canonical MoonBlokz chain types crate.

This crate provides immutable block types and validation-focused constructors
for deterministic integration with MoonBlokz storage and chain logic.
*/

#![no_std]

pub mod balance;
pub mod block;
pub mod error;
pub mod hash;
pub mod transaction;

pub use balance::{BalanceBlockPayloadView, BalanceIterator, NODE_INFO_SIZE, NodeInfo, NodeInfoView};
pub use block::{
    Block, BlockBuilder, BlockHeader, HEADER_SIZE, MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE, PAYLOAD_TYPE_APPROVAL, PAYLOAD_TYPE_BALANCE, PAYLOAD_TYPE_CHAIN_CONFIG,
    PAYLOAD_TYPE_TRANSACTION,
};
pub use error::BlockError;
pub use hash::{HASH_SIZE, calculate_hash};
pub use transaction::{
    BalanceInputView, BalanceOutputView, ComplexTransaction, ComplexTransactionView, InputIterator, InputView, NODE_TRANSFER_SIZE, NodeTransfer,
    NodeTransferView, OutputIterator, OutputView, REGISTRATION_SIZE, Registration, RegistrationView, TransactionBlockPayloadView, TransactionIterator,
    TransactionView, UtxoInputView, UtxoOutputView,
};
