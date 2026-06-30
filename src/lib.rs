/*! Canonical MoonBlokz chain types crate.

This crate provides immutable block types and validation-focused constructors
for deterministic integration with MoonBlokz storage and chain logic.
*/

#![no_std]

#[cfg(not(any(
    feature = "schnorr-crypto-bigint",
    feature = "schnorr-malachite",
    feature = "schnorr-num-bigint-dig"
)))]
compile_error!(
    "moonblokz-chain-types requires exactly one Schnorr backend feature; keep the default `schnorr-crypto-bigint`, or choose an alternate with `default-features = false`"
);

#[cfg(any(
    all(feature = "schnorr-crypto-bigint", feature = "schnorr-malachite"),
    all(feature = "schnorr-crypto-bigint", feature = "schnorr-num-bigint-dig"),
    all(feature = "schnorr-malachite", feature = "schnorr-num-bigint-dig")
))]
compile_error!(
    "moonblokz-chain-types requires exactly one Schnorr backend feature; disable default features when selecting an alternate backend"
);

pub mod balance;
pub mod block;
pub mod error;
pub mod hash;
pub mod transaction;

// Current chain wire types are Schnorr-shaped: 64-byte signatures and
// 32-byte public keys. If a future crypto backend changes these dimensions,
// the wire layout must be changed deliberately instead of silently truncating
// or padding serialized crypto artifacts.
const _: () = assert!(moonblokz_crypto::SIGNATURE_SIZE == 64);
const _: () = assert!(moonblokz_crypto::PUBLIC_KEY_SIZE == 32);

pub use balance::{
    BalanceBlockPayloadView, BalanceIterator, NODE_INFO_SIZE, NodeInfo, NodeInfoView,
};
pub use block::{
    Block, BlockBuilder, BlockHeader, BlockView, HEADER_SIZE, MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE,
    PAYLOAD_TYPE_APPROVAL, PAYLOAD_TYPE_BALANCE, PAYLOAD_TYPE_CHAIN_CONFIG,
    PAYLOAD_TYPE_TRANSACTION,
};
pub use error::BlockError;
pub use hash::{HASH_SIZE, calculate_hash};
pub use transaction::{
    BalanceInputView, BalanceOutputView, ComplexTransaction, ComplexTransactionView, InputIterator,
    InputView, NODE_TRANSFER_SIZE, NodeTransfer, NodeTransferView, OutputIterator, OutputView,
    REGISTRATION_SIZE, Registration, RegistrationView, TransactionBlockPayloadView,
    TransactionIterator, TransactionView, UtxoInputView, UtxoOutputView,
};
