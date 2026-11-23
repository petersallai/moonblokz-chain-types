/*! Canonical MoonBlokz chain types crate.

This crate provides immutable block types and validation-focused constructors
for deterministic integration with MoonBlokz storage and chain logic.
*/

#![no_std]

// Exactly one signature scheme (DEC-246); the crypto crate enforces the same rule.
#[cfg(not(any(feature = "schnorr", feature = "bls-min-sig", feature = "bls-min-pk")))]
compile_error!(
    "moonblokz-chain-types requires one signature-scheme feature: keep the default `schnorr`, or choose `bls-min-sig` / `bls-min-pk` with `default-features = false`"
);

// Exactly one block-size tier: the build's block capacity (DEC-220). It is a
// property of the whole binary, so every crate above forwards the same feature.
#[cfg(not(any(feature = "block-size-2016", feature = "block-size-65536")))]
compile_error!(
    "moonblokz-chain-types requires exactly one block-size tier feature; keep the default `block-size-2016`, or choose another with `default-features = false`"
);

#[cfg(all(feature = "block-size-2016", feature = "block-size-65536"))]
compile_error!(
    "moonblokz-chain-types requires exactly one block-size tier feature; disable default features when selecting another tier"
);

pub mod balance;
pub mod block;
pub mod chain_config;
pub mod error;
pub mod hash;
pub mod transaction;

// The wire layouts are derived from the scheme's sizes (DEC-251): every signature- and
// key-sized field, and every offset after one, is computed from these constants. A
// support or evidence contribution is a `MultiSignature`, the same size as a signature
// in every scheme, which the layouts rely on.
const _: () = assert!(moonblokz_crypto::MULTI_SIGNATURE_SIZE == moonblokz_crypto::SIGNATURE_SIZE);

/// The scheme's wire sizes, re-exported for crates that frame chain data without a
/// crypto dependency of their own (DEC-251).
pub use moonblokz_crypto::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE};

pub use balance::{
    BalanceBlockPayloadView, BalanceIterator, NODE_INFO_SIZE, NodeInfo, NodeInfoView,
};
pub use block::{
    APPROVAL_DEVIATION_SEQUENCE_OFFSET, APPROVAL_LATE_COUNT_SIZE, APPROVAL_LATE_ENTRY_SIZE,
    APPROVAL_M_OFFSET, APPROVAL_MAX_SUBGROUP, APPROVAL_PREFIX_SIZE,
    APPROVAL_SUPPORTER_VOTE_SUM_OFFSET, ApprovalView, Block, BlockBuilder, BlockHeader, BlockView,
    HEADER_SIZE, MAX_BLOCK_SIZE, MAX_PAYLOAD_SIZE, PAYLOAD_TYPE_APPROVAL, PAYLOAD_TYPE_BALANCE,
    PAYLOAD_TYPE_CHAIN_CONFIG, PAYLOAD_TYPE_TRANSACTION, PAYLOAD_TYPE_TWIN_FACT,
    TWIN_FACT_PREFIX_SIZE, TwinFactView, approval_fixed_size, twin_fact_size,
};
pub use chain_config::{
    CONFIG_KEY_BYTECODE_FLAG, CONFIG_PARAMETER_ID_MAX, CONFIG_VALUE_COUNT_SIZE,
    ChainConfigBlockPayloadView, ChainConfigPayloadBuilder, ConfigValueIterator, ConfigValueView,
};
pub use error::BlockError;
pub use hash::{HASH_SIZE, calculate_hash};
pub use transaction::{
    BalanceInputView, BalanceOutputView, ComplexTransaction, ComplexTransactionView, InputIterator,
    InputView, MAX_TRANSACTION_SIZE, NODE_TRANSFER_SIZE, NodeTransfer, NodeTransferView,
    OutputIterator, OutputView, REGISTRATION_SIZE, Registration, RegistrationView,
    TransactionBlockPayloadView, TransactionIterator, TransactionView, UtxoInputView,
    UtxoOutputView,
};
