# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [Unreleased]

### Added

- Added the chain-config payload envelope: `ChainConfigBlockPayloadView` (content region, node-#0 content signature, entry iteration, derived `content_end`), `ChainConfigPayloadBuilder` (frames an override set and appends the content signature), `ConfigValueView` / `ConfigValueIterator`, the key-byte constants, and `BlockView::chain_config()`. Framing only — the parameter registry and value semantics live in `moonblokz-configuration`.
- Added canonical `hash()` methods on `Block`, `BlockView`, `TransactionView`, `NodeTransfer`, `Registration`, and `ComplexTransaction` so callers can ask typed chain objects for their own hash instead of reimplementing `calculate_hash(object_bytes)` at each use site.

### Changed

- **Breaking wire change (ADR-016):** a UTXO input now references its output as `block_sequence: u32 LE ‖ output_index: u8` instead of `tr_hash: [u8; 32] ‖ output_index: u8`. The entry shrinks from 98 to 70 bytes (type byte included). `output_index` is the position in the referenced block's UTXO-output stream. `UtxoInputView::tr_hash()` is replaced by `block_sequence()`, and `ComplexTransaction::add_utxo_input` takes `(block_sequence, output_index, signature)`. Every complex-transaction and block hash containing a UTXO input changes value.

### Fixed

### Removed

