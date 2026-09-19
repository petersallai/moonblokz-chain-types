# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [Unreleased]

### Added

- Added the chain-config payload envelope: `ChainConfigBlockPayloadView` (content region, node-#0 content signature, entry iteration, derived `content_end`), `ChainConfigPayloadBuilder` (frames an override set and appends the content signature), `ConfigValueView` / `ConfigValueIterator`, the key-byte constants, and `BlockView::chain_config()`. Framing only — the parameter registry and value semantics live in `moonblokz-configuration`.
- Added canonical `hash()` methods on `Block`, `BlockView`, `TransactionView`, `NodeTransfer`, `Registration`, and `ComplexTransaction` so callers can ask typed chain objects for their own hash instead of reimplementing `calculate_hash(object_bytes)` at each use site.

### Changed

### Fixed

### Removed

