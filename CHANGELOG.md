# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [Unreleased]

### Added

- Added canonical `hash()` methods on `Block`, `BlockView`, `TransactionView`, `NodeTransfer`, `Registration`, and `ComplexTransaction` so callers can ask typed chain objects for their own hash instead of reimplementing `calculate_hash(object_bytes)` at each use site.

### Changed

### Fixed

### Removed

