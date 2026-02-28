# Release Process

This document defines the release workflow for `moonblokz-chain-types`.

## Versioning Policy

- Use SemVer (`MAJOR.MINOR.PATCH`).
- `PATCH`: bug fixes and non-breaking improvements.
- `MINOR`: backward-compatible API additions.
- `MAJOR`: breaking API or binary-layout contract changes.

## Changelog Policy

- Keep `CHANGELOG.md` updated using Keep a Changelog style sections.
- Record user-visible changes in:
- Added
- Changed
- Fixed
- Removed

## Pre-Release Checklist

1. Ensure intended changes are merged to `main`.
2. Update `Cargo.toml` version.
3. Update `CHANGELOG.md` for the target version/date.
4. Run local quality gates:
   - `cargo test`
5. Verify README dependency snippet and docs links.
6. Commit release-prep changes.

## Tagging and GitHub Release

1. Create annotated tag:
   - `git tag -a vX.Y.Z -m "moonblokz-chain-types vX.Y.Z"`
2. Push commit and tag:
   - `git push origin main`
   - `git push origin vX.Y.Z`
3. Create GitHub Release from tag and copy matching changelog section.

## Post-Release

1. Open new `Unreleased` changelog section for the next iteration.
