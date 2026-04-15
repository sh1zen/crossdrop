# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic Versioning.

## [0.1.1]

### Added

- Added auto discover on local network

## [0.1.0]

### Fixed

- GitHub Actions Linux workflows now install required X11 system libraries for crates that depend on `x11` via `pkg-config`.
- Added this changelog so release automation can populate release notes from `CHANGELOG.md`.

## [0.0.1] - 2026-02-27

### Added

- Initial public release of `crossdrop`.
- Terminal UI built with Ratatui and Crossterm.
- Peer-to-peer file transfer foundation with WebRTC and Iroh integration.
- Logging, configuration, and packaging metadata for multi-platform builds.
