# Changelog for singsing-rs

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-27

### Changed

- Change `ScanConfig::bandwidth_kib` to `NonZeroU64`, so a zero bandwidth can no longer be configured (breaking).
- Change `Port` to `NonZeroU16`, so port zero can no longer be scanned via a hand-built `ScanConfig` (breaking).
- Reject a `zucchini` `--timeout` above 86,400 seconds (24 hours) at argument parsing, matching the library's cap.
- Document the late-reply timeout and its bounds.
- Add a message to every test assertion.
- Improve code style.
- Update dependencies.

### Fixed

- Fix a rare receiver hang when a packet was read less than a microsecond before the late-reply deadline.

### Removed

- Remove `ScanError::ZeroBandwidth`, which can no longer occur (breaking).

## [0.1.2] - 2026-09-18

### Changed

- Improve workspace organization and dependency management.
- Improve documentation.

## 0.1.1 - 2026-09-18

### Changed

- Change the name of the binary crate from `zucchini` to `zucchini-scanner`.

### Fixed

- Fix failed doc build in CI and docs.rs.

## 0.1.0 - 2026-09-18

- First release to be published to [crates.io](https://crates.io/).

[unreleased]: https://github.com/0xdea/singsing-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/0xdea/singsing-rs/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/0xdea/singsing-rs/releases/tag/v0.1.2
