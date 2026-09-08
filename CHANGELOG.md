# Changelog for singsing-rs

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `singsing-rs` SYN scanning library and `zucchini` Linux command.
- CIDR target, port range, and `/etc/services` parsing.
- Cargo workspace separating the reusable library from the scanner binary.
- `-v`/`--verbose` tagged streaming results and progressively less frequent
  progress statistics with a local date/time ETA, followed by a separate,
  clearly introduced complete buffered output.
- Scanner banner and consistently separated final scan results.
- Clearly separated final `Done:` host/port-pair scan summary.
- Explicit `/31` and `/32` target-handling documentation.

### Changed

- Increased the default response timeout from 3 to 30 seconds.
- Increased the scan limit to 16,777,214 probes so either a single-port IPv4
  `/8` scan or a full-port `/24` scan fits.

## [0.1.1] - TODO

### Added

- TODO

### Changed

- TODO

### Deprecated

- TODO

### Removed

- TODO

### Fixed

- TODO

### Security

- TODO

## [0.1.0] - TODO

- First release to be published to [crates.io](https://crates.io/).

[unreleased]: https://github.com/0xdea/singsing-rs/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/0xdea/singsing-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/0xdea/singsing-rs/releases/tag/v0.1.0
