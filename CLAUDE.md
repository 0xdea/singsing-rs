# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`singsing-rs` is a two-crate Cargo workspace implementing a Linux IPv4 SYN port scanner, a Rust reimplementation of the original C `singsing`/`zucca` project by inode.

- `crates/singsing-rs` — library crate: raw-socket SYN scanning engine (`src/lib.rs`, ~1200 lines, single file).
- `crates/zucchini` — binary crate: CLI front-end built on `singsing-rs` (`src/main.rs`).

Scanning raw IPv4/TCP packets requires root or `CAP_NET_RAW` on Linux; most logic (parsing, packet building, response classification) is unprivileged and unit-tested without raw sockets.

## Commands

Build:
```sh
cargo build --workspace --locked
```

Lint (CI runs with `-D warnings`, i.e. all warnings are errors):
```sh
cargo fmt --all --check
cargo clippy --all-targets --workspace --locked -- -D warnings
```

Docs (CI treats rustdoc warnings as errors too):
```sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Unit tests and unprivileged integration tests:
```sh
cargo test --workspace --locked
```

Run a single test:
```sh
cargo test --workspace --locked -- test_name
cargo test -p singsing-rs --locked -- test_name   # scope to one crate
```

Ignored, privileged Linux loopback integration tests (raw sockets against `127.0.0.1`; exercise open/closed ports, callbacks, timeouts, sorting, and full `zucchini` CLI output). They must run serially (concurrent raw receivers can observe each other's packets) and need root/`CAP_NET_RAW`:
```sh
sudo --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME \
  env CARGO_TARGET_DIR=/tmp/singsing-rs-privileged-target \
  cargo test --workspace --locked -- --ignored --test-threads=1
```
Use a separate `CARGO_TARGET_DIR` so root-owned build artifacts don't end up in the repo's normal `target/`. These tests are compiled (not just skipped) during ordinary `cargo test`/CI runs, so API changes that break them are still caught even without running them.

Run the scanner locally (needs privilege, see Configuration below):
```sh
cargo run -p zucchini -- -h 192.0.2.10 -i eth0 -p 21-23,80,443
sudo setcap cap_net_raw=eip "$(command -v zucchini)"   # alternative to running as root
```

CI (`.github/workflows/build.yml`) runs, in order: `cargo fmt --check`, `cargo build`, `cargo clippy -D warnings`, `cargo audit`, `cargo doc -D warnings`, `cargo test`, and `cargo-semver-checks` (semver-checks applies to `singsing-rs` as a published library — avoid breaking its public API without bumping accordingly). A separate `zizmor` job lints GitHub Actions workflows.

## Workspace lint policy

`Cargo.toml` at the workspace root enables `clippy::all`, `pedantic`, `nursery`, `cargo`, and `restriction` at `warn`, with a curated list of `restriction`/other lints explicitly allowed back (see `[workspace.lints.clippy]`). When adding code, expect the full pedantic/nursery/restriction lint surface to apply unless already allowed in that list — don't reflexively silence new warnings with `#[allow]`; check whether the workspace already has an opinion first. `missing_docs` is a warned rustc lint, so public items need doc comments.

## Architecture (`crates/singsing-rs/src/lib.rs`)

Everything lives in one file, organized around a single entry point, `scan`/`scan_with_callback`/`scan_with_callbacks` (`ScanConfig` in, `Vec<ScanResult>` out). Understanding a change usually requires following this pipeline:

1. **Target/port parsing** — `parse_targets` (IPv4/CIDR → `Vec<Ipv4Addr>`, via `ipnet::Ipv4Net`) and `parse_ports` (comma list + inclusive ranges → deduped `Vec<u16>`); `ports_from_services` reads `/etc/services`-style files. A scan is capped at `MAX_PROBES = 16_777_214` host/port pairs (one port on a `/8`, or all 65535 ports on a `/24`); oversized CIDRs are rejected in `parse_targets` before expansion, and `validate_probe_count` re-checks the target×port product before a scan starts.
2. **Setup** — `scan_with_callbacks` picks a random ephemeral `source_port` (49152–65535) and a per-scan `nonce`, then builds an `expected: HashMap<(Ipv4Addr, u16), u32>` mapping each target host/port to a deterministic expected TCP sequence number (`sequence()`, derived from host/port/nonce). Duplicate target/port pairs are rejected here (`expected_responses`), not silently deduped, since duplicates would corrupt progress/probe counts.
3. **Concurrency model** — one `pnet` Layer-3 raw socket (`transport_channel`) is split into a sender used on the calling thread and a receiver moved into a spawned thread running `receive()`. An `Arc<AtomicBool>` (`done`) signals the receiver that sending has finished; the receiver then waits `config.timeout` more for late replies before returning. Results only flow back after `receive_thread.join()`.
4. **Sending** — the send loop builds a 40-byte raw SYN packet per pair (`syn_packet`: fixed IPv4+TCP headers, no payload, TTL 64, window 64240, IP ID derived from the sequence), paces transmission to `config.bandwidth_kib` KiB/s via an absolute per-packet deadline (no calibration traffic, unlike the original C `singsing`), and fires `on_progress` on a growing schedule (`ONE_MINUTE` → `TEN_MINUTES` after 10 min → `THIRTY_MINUTES` after 1 hour; see `next_progress_deadline`/`advance_progress_deadline`). A send error mid-scan does not abort silently: it's captured and surfaced as `IncompleteScanError` (with partial results and counts) after the receiver is still allowed to finish and results are sorted.
5. **Receiving/classification** — `classify_response` is the correlation core: a reply is only accepted if destination matches the scan's source address/port, the source host/port matches an actual probe key in `expected`, and the acknowledgement number equals `sequence.wrapping_add(1)` (stricter than the original C implementation, which trusted TCP flags plus a destination-port range). SYN/ACK → `PortState::Open`; RST/RST+ACK → `PortState::Closed` only if `show_closed` is set. A `seen: HashSet<(Ipv4Addr, u16)>` suppresses duplicate results per host/port.
6. **Results** — sorted by `(host, port)` before returning, regardless of arrival order, so both library callers and `zucchini`'s buffered output are deterministic; `on_result` callbacks fire in raw arrival order for live/verbose feedback independent of that final sort.

Host/port storage is a `HashMap` with unspecified (randomized) iteration order — deliberate, to interleave scan order across hosts/ports and avoid an obvious sequential pattern (unlike the original's deterministic bandwidth-derived stride).

Memory scales with total host×port pairs, not just responses received, since the full `expected` table and target/port vectors are built up front rather than generated incrementally.

## `crates/zucchini/src/main.rs`

Thin CLI layer over the library: `clap`-derived `Arguments` → `ScanConfig`, plus banner/progress/result formatting (`write_banner_to`, `write_scan_summary`, `format_progress`, `write_result_to`) that are unit-tested by writing to an in-memory `Vec<u8>` buffer rather than real stdout/stderr, so tests can assert exact output text without process-level capture. `format_progress` takes a generic `DateTime<Tz>` "now" so tests can inject a fixed time instead of `Local::now()`. On `IncompleteScanError`, `main` still prints whatever partial results were gathered before returning the error (non-zero exit).

## Notes

- Target platform is Linux only (raw socket behavior is Linux-specific); no macOS/Windows support currently (see README TODO).
- `singsing-rs` and `zucchini` are published, versioned crates (crates.io); public API changes to `singsing-rs` are checked by `cargo-semver-checks` in CI.
- `#![doc = include_str!("../../../README.md")]` in `lib.rs` embeds the workspace README into the published rustdoc — keep README changes rustdoc-safe (valid Markdown, doc-warning-free) since `cargo doc -D warnings` runs in CI.
