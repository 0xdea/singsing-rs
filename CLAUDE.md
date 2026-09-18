# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

`singsing-rs` is a two-crate Cargo workspace implementing a Linux IPv4 SYN port scanner, a Rust reimplementation of the original C `singsing`/`zucca` project by inode.

- `crates/singsing-rs` — library crate: raw-socket SYN scanning engine (`src/lib.rs`).
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

Unit tests, unprivileged integration tests, and `singsing-rs`'s doc examples (run as doctests):

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
cargo run -p zucchini -- -i eth0 -h 192.168.2.10 -p 21-23,80,443
sudo setcap cap_net_raw=eip "$(command -v zucchini)"   # alternative to running as root
```

CI (`.github/workflows/build.yml`) runs, in order: `cargo fmt --check`, `cargo build`, `cargo clippy -D warnings`, `cargo audit`, `cargo doc -D warnings`, `cargo test`, and `cargo-semver-checks` (semver-checks applies to `singsing-rs` as a published library — avoid breaking its public API without bumping accordingly). A separate `zizmor` job lints GitHub Actions workflows.

## Workspace lint policy

`Cargo.toml` at the workspace root enables `clippy::all`, `pedantic`, `nursery`, `cargo`, and `restriction` at `warn`, with a curated list of `restriction`/other lints explicitly allowed back (see `[workspace.lints.clippy]`). When adding code, expect the full pedantic/nursery/restriction lint surface to apply unless already allowed in that list — don't reflexively silence new warnings with `#[allow]`; check whether the workspace already has an opinion first. `missing_docs` is a warned rustc lint, so public items need doc comments. `elided_lifetimes_in_paths` is also warned, so a type usage that elides a struct/enum's own lifetime parameter (e.g. `ReceiveConfig`, `Ipv4Packet`) must write it as `<'_>` (e.g. `&ReceiveConfig<'_>`) rather than omitting it entirely. Two more `rust_2018_idioms` members are warned alongside it: `bare_trait_objects` (a trait object must be written `dyn Trait`, never bare `Trait`) and `explicit_outlives_requirements` (its mirror image — drop a lifetime-outlives bound like `T: 'a` on a generic type when the compiler already infers it, rather than spelling out a redundant one). The other two `rust_2018_idioms` members (`unused_extern_crates`, `ellipsis_inclusive_range_patterns`) and the edition-transition groups `rust_2021_compatibility`/`rust_2024_compatibility` are deliberately not enabled — the former two have nothing to check in an edition-2024 codebase with no `extern crate` items or `...` range patterns, and the latter two are one-shot `cargo fix --edition` migration aids, not lints meant to stay on permanently.

Two different suppression mechanisms are used deliberately, not interchangeably: a workspace-level `= "allow"` entry in `Cargo.toml` is for lints considered broadly noisy across the whole codebase (e.g. `shadow_reuse`, `arithmetic_side_effects`, `integer_division`, `integer_division_remainder_used`, `pattern_type_mismatch` — the last because it directly conflicts with `ref_patterns`/`needless_borrowed_reference`, which this codebase relies on throughout via ordinary match ergonomics); a function/statement-level `#[expect(clippy::LINT, reason = "...")]` is for lints kept live everywhere else but locally justified at one call site (e.g. `expect_used` in `syn_packet` on the provably-infallible fixed-size packet construction, `as_conversions` on provably-lossless truncating casts, `iter_over_hash_type` on the deliberately-randomized send loop). When a new lint fires, decide which bucket it belongs in rather than defaulting to either one.

## Architecture (`crates/singsing-rs/src/lib.rs`)

Everything lives in one file, organized around a single entry point, `scan`/`scan_with_callback`/`scan_with_callbacks` (`ScanConfig` in, `Vec<ScanResult>` out). Understanding a change usually requires following this pipeline:

1. **Target/port parsing** — `parse_targets` (IPv4/CIDR → `Vec<Ipv4Addr>`, via `ipnet::Ipv4Net`) and `parse_ports` (comma list + inclusive ranges → deduped, ascending-sorted `Vec<Port>` via a `BTreeSet`); `ports_from_services` reads `/etc/services`-style files the same way. A scan is capped at `MAX_PROBES = 16_777_214` host/port pairs (one port on a `/8`, or all 65535 ports on a `/24`); oversized CIDRs are rejected in `parse_targets` before expansion, and `validate_probe_count` re-checks the target×port product before a scan starts. `validate_probe_count` also rejects zero bandwidth and `timeout > MAX_TIMEOUT` (24 hours) up front — the timeout cap exists specifically so `Instant::now() + config.timeout` in `receive()` can never overflow `Instant`'s range and panic (`Instant`'s `Add<Duration>` is unchecked and panics on overflow, unlike everything else in this pipeline, which returns a typed error). `bandwidth_kib` deliberately has no analogous upper sanity cap, only the `ScanError::BandwidthOverflow` guard on the `× 1024` conversion to bytes/s in `scan_with_callbacks` (~`u64::MAX / 1024` KiB/s) — an extreme-but-non-overflowing value just drives the packets-per-second→interval division to floor to `Duration::ZERO`, so the send loop never sleeps and sending is effectively unthrottled rather than panicking or misbehaving, so a cap wasn't worth adding.
2. **Setup** — `scan_with_callbacks` picks a random ephemeral `source_port` (49152–65535) and a per-scan `nonce`, then builds an `expected: ExpectedResponses` (`HashMap<(Ipv4Addr, Port), SeqNum>`) mapping each target host/port to a deterministic expected TCP sequence number (`sequence()`, derived from host/port/nonce). Duplicate target/port pairs are rejected here (`expected_responses`), not silently deduped like the parsing step above, since duplicates at this stage would corrupt progress/probe counts; `expected`'s `HashMap` is also deliberately kept unordered/randomized (see Workspace lint policy) rather than sorted like `parse_ports`, since this is the table that determines send order.
3. **Concurrency model** — one `pnet` Layer-3 raw socket (`transport_channel`) is split into a sender used on the calling thread and a receiver moved into a spawned thread running `receive()`. An `Arc<AtomicBool>` (`done`) signals the receiver that sending has finished; the receiver then waits `config.timeout` more for late replies before returning. Results only flow back after `receive_thread.join()`.
4. **Sending** — the send loop builds a 40-byte raw SYN packet per pair (`syn_packet`: fixed IPv4+TCP headers, no payload, TTL 64, window 64240, IP ID derived from the sequence), paces transmission to `config.bandwidth_kib` KiB/s via an absolute per-packet deadline (no calibration traffic, unlike the original C `singsing`), and fires `on_progress` on a growing schedule (`ONE_MINUTE` → `TEN_MINUTES` after 10 min → `THIRTY_MINUTES` after 1 hour; see `next_progress_deadline`/`advance_progress_deadline`). A send error mid-scan does not abort silently: it's captured as a `SendError` and surfaced as `ScanError::Incomplete(IncompleteScanError)` (with partial results and counts) after the receiver is still allowed to finish and results are sorted. A failing `on_progress` is treated identically to a real send/packet-construction failure — it stops the send loop and is preserved as `SendError::Callback` inside that same `IncompleteScanError`, unlike a failing `on_result` on the receive side (see point 5), which discards `results` entirely instead.
5. **Receiving/classification** — `classify_response` is the correlation core: a reply is only accepted if destination matches the scan's source address/port, the source host/port matches an actual probe key in `expected`, and the acknowledgement number equals `sequence.wrapping_add(1)` (stricter than the original C implementation, which trusted TCP flags plus a destination-port range). SYN/ACK → `PortState::Open`; RST/RST+ACK → `PortState::Closed` only if `show_closed` is set. A `seen: HashSet<(Ipv4Addr, Port)>` suppresses duplicate results per host/port. `receive()` calls `on_result` before appending to its local `results`, but this is not the send-loop's partial-results pattern: a failing `on_result` returns `ScanError::Callback` and discards `results` entirely, unlike a send-loop failure, which preserves whatever was gathered via `IncompleteScanError` — there's no equivalent preservation on the receive side.
6. **Results** — sorted by `(host, port)` before returning, regardless of arrival order, so both library callers and `zucchini`'s buffered output are deterministic; `on_result` callbacks fire in raw arrival order for live/verbose feedback independent of that final sort.

Host/port storage is a `HashMap` with unspecified (randomized) iteration order — deliberate, to interleave scan order across hosts/ports and avoid an obvious sequential pattern (unlike the original's deterministic bandwidth-derived stride).

Memory scales with total host×port pairs, not just responses received, since the full `expected` table and target/port vectors are built up front rather than generated incrementally.

Public data structs (`ScanConfig`, `ScanResult`, `ScanProgress`) are all `#[non_exhaustive]` with a `::new()` constructor, even though every field is `pub` and freely settable afterward — this keeps adding a field to any of them a non-breaking change. New public structs should follow the same shape; `IncompleteScanError` doesn't need it since all its fields are already private.

**Errors are typed, not `anyhow`.** `singsing-rs` is a published library other crates may depend on, so its public functions return `thiserror`-derived, `#[non_exhaustive]` error enums instead of `anyhow::Result`, letting callers `match` on a specific failure instead of downcasting or parsing message text: `InterfaceError` (`interface_ipv4`), `TargetsError` (`parse_targets`), `PortsError` (`parse_ports`/`ports_from_services`), and `ScanError` (`scan`/`scan_with_callback`/`scan_with_callbacks`). `SendError` is the narrower error type specific to the send loop, used only as `IncompleteScanError`'s private `source` field (not as a function return type) — it's kept separate from `ScanError` rather than reused there to avoid a `ScanError::Incomplete(IncompleteScanError)` ↔ `IncompleteScanError.source: ScanError` cycle. Both `on_result` and `on_progress` callbacks are caller-defined and can fail for reasons the library can't enumerate in advance, so their error type is the opaque, public `CallbackError` (`Box<dyn std::error::Error + Send + Sync>`), surfaced as `SendError::Callback` (progress callback, folded into `IncompleteScanError` since it stops the send loop) or `ScanError::Callback` (result callback, on the receiver thread). `anyhow` is deliberately _not_ a `singsing-rs` runtime dependency any more — only a `[dev-dependencies]` entry for convenient `?`-based test code — since `anyhow`'s own guidance reserves it for application code; `zucchini`, the binary crate, is where `anyhow` still belongs, converting the library's typed errors at the boundary (see `to_boxed_error` in `main.rs`).

**Type aliases exist for repeated or semantically-named shapes, not every primitive.** `Port` (`u16`) and `SeqNum` (`u32`) name the two dominant meanings of those primitives in this file; `ExpectedResponses` (`HashMap<(Ipv4Addr, Port), SeqNum>`) and `CallbackError` (`Box<dyn std::error::Error + Send + Sync>`) collapse types that were previously spelled out verbatim at several call sites. Since a type alias is fully transparent (not a newtype), introducing or extending one is never a breaking change and needs no conversions at any call site — including across the `pnet` boundary, where `syn_packet`/`classify_response` still pass `Port`/`SeqNum` values directly into `pnet`'s own raw `u16`/`u32` APIs. Only `Port` and `CallbackError` are `pub`: `CallbackError` appears directly in public signatures (`scan_with_callback`/`scan_with_callbacks`'s callback bounds, `SendError`/`ScanError::Callback`), and `Port` was extended to every public port-shaped field (`ScanConfig.ports`, `ScanResult.port`, `ScanError::DuplicatePair.port`, `SendError::Io.port`, `parse_ports`/`ports_from_services`'s return types, and `zucchini`'s `Ports` newtype) once established, so it now reads consistently end-to-end and gets its own linked doc entry on docs.rs instead of a bare `u16` repeated at every occurrence. `SeqNum` and `ExpectedResponses` stay private: no public item ever holds a raw sequence number or the expected-response table itself, so there's no public signature for a `pub` alias to actually reach — publicizing either would only add unreachable, unlinked entries to the public API (and, for `ExpectedResponses`, needless `cargo-semver-checks` surface over what's really an internal implementation detail).

## `crates/zucchini/src/main.rs`

Thin CLI layer over the library: `clap`-derived `Arguments` → `ScanConfig`.

- **Argument parsing is pushed into clap itself**, not validated after the fact in `run()`. `host`/`ports` parse directly into `Targets`/`Ports` newtypes (each wrapping `Vec<Ipv4Addr>`/`Vec<Port>`) via `FromStr` impls that delegate to `parse_targets`/`parse_ports`; the newtype wrapping exists because clap's derive otherwise treats a bare `Vec<...>`-shaped field as "one value per occurrence" rather than "one occurrence that parses into a `Vec`," causing a runtime type-downcast panic. `bandwidth`/`timeout` use `value_parser = clap::value_parser!(u64).range(1..)` so out-of-range values are rejected by clap before `run()` runs at all. `-h` is reserved for `--host` (matching the original `zucca`'s flag), so the default help flag is disabled (`disable_help_flag = true`) and manually re-added as a long-only `--help`; `-V`/`--version` is deliberately absent (no `version` attribute, and `about = None` suppresses the struct doc comment from leaking into `--help` output).
- **Every output concern follows the same two-function pattern**: a pure `write_x_to(output: &mut impl Write, ...)` that does the actual formatting (unit-tested by writing into a `Vec<u8>`, so tests assert exact text without touching real stdout/stderr), plus an impure `write_x(...)` wrapper that locks the real stream, delegates, and flushes when the output needs to be visible before the next blocking step (banner, scan summary, each progress tick, and verbose per-result lines all flush explicitly; the final buffered `write_results` doesn't, since it's the last stdout write before a normal process exit). `format_progress` is the one exception to the naming pattern: its only source of non-determinism is the injected `now: DateTime<Tz>`, not the output stream, so it returns a `String` directly instead of writing anywhere.
- **stderr carries status, stdout carries data**: the banner, scan summary, progress ticks, and done summary all go to stderr; only verbose per-result lines and the final `Scan results:` block go to stdout — so redirecting stdout captures just the scan output, not diagnostic/status text.
- **Exit codes are meaningful**: clap usage errors (missing/invalid arguments) exit 2, `run()`-level `anyhow` errors (e.g. an unknown interface) exit 1 via `ExitCode::FAILURE`, and `--help` exits 0. On `ScanError::Incomplete`, `main` prints how far sending got (`write_incomplete_summary`, using `IncompleteScanError::probes_sent`/`::total_probes`) and whatever partial results were gathered (via the `IncompleteScanError` payload) before returning the error (exit 1). `singsing-rs`'s typed errors (`TargetsError`, `PortsError`, `ScanError`, ...) convert into `anyhow::Error` via `?` at every call site; the one place conversion runs the other way is `to_boxed_error`, which adapts a `write_*` helper's `anyhow::Result` into the `CallbackError` the library's `on_result`/`on_progress` callbacks expect.

## Notes

- Target platform is Linux only; `crates/singsing-rs/src/lib.rs` enforces this with `#[cfg(not(target_os = "linux"))] compile_error!(...)` right after the crate doc attributes, so non-Linux builds fail immediately rather than compiling against `pnet`'s cross-platform raw-socket support and risking silently wrong packet behavior (e.g. BSD/macOS raw sockets have different `IP_HDRINCL` byte-order semantics than Linux). No macOS/Windows support currently (see README TODO) — that guard is the first thing to touch if this is ever ported.
- `singsing-rs` and `zucchini` are published, versioned crates (crates.io); public API changes to `singsing-rs` are checked by `cargo-semver-checks` in CI.
- `#![doc = include_str!("../../../README.md")]` in `lib.rs` embeds the workspace README into the published rustdoc — keep README changes rustdoc-safe (valid Markdown, doc-warning-free) since `cargo doc -D warnings` runs in CI.
- Relevant public items in `crates/singsing-rs/src/lib.rs` have a `# Examples` doc section, run as a doctest by `cargo test --workspace`. Examples that need root/`CAP_NET_RAW` or a live network (`scan`, `scan_with_callback`, `scan_with_callbacks`, and `IncompleteScanError`'s example, which needs an actual failed scan to produce one) are marked ` ```no_run ` — still compiled every run to catch API drift, just not executed. Every other example runs for real, including ones that touch the filesystem or a real interface (`interface_ipv4`'s example resolves `lo`; `ports_from_services`'s writes, reads, and removes a real temp file). New public items should follow the same pattern unless there's nothing of value to demonstrate (e.g. the bare `Port` type alias has none).
