# singsing-rs

[![](https://img.shields.io/github/stars/0xdea/singsing-rs.svg?style=flat&color=yellow)](https://github.com/0xdea/singsing-rs)
[![](https://img.shields.io/crates/v/singsing-rs?style=flat&color=green&label=singsing-rs)](https://crates.io/crates/singsing-rs)
[![](https://img.shields.io/crates/v/zucchini?style=flat&color=red&label=zucchini)](https://crates.io/crates/zucchini)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)
[![build](https://github.com/0xdea/singsing-rs/actions/workflows/build.yml/badge.svg)](https://github.com/0xdea/singsing-rs/actions/workflows/build.yml)

> "Then, we got a modem."
>
> -- [Matt Harrigan](https://wherewarlocksstayuplate.com/interview/episode-1-digital-jesus-aka-matt-harrigan/)

The [`singsing-rs`](https://github.com/0xdea/singsing-rs/tree/master/crates/singsing-rs) library crate is a modern Rust reimplementation of the original [`singsing`](https://github.com/inode-/singsing) project by my old friend and longtime packet wizard [inode](https://github.com/inode-). It's a blazing fast ⚡️ Linux IPv4 port scanning library.

The [`zucchini`](https://github.com/0xdea/singsing-rs/tree/master/crates/zucchini) binary crate is a standalone command-line port scanner based on `singsing-rs`, inspired by the original
[`zucca`](https://github.com/inode-/singsing/blob/master/src/examples/zucca.c) scanner from the `singsing` project.

![](https://raw.githubusercontent.com/0xdea/singsing-rs/master/.img/screen01.png)

## How it works

The scanner creates raw IPv4/TCP packets, sends bandwidth-limited SYN probes, and asynchronously validates response acknowledgement numbers before reporting SYN/ACK responses as open or, optionally, RST responses as closed. Target hosts that do not reply are treated as filtered or unreachable and are not printed in the output.

> [!NOTE]
> Creating the raw transport socket requires root or the `CAP_NET_RAW` capability.

See [below](https://github.com/0xdea/singsing-rs#implementation-details) for the main differences from the original `singsing` and other implementation details.

## Features

- Support for IPv4 hosts and CIDR ranges to scan.
- Support for comma-separated ports and inclusive port ranges to scan.
- Support for TCP ports from `/etc/services` if target ports are not specified.
- Optional reporting of closed ports.
- Configurable bandwidth and response timeout.
- Progress statistics printed while scanning.
- Immediate per-result feedback with `-v`/`--verbose`.
- Partial results preserved when probe transmission fails.

## See also

- <https://github.com/inode-/singsing>
- <https://github.com/inode-/singsing/blob/master/src/examples/zucca.c>

## Installing

Install the latest release of the scanner from [crates.io](https://crates.io/crates/zucchini):

```sh
cargo install zucchini --locked
```

To use the scanning library in another Rust project:

```sh
cargo add singsing-rs
```

## Compiling

Alternatively, you can build from [source](https://github.com/0xdea/singsing-rs):

```sh
git clone https://github.com/0xdea/singsing-rs
cd singsing-rs
cargo build --release --locked
```

## Configuration

The `zucchini` scanner uses a raw transport socket. Either run it as root, or grant the installed binary only the capability it needs:

```sh
sudo setcap cap_net_raw=eip "$(command -v zucchini)"
```

Choose an interface with `-i`/`--interface` whose IPv4 address can route to the targets. You can list available interfaces with `ip -brief address`.

## Usage

> [!WARNING]
> Only scan systems you own or have explicit permission to test.

Scan selected ports on one host:

```sh
zucchini -h 192.168.2.10 -i eth0 -p 21-23,80,443
```

Scan all ports on a `/24` subnet, including closed ports:

```sh
zucchini -h 192.168.2.0/24 -i eth0 -p 1-65535 -c
```

Scan one port on a `/8` subnet, increasing the send rate bandwidth to 40 KiB/s:

```sh
zucchini -h 192.168.0.0/8 -i eth0 -p 22 -b 40
```

Scan TCP port entries from `/etc/services` on one host and wait only five seconds for late replies:

```sh
zucchini -h 192.168.2.10 -i eth0 -t 5
```

Progress statistics with a local date/time ETA are printed every minute for the first ten minutes, every ten minutes through the first hour, and every thirty minutes thereafter. Use `-v`/`--verbose` to additionally print responses as soon as they arrive. The complete sorted results are always printed under a separate `Scan results:` heading when the scan finishes:

```sh
zucchini -h 192.168.2.0/24 -i eth0 -p 22,80,443 -v
```

Run `zucchini --help` for the complete command-line reference.

Library users can construct a [`ScanConfig`](https://docs.rs/singsing-rs/latest/singsing_rs/struct.ScanConfig.html)
and call [`scan`](https://docs.rs/singsing-rs/latest/singsing_rs/fn.scan.html). See the [API documentation](https://docs.rs/singsing-rs/latest/singsing_rs/) for more details.

## Testing

Run the unit tests and unprivileged integration tests normally:

```sh
cargo test --workspace --locked
```

Ignored Linux loopback integration tests exercise live raw-socket scanning, open and closed ports, callbacks, timeout handling, sorting, and complete `zucchini` output. They require root or `CAP_NET_RAW` and must run serially because concurrent raw receivers could observe each other's packets. Run them manually as follows:

```sh
sudo --preserve-env=PATH,CARGO_HOME,RUSTUP_HOME \
  env CARGO_TARGET_DIR=/tmp/singsing-rs-privileged-target \
  cargo test --workspace --locked -- --ignored --test-threads=1
```

The separate target directory prevents Cargo from leaving root-owned build artifacts in the repository's normal `target/` directory. The ignored tests are still compiled by ordinary test and CI runs, so API changes cannot silently break them.

## Compatibility

The scanner is intentionally Linux-focused. The release build and test suite have been verified on Ubuntu Linux 24.04 (`aarch64` and `x86_64`).

## Credits

- Maurizio Agazzini ([inode](https://github.com/inode-)) 🧙‍♂️, author of the original `singsing` and `zucca`.

## Changelog

- [CHANGELOG.md](https://github.com/0xdea/singsing-rs/blob/master/CHANGELOG.md)

## TODO

- Maybe port to macOS (or even Windows) if there's interest.

## Implementation details

### Packet I/O

Unlike the original `singsing`, which sent probes with a raw socket and captured responses through `libpcap`, this implementation uses `pnet` for interface discovery, IPv4/TCP packet construction and parsing, and Layer-3 raw-socket sending and receiving. It therefore does not require `libpcap` or expose link-layer headers. Responses are correlated and filtered in Rust rather than with a `libpcap` BPF capture filter.

### Bandwidth pacing

The default bandwidth is 15 KiB/s. With the Rust scanner's 40-byte IPv4/TCP header accounting, this corresponds to approximately 384 SYN probes per second. Override it with `-b`/`--bandwidth`.

The original `singsing` calibrated transmission by sending test SYNs to the local host, then adjusted a sleep after groups of roughly ten packets using a 58-byte packet estimate. This implementation sends no calibration traffic: it schedules each probe against an absolute deadline using its 40-byte IPv4/TCP header size. The deadline approach is smoother and automatically accounts for ordinary send overhead, and the same bandwidth value permits about 45% more SYNs per second than the original 58-byte calculation.

### Transmission order

The original `zucca` used a deterministic segmented traversal: for each port, it walked large address ranges with a bandwidth-derived stride, falling back to sequential hosts for small ranges. This implementation stores exact host/port pairs in a randomly seeded `HashMap` and sends them in its unspecified iteration order. Consequently, hosts and ports are interleaved differently between runs rather than following a predictable sequence. This improves scan stealthiness by avoiding an obvious sequential pattern.

### Packet fingerprint

Rust probes use TTL 64, a 64,240-byte TCP window, and an IP ID derived from the probe sequence; the original `singsing` used TTL 100, a 32,768-byte window, and incrementing IP IDs. These values should not change normal open/closed results: TTL 64 is sufficient for typical paths, the window matters only after a handshake, and these small packets are not normally fragmented. They do produce a different observable fingerprint and may be treated differently by unusual middlebox rules.

### Response validation

The original `singsing` primarily trusted TCP flags and a destination-port range. This implementation accepts a response only when its source host and port match an actual probe, its destination matches the scanner address and source port, and its acknowledgement number matches the transmitted sequence number. It then treats SYN/ACK as open and, when requested, RST as closed. This stricter correlation reduces false positives from unrelated TCP traffic, but ignores unusual RST responses without the expected acknowledgement number.

### Source port behavior

Each scan selects one TCP source-port number from the `49152–65535` range and reuses it for every raw SYN probe. The scanner writes this number directly into the TCP headers; it does not bind or reserve a local TCP socket.

The selected port number can therefore overlap a port used by another local connection. TCP connections are identified by their complete local and remote address/port tuple, so interference additionally requires the scan to target the same remote address and port. This is unlikely in typical use but is worth considering on busy scanning hosts with existing connections to the targets.

### Scan size limit and memory usage

A single scan is limited to 16,777,214 host/port pairs. This accommodates either one TCP port across all usable addresses of an IPv4 `/8` subnet, or all 65,535 TCP ports across the 254 usable addresses of a `/24` subnet. Full-port scans of networks larger than `/24` exceed the limit and must be split into `/24` subnets or smaller scans. Larger networks can be scanned when the selected port count keeps the total number of host/port pairs within the limit.

Unlike the original `singsing`, which generated probes incrementally, this implementation expands all targets and builds an expected-response hash-table entry for every host/port pair before sending. Memory use therefore grows with the total number of pairs, not only with the number of responses. On a typical 64-bit build, a one-port scan of a full usable `/8` subnet consumes roughly 500 MiB when few hosts answer. If every host returns an accepted response, the expected-response table, duplicate set, target list, and buffered results together require approximately 832 MiB; allocator and operating-system overhead can bring peak memory close to or above 1 GiB. The exact amount depends on the Rust toolchain and allocator. Split large scans when memory is constrained even if they are below the configured pair limit.

Networks larger than `/8` are rejected before their addresses are expanded, preventing oversized CIDRs such as `/7` or `/0` from exhausting memory before the scan limit can be checked.

Library callers constructing `ScanConfig` directly must provide unique target and port vectors; duplicate entries are rejected rather than silently producing inaccurate probe and progress counts.

### Target handling

For networks from `/8` through `/30`, `zucchini` omits the network and broadcast addresses. A `/31` subnet is treated as a point-to-point network, so both its addresses are scanned. A `/32` scans its single address.

```text
192.168.2.0/30 -> 192.168.2.1, 192.168.2.2
192.168.2.0/31 -> 192.168.2.0, 192.168.2.1
192.168.2.7/32 -> 192.168.2.7
```

### Error handling

If transmission stops after an individual probe error, `zucchini` prints the results received from probes that were successfully sent, then reports the incomplete scan and exits with a failure status. Library callers can downcast the returned error to `IncompleteScanError` to inspect its partial results and sent-probe count.
