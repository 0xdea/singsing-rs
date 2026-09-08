# singsing-rs

[![](https://img.shields.io/github/stars/0xdea/singsing-rs.svg?style=flat&color=yellow)](https://github.com/0xdea/singsing-rs)
[![](https://img.shields.io/crates/v/singsing-rs?style=flat&color=green)](https://crates.io/crates/singsing-rs)
[![](https://img.shields.io/crates/d/singsing-rs?style=flat&color=red)](https://crates.io/crates/singsing-rs)
[![](https://img.shields.io/badge/todo-0.1.1-violet)](https://todo.com/)
[![](https://img.shields.io/badge/twitter-%400xdea-blue.svg)](https://twitter.com/0xdea)
[![](https://img.shields.io/badge/mastodon-%40raptor-purple.svg)](https://infosec.exchange/@raptor)
[![build](https://github.com/0xdea/singsing-rs/actions/workflows/build.yml/badge.svg)](https://github.com/0xdea/singsing-rs/actions/workflows/build.yml)
[![doc](https://github.com/0xdea/singsing-rs/actions/workflows/doc.yml/badge.svg)](https://github.com/0xdea/singsing-rs/actions/workflows/doc.yml)

An IPv4 SYN scanning workspace containing the `singsing-rs` library and the
`zucchini` Linux port scanner, based on the original
[`zucca`](https://github.com/inode-/singsing/blob/master/src/examples/zucca.c)
scanner from the C singsing project.

The scanner creates raw IPv4/TCP packets, sends bandwidth-limited SYN probes,
and validates response acknowledgement numbers before reporting SYN/ACK
responses as open or RST responses as closed. Hosts that do not reply are
treated as filtered or unreachable and are not printed.

Typical output begins with the scanner banner and keeps the final result list
under a separate heading. The heading is omitted when no scan results are
found:

```text
zucchini 0.1.0 - A blazing fast Linux IPv4 port scanner
Copyright (c) 2026 Marco Ivaldi <raptor@0xdeadbeef.info>

Scanning: 3 host/port pairs via eth0 (192.0.2.1)...

Scan results:
open 198.51.100.10:443

Done: 3 host/port pairs scanned in 30.1 seconds
```

## Features

- IPv4 hosts and CIDR ranges
- Comma-separated ports and inclusive port ranges
- TCP ports from `/etc/services` when `--ports` is omitted
- Linux interface address discovery
- Configurable bandwidth and response timeout
- Immediate per-result feedback with `-v`/`--verbose`
- Optional reporting of closed ports
- Duplicate response suppression
- Partial results preserved when probe transmission fails

If transmission stops after an individual probe error, `zucchini` prints the
results received from probes that were successfully sent, then reports the
incomplete scan and exits with a failure status. Library callers can downcast
the returned error to `IncompleteScanError` to inspect its partial results and
sent-probe count.

## See also

- [The original singsing project](https://github.com/inode-/singsing)
- [The original zucca scanner](https://github.com/inode-/singsing/blob/master/src/examples/zucca.c)

## Installing

Install the scanner from [crates.io](https://crates.io/crates/zucchini):

```sh
cargo install zucchini
```

To use the scanning library in another Rust project:

```sh
cargo add singsing-rs
```

## Workspace

- `crates/singsing-rs` contains the reusable SYN scanning library.
- `crates/zucchini` contains the command-line scanner.

## Compiling

Alternatively, you can build from [source](https://github.com/0xdea/singsing-rs):

```sh
git clone https://github.com/0xdea/singsing-rs
cd singsing-rs
cargo build --release
```

## Configuration

> [!WARNING]
> Only scan systems you own or have explicit permission to test.

`zucchini` uses a raw transport socket. Run it as root, or grant the installed
binary only the capability it needs:

```sh
sudo setcap cap_net_raw=eip "$(command -v zucchini)"
```

Choose an interface whose IPv4 address can route to the targets. List available
interfaces with `ip -brief address`.

### Bandwidth pacing

The default bandwidth is 15 KiB/s. With the Rust scanner's 40-byte IPv4/TCP
header accounting, this corresponds to approximately 384 SYN probes per
second. Override it with `-b` or `--bandwidth`.

Original singsing calibrated transmission by sending test SYNs to itself, then
adjusted a sleep after groups of roughly ten packets using a 58-byte packet
estimate. This Rust implementation sends no calibration traffic: it schedules
each probe against an absolute deadline using its 40-byte IPv4/TCP header size.
The deadline approach is smoother and automatically accounts for ordinary send
overhead, but the same bandwidth value permits about 45% more SYNs per second
than the original 58-byte calculation.

### Transmission order

Original zucca used a deterministic segmented traversal: for each port, it
walked large address ranges with a bandwidth-derived stride, falling back to
sequential hosts for small ranges. This implementation stores exact
host/port pairs in a randomly seeded `HashMap` and sends them in its
unspecified iteration order. Consequently, hosts and ports are interleaved
differently between runs rather than following a predictable sequence. This
improves scan stealthiness by avoiding an obvious sequential pattern, although
it does not make the traffic undetectable.

### Packet fingerprint

Rust probes use TTL 64, a 64,240-byte TCP window, and an IP ID derived from the
probe sequence; original singsing used TTL 100, a 32,768-byte window, and
incrementing IP IDs. These values should not change normal open/closed results:
TTL 64 is sufficient for typical paths, the window matters only after a
handshake, and these small packets are not normally fragmented. They do produce
a different observable fingerprint and may be treated differently by unusual
middlebox rules.

### Response validation

Original singsing primarily trusted TCP flags and a destination-port range.
This implementation accepts a response only when its source host and port match
an actual probe, its destination matches the scanner address and source port,
and its acknowledgement number matches the transmitted sequence number. It
then treats SYN/ACK as open and, when requested, RST as closed. This stricter
correlation reduces false positives from unrelated TCP traffic, but ignores
unusual RST responses without the expected acknowledgement number.

### Source port behavior

Each scan selects one TCP source-port number from `49152–65535` and reuses it
for every raw SYN probe. The scanner writes this number directly into the TCP
headers; it does not bind or reserve a local TCP socket.

The selected number can therefore overlap a port used by another local
connection. TCP connections are identified by their complete local and remote
address/port tuple, so interference additionally requires the scan to target
the same remote address and port. This is unlikely in typical use but is worth
considering on busy scanning hosts with existing connections to the targets.

### Scan size limit

A single scan is limited to 16,777,214 host/port pairs. This accommodates
either one TCP port across all usable addresses of an IPv4 `/8`, or all 65,535
TCP ports across the 254 usable addresses of a `/24`. Full-port scans of
networks larger than `/24` exceed the limit and must be split into `/24` or
smaller scans. Larger networks can be scanned when the selected port count
keeps the total number of host/port pairs within the limit.

### Target handling

For networks from `/0` through `/30`, `zucchini` omits the network and
broadcast addresses. A `/31` is treated as a point-to-point network, so both
addresses are scanned. A `/32` scans its single address.

```text
192.0.2.0/30 → 192.0.2.1, 192.0.2.2
192.0.2.0/31 → 192.0.2.0, 192.0.2.1
192.0.2.7/32 → 192.0.2.7
```

## Usage

Scan selected ports on one host:

```sh
sudo zucchini -h 192.0.2.10 -i eth0 -p 22,80,443
```

Scan a subnet and include closed ports:

```sh
sudo zucchini -h 192.0.2.0/24 -i eth0 -p 1-1024 -c
```

Use TCP entries from `/etc/services`, limit the send rate to 100 KiB/s, and
wait five seconds for late replies:

```sh
sudo zucchini -h 192.0.2.10 -i eth0 -b 100 -t 5
```

Run `zucchini --help` for the complete command-line reference.

Use `-v` or `--verbose` to print tagged responses as soon as they arrive and
progress statistics with a local date/time ETA every minute for the first ten
minutes, every ten minutes through the first hour, and every thirty minutes
thereafter. The complete sorted results are still printed normally under a
separate `Scan results:` heading when the scan finishes:

```sh
sudo zucchini -h 192.0.2.0/24 -i eth0 -p 22,80,443 --verbose
```

Library users can construct a [`ScanConfig`](https://docs.rs/singsing-rs/latest/singsing_rs/struct.ScanConfig.html)
and call [`scan`](https://docs.rs/singsing-rs/latest/singsing_rs/fn.scan.html).

## Compatibility

The scanner is intentionally Linux-focused. The release build and test suite
are verified on Ubuntu Linux 24.04 (`aarch64`).

## Credits

- Maurizio Agazzini (inode), author of the original singsing and zucca code
- Marco Ivaldi (0xdea), Rust port

## Changelog

- [CHANGELOG.md](https://github.com/0xdea/singsing-rs/blob/master/CHANGELOG.md)

