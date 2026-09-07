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

## Features

- IPv4 hosts and CIDR ranges
- Comma-separated ports and inclusive port ranges
- TCP ports from `/etc/services` when `--ports` is omitted
- Linux interface address discovery
- Configurable bandwidth and response timeout
- Optional reporting of closed ports
- Duplicate response suppression

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

