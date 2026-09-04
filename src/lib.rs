#![doc = env!("CARGO_PKG_DESCRIPTION")]

//! Linux IPv4 SYN scanning primitives.
//!
//! The scanner sends raw TCP SYN packets and classifies SYN/ACK replies as
//! open and RST replies as closed. Creating the raw transport socket requires
//! root or the `CAP_NET_RAW` capability.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use ipnet::Ipv4Net;
use pnet::datalink;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum as ipv4_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum as tcp_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{TransportChannelType, ipv4_packet_iter, transport_channel};

const PACKET_LEN: usize = 40;
const MAX_PROBES: usize = 16_000_000;

/// The state inferred from a TCP response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortState {
    /// A SYN/ACK was received.
    Open,
    /// A RST was received.
    Closed,
}

/// One response produced by a scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanResult {
    /// The responding host.
    pub host: Ipv4Addr,
    /// The responding TCP port.
    pub port: u16,
    /// The inferred port state.
    pub state: PortState,
}

/// Configuration for one SYN scan.
#[derive(Clone, Debug)]
pub struct ScanConfig {
    /// IPv4 addresses to scan.
    pub targets: Vec<Ipv4Addr>,
    /// TCP ports to scan.
    pub ports: Vec<u16>,
    /// Source IPv4 address assigned to the selected interface.
    pub source: Ipv4Addr,
    /// Approximate maximum packet bandwidth in KiB/s.
    pub bandwidth_kib: u64,
    /// Time to listen for late replies after the final probe.
    pub timeout: Duration,
    /// Whether RST responses should be returned.
    pub show_closed: bool,
}

impl ScanConfig {
    /// Creates a configuration with the original zucca defaults.
    #[must_use]
    pub fn new(targets: Vec<Ipv4Addr>, ports: Vec<u16>, source: Ipv4Addr) -> Self {
        Self {
            targets,
            ports,
            source,
            bandwidth_kib: 15,
            timeout: Duration::from_secs(3),
            show_closed: false,
        }
    }
}

/// Resolves the first IPv4 address assigned to a network interface.
///
/// # Errors
///
/// Returns an error if the interface does not exist or has no IPv4 address.
pub fn interface_ipv4(name: &str) -> Result<Ipv4Addr> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == name)
        .ok_or_else(|| anyhow!("network interface {name:?} does not exist"))?;

    interface
        .ips
        .into_iter()
        .find_map(|network| match network.ip() {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| anyhow!("network interface {name:?} has no IPv4 address"))
}

/// Expands an IPv4 address or CIDR into scan targets.
///
/// Network and broadcast addresses are omitted for prefixes shorter than
/// `/31`, matching [`Ipv4Net::hosts`].
///
/// # Errors
///
/// Returns an error for malformed IPv4/CIDR input.
pub fn parse_targets(input: &str) -> Result<Vec<Ipv4Addr>> {
    let network: Ipv4Net = if input.contains('/') {
        input.parse().context("invalid IPv4 network")?
    } else {
        format!("{input}/32")
            .parse()
            .context("invalid IPv4 address")?
    };
    Ok(network.hosts().collect())
}

/// Parses comma-separated ports and inclusive ranges such as `22,80,8000-8010`.
///
/// Duplicate ports are removed while preserving their first occurrence.
///
/// # Errors
///
/// Returns an error for empty items, reversed ranges, port zero, or values
/// larger than 65535.
pub fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    let mut seen = HashSet::new();

    for item in input.split(',') {
        if item.is_empty() {
            bail!("empty port in {input:?}");
        }
        if let Some((start, end)) = item.split_once('-') {
            if end.contains('-') {
                bail!("invalid port range {item:?}");
            }
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                bail!("reversed port range {item:?}");
            }
            for port in start..=end {
                if seen.insert(port) {
                    ports.push(port);
                }
            }
        } else {
            let port = parse_port(item)?;
            if seen.insert(port) {
                ports.push(port);
            }
        }
    }
    Ok(ports)
}

/// Reads TCP ports from a services file (normally `/etc/services`).
///
/// # Errors
///
/// Returns an error when the file cannot be read or contains no TCP services.
pub fn ports_from_services(path: impl AsRef<std::path::Path>) -> Result<Vec<u16>> {
    let contents = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("failed to read {}", path.as_ref().display()))?;
    let mut ports = Vec::new();
    let mut seen = HashSet::new();
    for line in contents.lines() {
        let mut fields = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let _service = fields.next();
        if let Some(port_protocol) = fields.next() {
            if let Some((port, "tcp")) = port_protocol.split_once('/') {
                if let Ok(port) = parse_port(port) {
                    if seen.insert(port) {
                        ports.push(port);
                    }
                }
            }
        }
    }
    if ports.is_empty() {
        bail!("{} contains no TCP services", path.as_ref().display());
    }
    Ok(ports)
}

/// Executes a Linux IPv4 SYN scan.
///
/// No reply means filtered or unreachable and therefore produces no result.
/// Raw sockets require root or `CAP_NET_RAW`.
///
/// # Errors
///
/// Returns an error for an empty or excessively large scan, invalid bandwidth,
/// raw socket permission failures, packet send failures, or receiver failures.
pub fn scan(config: &ScanConfig) -> Result<Vec<ScanResult>> {
    if config.targets.is_empty() || config.ports.is_empty() {
        bail!("at least one target and one port are required");
    }
    if config.bandwidth_kib == 0 {
        bail!("bandwidth must be greater than zero");
    }
    let probe_count = config
        .targets
        .len()
        .checked_mul(config.ports.len())
        .ok_or_else(|| anyhow!("scan size overflow"))?;
    if probe_count > MAX_PROBES {
        bail!("scan contains {probe_count} probes; maximum is {MAX_PROBES}");
    }

    let source_port = source_port();
    let nonce = nonce();
    let expected: HashMap<(Ipv4Addr, u16), u32> = config
        .targets
        .iter()
        .flat_map(|host| {
            config
                .ports
                .iter()
                .map(move |port| ((*host, *port), sequence(*host, *port, nonce)))
        })
        .collect();
    let expected = Arc::new(expected);

    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut sender, mut receiver) = transport_channel(1 << 20, protocol)
        .context("failed to create raw socket (run as root or grant CAP_NET_RAW)")?;

    let done = Arc::new(AtomicBool::new(false));
    let receiver_done = Arc::clone(&done);
    let receiver_expected = Arc::clone(&expected);
    let source = config.source;
    let timeout = config.timeout;
    let show_closed = config.show_closed;
    let receive_thread = thread::spawn(move || {
        receive(
            &mut receiver,
            &receiver_expected,
            source,
            source_port,
            show_closed,
            &receiver_done,
            timeout,
        )
    });

    let packets_per_second = (config.bandwidth_kib * 1024 / PACKET_LEN as u64).max(1);
    let interval = Duration::from_secs_f64(1.0 / packets_per_second as f64);
    let mut next_send = Instant::now();
    let send_result = (|| -> Result<()> {
        for (&(host, port), &sequence) in expected.iter() {
            let packet = syn_packet(config.source, host, source_port, port, sequence);
            sender
                .send_to(
                    MutableIpv4Packet::owned(packet).expect("fixed-size IPv4 packet"),
                    IpAddr::V4(host),
                )
                .with_context(|| format!("failed to send SYN to {host}:{port}"))?;
            next_send += interval;
            if let Some(delay) = next_send.checked_duration_since(Instant::now()) {
                thread::sleep(delay);
            }
        }
        Ok(())
    })();
    done.store(true, Ordering::Release);

    let mut results = receive_thread
        .join()
        .map_err(|_| anyhow!("packet receiver thread panicked"))??;
    send_result?;
    results.sort_unstable_by_key(|result| (u32::from(result.host), result.port));
    Ok(results)
}

fn parse_port(input: &str) -> Result<u16> {
    let port: u16 = input
        .parse()
        .with_context(|| format!("invalid TCP port {input:?}"))?;
    if port == 0 {
        bail!("TCP port zero is not supported");
    }
    Ok(port)
}

fn source_port() -> u16 {
    49152 + (nonce() % 16384) as u16
}

fn nonce() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

fn sequence(host: Ipv4Addr, port: u16, nonce: u32) -> u32 {
    u32::from(host)
        .rotate_left(13)
        .wrapping_add(u32::from(port).rotate_left(3))
        ^ nonce
}

fn syn_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; PACKET_LEN];
    let mut ipv4 = MutableIpv4Packet::new(&mut bytes).expect("fixed-size IPv4 packet");
    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_total_length(PACKET_LEN as u16);
    ipv4.set_identification((sequence >> 16) as u16);
    ipv4.set_ttl(64);
    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4.set_source(source);
    ipv4.set_destination(destination);

    let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).expect("fixed-size TCP packet");
    tcp.set_source(source_port);
    tcp.set_destination(destination_port);
    tcp.set_sequence(sequence);
    tcp.set_data_offset(5);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(64240);
    tcp.set_checksum(tcp_checksum(&tcp.to_immutable(), &source, &destination));
    ipv4.set_checksum(ipv4_checksum(&ipv4.to_immutable()));
    bytes
}

fn receive(
    receiver: &mut pnet::transport::TransportReceiver,
    expected: &HashMap<(Ipv4Addr, u16), u32>,
    source: Ipv4Addr,
    source_port: u16,
    show_closed: bool,
    done: &AtomicBool,
    timeout: Duration,
) -> io::Result<Vec<ScanResult>> {
    let mut iterator = ipv4_packet_iter(receiver);
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let mut deadline = None;

    loop {
        if done.load(Ordering::Acquire) && deadline.is_none() {
            deadline = Some(Instant::now() + timeout);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        let wait = deadline
            .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100));
        let Some((ipv4, _)) = iterator.next_with_timeout(wait)? else {
            continue;
        };
        if ipv4.get_destination() != source {
            continue;
        }
        let Some(tcp) = TcpPacket::new(ipv4.payload()) else {
            continue;
        };
        let key = (ipv4.get_source(), tcp.get_source());
        let Some(sequence) = expected.get(&key) else {
            continue;
        };
        if tcp.get_destination() != source_port
            || tcp.get_acknowledgement() != sequence.wrapping_add(1)
            || !seen.insert(key)
        {
            continue;
        }
        let flags = tcp.get_flags();
        let state = if flags & (TcpFlags::SYN | TcpFlags::ACK) == TcpFlags::SYN | TcpFlags::ACK {
            PortState::Open
        } else if flags & TcpFlags::RST != 0 && show_closed {
            PortState::Closed
        } else {
            continue;
        };
        results.push(ScanResult {
            host: key.0,
            port: key.1,
            state,
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ipv4::Ipv4Packet;

    #[test]
    fn parses_ports_ranges_and_duplicates() {
        assert_eq!(parse_ports("22,80,79-81").unwrap(), [22, 80, 79, 81]);
    }

    #[test]
    fn rejects_invalid_ports() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("80-79").is_err());
        assert!(parse_ports("65536").is_err());
        assert!(parse_ports("22,").is_err());
    }

    #[test]
    fn parses_host_and_network() {
        assert_eq!(
            parse_targets("192.0.2.9").unwrap(),
            ["192.0.2.9".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            parse_targets("192.0.2.0/30").unwrap(),
            [
                "192.0.2.1".parse::<Ipv4Addr>().unwrap(),
                "192.0.2.2".parse::<Ipv4Addr>().unwrap()
            ]
        );
    }

    #[test]
    fn builds_valid_syn_packet() {
        let source = "192.0.2.1".parse().unwrap();
        let destination = "198.51.100.2".parse().unwrap();
        let bytes = syn_packet(source, destination, 50000, 443, 123);
        let ipv4 = Ipv4Packet::new(&bytes).unwrap();
        let tcp = TcpPacket::new(ipv4.payload()).unwrap();

        let mut ip_for_checksum = MutableIpv4Packet::owned(bytes.clone()).unwrap();
        ip_for_checksum.set_checksum(0);
        assert_eq!(
            ipv4.get_checksum(),
            ipv4_checksum(&ip_for_checksum.to_immutable())
        );
        let mut tcp_for_checksum = MutableTcpPacket::owned(tcp.packet().to_vec()).unwrap();
        tcp_for_checksum.set_checksum(0);
        assert_eq!(
            tcp.get_checksum(),
            tcp_checksum(&tcp_for_checksum.to_immutable(), &source, &destination)
        );
        assert_eq!(tcp.get_destination(), 443);
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
    }
}
