#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../../../README.md"))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/0xdea/singsing-rs/master/.img/logo_singsing.png"
)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fmt, thread};

use anyhow::{Context, Result, anyhow, bail};
use ipnet::Ipv4Net;
use pnet::datalink;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum as ipv4_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum as tcp_checksum};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{TransportChannelType, ipv4_packet_iter, transport_channel};

const PACKET_LEN: usize = 40;
const MAX_PROBES: usize = 16_777_214;
const ONE_MINUTE: Duration = Duration::from_mins(1);
const TEN_MINUTES: Duration = Duration::from_mins(10);
const ONE_HOUR: Duration = Duration::from_hours(1);
const THIRTY_MINUTES: Duration = Duration::from_mins(30);

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

/// An error that stopped transmission after part of a scan was sent.
#[derive(Debug)]
pub struct IncompleteScanError {
    source: anyhow::Error,
    partial_results: Vec<ScanResult>,
    probes_sent: usize,
    total_probes: usize,
}

impl IncompleteScanError {
    /// Returns results received from probes sent before transmission stopped.
    #[must_use]
    pub fn partial_results(&self) -> &[ScanResult] {
        &self.partial_results
    }

    /// Returns the number of probes successfully sent before the error.
    #[must_use]
    pub const fn probes_sent(&self) -> usize {
        self.probes_sent
    }

    /// Returns the total number of probes requested by the scan.
    #[must_use]
    pub const fn total_probes(&self) -> usize {
        self.total_probes
    }
}

impl fmt::Display for IncompleteScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "scan stopped after sending {} of {} probes",
            self.probes_sent, self.total_probes
        )
    }
}

impl std::error::Error for IncompleteScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Sending progress reported during a scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanProgress {
    /// Number of probes sent so far.
    pub probes_sent: usize,
    /// Total number of probes in the scan.
    pub total_probes: usize,
    /// Time elapsed since sending began.
    pub elapsed: Duration,
}

impl ScanProgress {
    /// Returns the integer completion percentage.
    #[must_use]
    pub const fn percent(self) -> usize {
        if self.total_probes == 0 {
            return 0;
        }
        self.probes_sent.saturating_mul(100) / self.total_probes
    }

    /// Estimates the time required to send the remaining probes.
    #[must_use]
    pub fn estimated_remaining(self) -> Option<Duration> {
        let sent = u32::try_from(self.probes_sent).ok()?;
        let remaining = u32::try_from(self.total_probes.saturating_sub(self.probes_sent)).ok()?;
        if sent == 0 {
            return None;
        }
        self.elapsed.checked_mul(remaining)?.checked_div(sent)
    }
}

/// Configuration for one SYN scan.
#[derive(Clone, Debug)]
pub struct ScanConfig {
    /// IPv4 addresses to scan.
    ///
    /// Addresses must be unique.
    pub targets: Vec<Ipv4Addr>,
    /// TCP ports to scan.
    ///
    /// Ports must be unique.
    pub ports: Vec<u16>,
    /// Source IPv4 address assigned to the selected interface.
    pub source: Ipv4Addr,
    /// Approximate maximum packet bandwidth in KiB/s.
    ///
    /// [`ScanConfig::new`] defaults this to 15 KiB/s, or approximately 384
    /// probes per second with the scanner's 40-byte packet accounting.
    pub bandwidth_kib: u64,
    /// Time to listen for late replies after the final probe.
    pub timeout: Duration,
    /// Whether RST responses should be returned.
    pub show_closed: bool,
}

impl ScanConfig {
    /// Creates a configuration with 15 KiB/s bandwidth and a 30-second timeout.
    #[must_use]
    pub const fn new(targets: Vec<Ipv4Addr>, ports: Vec<u16>, source: Ipv4Addr) -> Self {
        Self {
            targets,
            ports,
            source,
            bandwidth_kib: 15,
            timeout: Duration::from_secs(30),
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
/// Network and broadcast addresses are omitted for prefixes from `/0` through
/// `/30`. Both addresses of a `/31` are included, as is the single address of
/// a `/32`, matching [`Ipv4Net::hosts`].
///
/// # Errors
///
/// Returns an error for malformed IPv4/CIDR input or a network containing more
/// usable addresses than a `/8`.
pub fn parse_targets(input: &str) -> Result<Vec<Ipv4Addr>> {
    let network: Ipv4Net = if input.contains('/') {
        input.parse().context("invalid IPv4 network")?
    } else {
        format!("{input}/32")
            .parse()
            .context("invalid IPv4 address")?
    };
    if usable_target_count(network).is_none_or(|count| count > MAX_PROBES) {
        bail!(
            "{network} contains more than {MAX_PROBES} usable addresses; \
             split networks larger than a /8"
        );
    }
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
        if let Some(port_protocol) = fields.next()
            && let Some((port, "tcp")) = port_protocol.split_once('/')
            && let Ok(port) = parse_port(port)
            && seen.insert(port)
        {
            ports.push(port);
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
/// duplicate targets or ports, raw socket permission failures, packet send
/// failures, or receiver failures. A transmission-phase failure is returned as
/// [`IncompleteScanError`], which retains results received for successfully
/// sent probes.
pub fn scan(config: &ScanConfig) -> Result<Vec<ScanResult>> {
    scan_with_callbacks(config, |_| Ok(()), |_| Ok(()))
}

/// Executes a SYN scan and calls `on_result` as each response arrives.
///
/// Results are still returned in sorted order after the scan. The callback is
/// useful for interactive clients that need immediate per-result feedback.
///
/// # Errors
///
/// Returns the same errors as [`scan`], along with errors returned by
/// `on_result`.
pub fn scan_with_callback(
    config: &ScanConfig,
    on_result: impl FnMut(ScanResult) -> Result<()> + Send + 'static,
) -> Result<Vec<ScanResult>> {
    scan_with_callbacks(config, on_result, |_| Ok(()))
}

/// Executes a SYN scan with callbacks for results and sending progress.
///
/// `on_result` runs as each response arrives. While probes are being sent,
/// `on_progress` runs every minute for the first ten minutes, every ten minutes
/// through the first hour, and every thirty minutes thereafter.
///
/// # Errors
///
/// Returns the same errors as [`scan`], along with errors returned by either
/// callback.
pub fn scan_with_callbacks(
    config: &ScanConfig,
    mut on_result: impl FnMut(ScanResult) -> Result<()> + Send + 'static,
    mut on_progress: impl FnMut(ScanProgress) -> Result<()>,
) -> Result<Vec<ScanResult>> {
    let probe_count = validate_scan(config)?;

    let source_port = source_port();
    let nonce = nonce();
    let expected = expected_responses(config, nonce, probe_count)?;
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
        let receive_config = ReceiveConfig {
            expected: &receiver_expected,
            source,
            source_port,
            show_closed,
            done: &receiver_done,
            timeout,
        };
        receive(&mut receiver, &receive_config, &mut on_result)
    });

    let bytes_per_second = config
        .bandwidth_kib
        .checked_mul(1024)
        .ok_or_else(|| anyhow!("bandwidth is too large"))?;
    let packets_per_second = (bytes_per_second / 40).max(1);
    let interval = Duration::from_nanos(1_000_000_000_u64 / packets_per_second);
    let mut next_send = Instant::now();
    let started = next_send;
    let mut next_progress = ONE_MINUTE;
    let mut probes_sent = 0;
    let send_result = (|| -> Result<()> {
        for (&(host, port), &sequence) in expected.iter() {
            let packet = syn_packet(config.source, host, source_port, port, sequence);
            let ipv4_packet = MutableIpv4Packet::owned(packet)
                .ok_or_else(|| anyhow!("failed to construct IPv4 packet"))?;
            sender
                .send_to(ipv4_packet, IpAddr::V4(host))
                .with_context(|| format!("failed to send SYN to {host}:{port}"))?;
            probes_sent += 1;
            next_send += interval;
            if let Some(delay) = next_send.checked_duration_since(Instant::now()) {
                thread::sleep(delay);
            }
            let now = Instant::now();
            let elapsed = now.duration_since(started);
            if elapsed >= next_progress {
                on_progress(ScanProgress {
                    probes_sent,
                    total_probes: probe_count,
                    elapsed,
                })?;
                next_progress = advance_progress_deadline(next_progress, elapsed);
            }
        }
        Ok(())
    })();
    done.store(true, Ordering::Release);

    let mut results = receive_thread
        .join()
        .map_err(|_| anyhow!("packet receiver thread panicked"))??;
    results.sort_unstable_by_key(|result| (u32::from(result.host), result.port));
    if let Err(source) = send_result {
        return Err(IncompleteScanError {
            source,
            partial_results: results,
            probes_sent,
            total_probes: probe_count,
        }
        .into());
    }
    Ok(results)
}

fn validate_scan(config: &ScanConfig) -> Result<usize> {
    validate_probe_count(
        config.targets.len(),
        config.ports.len(),
        config.bandwidth_kib,
    )
}

fn usable_target_count(network: Ipv4Net) -> Option<usize> {
    let host_bits = 32_u32.checked_sub(u32::from(network.prefix_len()))?;
    match host_bits {
        0 => Some(1),
        1 => Some(2),
        bits => 1_usize.checked_shl(bits)?.checked_sub(2),
    }
}

fn expected_responses(
    config: &ScanConfig,
    nonce: u32,
    probe_count: usize,
) -> Result<HashMap<(Ipv4Addr, u16), u32>> {
    let mut expected = HashMap::with_capacity(probe_count);
    for &host in &config.targets {
        for &port in &config.ports {
            if expected
                .insert((host, port), sequence(host, port, nonce))
                .is_some()
            {
                bail!(
                    "duplicate host/port pair {host}:{port}; \
                     ScanConfig targets and ports must be unique"
                );
            }
        }
    }
    Ok(expected)
}

fn validate_probe_count(
    target_count: usize,
    port_count: usize,
    bandwidth_kib: u64,
) -> Result<usize> {
    if target_count == 0 || port_count == 0 {
        bail!("at least one target and one port are required");
    }
    if bandwidth_kib == 0 {
        bail!("bandwidth must be greater than zero");
    }
    let probe_count = target_count
        .checked_mul(port_count)
        .ok_or_else(|| anyhow!("scan size overflow"))?;
    if probe_count > MAX_PROBES {
        bail!(
            "scan contains {probe_count} probes; maximum is {MAX_PROBES} \
             (one port on a /8 or all 65,535 ports on a /24); split larger scans"
        );
    }
    Ok(probe_count)
}

fn advance_progress_deadline(mut deadline: Duration, elapsed: Duration) -> Duration {
    while deadline <= elapsed {
        deadline = next_progress_deadline(deadline);
    }
    deadline
}

fn next_progress_deadline(previous: Duration) -> Duration {
    let interval = if previous < TEN_MINUTES {
        ONE_MINUTE
    } else if previous < ONE_HOUR {
        TEN_MINUTES
    } else {
        THIRTY_MINUTES
    };
    previous + interval
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
    ipv4.set_total_length(40);
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

struct ReceiveConfig<'a> {
    expected: &'a HashMap<(Ipv4Addr, u16), u32>,
    source: Ipv4Addr,
    source_port: u16,
    show_closed: bool,
    done: &'a AtomicBool,
    timeout: Duration,
}

fn receive(
    receiver: &mut pnet::transport::TransportReceiver,
    config: &ReceiveConfig<'_>,
    on_result: &mut impl FnMut(ScanResult) -> Result<()>,
) -> Result<Vec<ScanResult>> {
    let mut iterator = ipv4_packet_iter(receiver);
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let mut deadline = None;

    loop {
        if config.done.load(Ordering::Acquire) && deadline.is_none() {
            deadline = Some(Instant::now() + config.timeout);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        let wait = deadline
            .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100));
        let Some((ipv4, _)) = iterator
            .next_with_timeout(wait)
            .context("failed to receive raw packet")?
        else {
            continue;
        };
        let Some(result) = classify_response(
            &ipv4,
            config.expected,
            config.source,
            config.source_port,
            config.show_closed,
            &mut seen,
        ) else {
            continue;
        };
        on_result(result)?;
        results.push(result);
    }
    Ok(results)
}

fn classify_response(
    ipv4: &Ipv4Packet<'_>,
    expected: &HashMap<(Ipv4Addr, u16), u32>,
    source: Ipv4Addr,
    source_port: u16,
    show_closed: bool,
    seen: &mut HashSet<(Ipv4Addr, u16)>,
) -> Option<ScanResult> {
    if ipv4.get_destination() != source {
        return None;
    }
    let tcp = TcpPacket::new(ipv4.payload())?;
    let key = (ipv4.get_source(), tcp.get_source());
    let sequence = expected.get(&key)?;
    if tcp.get_destination() != source_port || tcp.get_acknowledgement() != sequence.wrapping_add(1)
    {
        return None;
    }
    let flags = tcp.get_flags();
    let state = if flags == TcpFlags::SYN | TcpFlags::ACK {
        PortState::Open
    } else if show_closed && (flags == TcpFlags::RST || flags == TcpFlags::RST | TcpFlags::ACK) {
        PortState::Closed
    } else {
        return None;
    };
    if !seen.insert(key) {
        return None;
    }
    Some(ScanResult {
        host: key.0,
        port: key.1,
        state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_packet(
        remote: Ipv4Addr,
        local: Ipv4Addr,
        remote_port: u16,
        local_port: u16,
        acknowledgement: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut bytes = vec![0_u8; PACKET_LEN];
        let mut ipv4 = MutableIpv4Packet::new(&mut bytes).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(40);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4.set_source(remote);
        ipv4.set_destination(local);

        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
        tcp.set_source(remote_port);
        tcp.set_destination(local_port);
        tcp.set_acknowledgement(acknowledgement);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        bytes
    }

    fn classify_packet(
        bytes: &[u8],
        expected: &HashMap<(Ipv4Addr, u16), u32>,
        source: Ipv4Addr,
        source_port: u16,
        show_closed: bool,
        seen: &mut HashSet<(Ipv4Addr, u16)>,
    ) -> Option<ScanResult> {
        let ipv4 = Ipv4Packet::new(bytes).unwrap();
        classify_response(&ipv4, expected, source, source_port, show_closed, seen)
    }

    fn services_path() -> std::path::PathBuf {
        static NEXT_FILE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

        let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "singsing-rs-services-{}-{number}",
            std::process::id()
        ))
    }

    fn services_from(contents: &str) -> Result<Vec<u16>> {
        let path = services_path();
        std::fs::write(&path, contents)?;
        let result = ports_from_services(&path);
        std::fs::remove_file(path)?;
        result
    }

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
        assert_eq!(
            parse_targets("192.0.2.0/31").unwrap(),
            [
                "192.0.2.0".parse::<Ipv4Addr>().unwrap(),
                "192.0.2.1".parse::<Ipv4Addr>().unwrap()
            ]
        );
        assert_eq!(
            parse_targets("192.0.2.7/32").unwrap(),
            ["192.0.2.7".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn normalizes_host_bits_and_rejects_invalid_targets() {
        assert_eq!(
            parse_targets("192.0.2.7/30").unwrap(),
            [
                "192.0.2.5".parse::<Ipv4Addr>().unwrap(),
                "192.0.2.6".parse::<Ipv4Addr>().unwrap()
            ]
        );
        assert!(parse_targets("").is_err());
        assert!(parse_targets("not-an-address").is_err());
        assert!(parse_targets("192.0.2.1/33").is_err());
    }

    #[test]
    fn rejects_oversized_cidr_before_expansion() {
        let slash_8 = "10.0.0.0/8".parse::<Ipv4Net>().unwrap();
        let slash_31 = "192.0.2.0/31".parse::<Ipv4Net>().unwrap();
        let slash_32 = "192.0.2.1/32".parse::<Ipv4Net>().unwrap();

        assert_eq!(usable_target_count(slash_8), Some(MAX_PROBES));
        assert_eq!(usable_target_count(slash_31), Some(2));
        assert_eq!(usable_target_count(slash_32), Some(1));
        assert!(parse_targets("10.0.0.0/7").is_err());
        assert!(parse_targets("0.0.0.0/0").is_err());
    }

    #[test]
    fn builds_valid_syn_packet() {
        let source = "192.0.2.1".parse().unwrap();
        let destination = "198.51.100.2".parse().unwrap();
        let sequence = 0x1234_5678;
        let bytes = syn_packet(source, destination, 50000, 443, sequence);
        let ipv4 = Ipv4Packet::new(&bytes).unwrap();
        let tcp = TcpPacket::new(ipv4.payload()).unwrap();

        assert_eq!(bytes.len(), PACKET_LEN);
        assert_eq!(ipv4.get_version(), 4);
        assert_eq!(ipv4.get_header_length(), 5);
        assert_eq!(ipv4.get_total_length(), 40);
        assert_eq!(ipv4.get_identification(), (sequence >> 16) as u16);
        assert_eq!(ipv4.get_ttl(), 64);
        assert_eq!(ipv4.get_next_level_protocol(), IpNextHeaderProtocols::Tcp);
        assert_eq!(ipv4.get_source(), source);
        assert_eq!(ipv4.get_destination(), destination);
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
        assert_eq!(tcp.packet().len(), 20);
        assert!(tcp.payload().is_empty());
        assert_eq!(tcp.get_source(), 50000);
        assert_eq!(tcp.get_destination(), 443);
        assert_eq!(tcp.get_sequence(), sequence);
        assert_eq!(tcp.get_acknowledgement(), 0);
        assert_eq!(tcp.get_data_offset(), 5);
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
        assert_eq!(tcp.get_window(), 64240);
        assert_eq!(tcp.get_urgent_ptr(), 0);
    }

    #[test]
    fn accepts_open_response_once() {
        let source = "192.0.2.1".parse().unwrap();
        let target = "198.51.100.2".parse().unwrap();
        let source_port = 50000;
        let target_port = 443;
        let sequence = 0x1234_5678_u32;
        let expected = HashMap::from([((target, target_port), sequence)]);
        let open = ScanResult {
            host: target,
            port: target_port,
            state: PortState::Open,
        };

        let valid_open = response_packet(
            target,
            source,
            target_port,
            source_port,
            sequence.wrapping_add(1),
            TcpFlags::SYN | TcpFlags::ACK,
        );
        let mut seen = HashSet::new();
        assert_eq!(
            classify_packet(
                &valid_open,
                &expected,
                source,
                source_port,
                false,
                &mut seen
            ),
            Some(open)
        );
        assert_eq!(
            classify_packet(
                &valid_open,
                &expected,
                source,
                source_port,
                false,
                &mut seen
            ),
            None
        );
    }

    #[test]
    fn rejects_uncorrelated_responses() {
        let source = "192.0.2.1".parse().unwrap();
        let target = "198.51.100.2".parse().unwrap();
        let other_target = "198.51.100.3".parse().unwrap();
        let source_port = 50000;
        let target_port = 443;
        let sequence = 0x1234_5678_u32;
        let expected = HashMap::from([((target, target_port), sequence)]);
        let invalid_packets = [
            response_packet(
                target,
                "192.0.2.2".parse().unwrap(),
                target_port,
                source_port,
                sequence.wrapping_add(1),
                TcpFlags::SYN | TcpFlags::ACK,
            ),
            response_packet(
                other_target,
                source,
                target_port,
                source_port,
                sequence.wrapping_add(1),
                TcpFlags::SYN | TcpFlags::ACK,
            ),
            response_packet(
                target,
                source,
                80,
                source_port,
                sequence.wrapping_add(1),
                TcpFlags::SYN | TcpFlags::ACK,
            ),
            response_packet(
                target,
                source,
                target_port,
                source_port + 1,
                sequence.wrapping_add(1),
                TcpFlags::SYN | TcpFlags::ACK,
            ),
            response_packet(
                target,
                source,
                target_port,
                source_port,
                sequence,
                TcpFlags::SYN | TcpFlags::ACK,
            ),
        ];
        for packet in invalid_packets {
            assert_eq!(
                classify_packet(
                    &packet,
                    &expected,
                    source,
                    source_port,
                    false,
                    &mut HashSet::new()
                ),
                None
            );
        }
    }

    #[test]
    fn reports_closed_responses_only_when_requested() {
        let source = "192.0.2.1".parse().unwrap();
        let target = "198.51.100.2".parse().unwrap();
        let source_port = 50000;
        let target_port = 443;
        let sequence = 0x1234_5678_u32;
        let expected = HashMap::from([((target, target_port), sequence)]);
        let closed_packet = response_packet(
            target,
            source,
            target_port,
            source_port,
            sequence.wrapping_add(1),
            TcpFlags::RST | TcpFlags::ACK,
        );
        let mut closed_seen = HashSet::new();
        assert_eq!(
            classify_packet(
                &closed_packet,
                &expected,
                source,
                source_port,
                false,
                &mut closed_seen
            ),
            None
        );
        assert_eq!(
            classify_packet(
                &closed_packet,
                &expected,
                source,
                source_port,
                true,
                &mut closed_seen
            ),
            Some(ScanResult {
                host: target,
                port: target_port,
                state: PortState::Closed,
            })
        );
    }

    #[test]
    fn ignores_truncated_and_unexpected_responses() {
        let source = "192.0.2.1".parse().unwrap();
        let target = "198.51.100.2".parse().unwrap();
        let source_port = 50000;
        let target_port = 443;
        let sequence = 0x1234_5678_u32;
        let expected = HashMap::from([((target, target_port), sequence)]);
        let mut truncated = vec![0_u8; 20];
        let mut ipv4 = MutableIpv4Packet::new(&mut truncated).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(20);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4.set_source(target);
        ipv4.set_destination(source);

        let mut seen = HashSet::new();
        assert_eq!(
            classify_packet(&truncated, &expected, source, source_port, false, &mut seen),
            None
        );
        for flags in [TcpFlags::ACK, TcpFlags::SYN | TcpFlags::ACK | TcpFlags::RST] {
            let packet = response_packet(
                target,
                source,
                target_port,
                source_port,
                sequence.wrapping_add(1),
                flags,
            );
            assert_eq!(
                classify_packet(&packet, &expected, source, source_port, true, &mut seen),
                None
            );
        }

        let valid = response_packet(
            target,
            source,
            target_port,
            source_port,
            sequence.wrapping_add(1),
            TcpFlags::SYN | TcpFlags::ACK,
        );
        assert!(
            classify_packet(&valid, &expected, source, source_port, false, &mut seen).is_some()
        );
    }

    #[test]
    fn accepts_wrapped_acknowledgement_number() {
        let source = "192.0.2.1".parse().unwrap();
        let target = "198.51.100.2".parse().unwrap();
        let source_port = 50000;
        let target_port = 443;
        let expected = HashMap::from([((target, target_port), u32::MAX)]);
        let response = response_packet(
            target,
            source,
            target_port,
            source_port,
            0,
            TcpFlags::SYN | TcpFlags::ACK,
        );

        assert!(
            classify_packet(
                &response,
                &expected,
                source,
                source_port,
                false,
                &mut HashSet::new()
            )
            .is_some()
        );
    }

    #[test]
    fn validates_scan_limits_and_configuration() {
        assert_eq!(validate_probe_count(254, 65_535, 15).unwrap(), 16_645_890);
        assert_eq!(validate_probe_count(256, 65_535, 15).unwrap(), 16_776_960);
        assert_eq!(validate_probe_count(MAX_PROBES, 1, 15).unwrap(), MAX_PROBES);
        assert!(validate_probe_count(257, 65_535, 15).is_err());
        assert!(validate_probe_count(MAX_PROBES + 1, 1, 15).is_err());
        assert!(validate_probe_count(usize::MAX, 2, 15).is_err());
        assert!(validate_probe_count(0, 1, 15).is_err());
        assert!(validate_probe_count(1, 0, 15).is_err());
        assert!(validate_probe_count(1, 1, 0).is_err());
    }

    #[test]
    fn rejects_duplicate_scan_config_entries() {
        let host = "192.0.2.1".parse().unwrap();
        let duplicate_targets = ScanConfig::new(vec![host, host], vec![443], host);
        let duplicate_ports = ScanConfig::new(vec![host], vec![443, 443], host);
        let unique = ScanConfig::new(vec![host], vec![80, 443], host);

        assert!(
            expected_responses(&duplicate_targets, 1, 2)
                .unwrap_err()
                .to_string()
                .contains("must be unique")
        );
        assert!(
            expected_responses(&duplicate_ports, 1, 2)
                .unwrap_err()
                .to_string()
                .contains("must be unique")
        );
        assert_eq!(expected_responses(&unique, 1, 2).unwrap().len(), 2);
    }

    #[test]
    fn parses_tcp_services_and_ignores_other_entries() -> Result<()> {
        let ports = services_from(
            "\
# comment
ssh             22/tcp
domain          53/udp
http            80/tcp  www # inline comment
http-alt        80/tcp
malformed
invalid         nope/tcp
zero            0/tcp
",
        )?;

        assert_eq!(ports, [22, 80]);
        Ok(())
    }

    #[test]
    fn rejects_services_file_without_tcp_ports() {
        assert!(services_from("domain 53/udp\n# comment\nmalformed\n").is_err());
    }

    #[test]
    fn reports_missing_services_file_path() {
        let path = services_path();
        let error = ports_from_services(&path).unwrap_err();

        assert!(format!("{error:#}").contains(&path.display().to_string()));
    }

    #[test]
    fn incomplete_scan_error_preserves_context() {
        let partial_result = ScanResult {
            host: "198.51.100.2".parse().unwrap(),
            port: 443,
            state: PortState::Open,
        };
        let incomplete = IncompleteScanError {
            source: anyhow!("send failed"),
            partial_results: vec![partial_result],
            probes_sent: 7,
            total_probes: 10,
        };

        assert_eq!(incomplete.partial_results(), [partial_result]);
        assert_eq!(incomplete.probes_sent(), 7);
        assert_eq!(incomplete.total_probes(), 10);
        assert_eq!(
            incomplete.to_string(),
            "scan stopped after sending 7 of 10 probes"
        );
        assert_eq!(
            std::error::Error::source(&incomplete).unwrap().to_string(),
            "send failed"
        );

        let error: anyhow::Error = incomplete.into();
        assert!(error.downcast_ref::<IncompleteScanError>().is_some());
        assert_eq!(
            format!("{error:#}"),
            "scan stopped after sending 7 of 10 probes: send failed"
        );
    }

    #[test]
    fn estimates_scan_progress() {
        let progress = ScanProgress {
            probes_sent: 25,
            total_probes: 100,
            elapsed: Duration::from_secs(60),
        };

        assert_eq!(progress.percent(), 25);
        assert_eq!(
            progress.estimated_remaining(),
            Some(Duration::from_secs(180))
        );
    }

    #[test]
    fn handles_scan_progress_boundaries() {
        let no_probes = ScanProgress {
            probes_sent: 0,
            total_probes: 0,
            elapsed: Duration::from_secs(60),
        };
        let not_started = ScanProgress {
            total_probes: 100,
            ..no_probes
        };
        let complete = ScanProgress {
            probes_sent: 100,
            ..not_started
        };
        let over_complete = ScanProgress {
            probes_sent: 101,
            ..complete
        };

        assert_eq!(no_probes.percent(), 0);
        assert_eq!(no_probes.estimated_remaining(), None);
        assert_eq!(not_started.percent(), 0);
        assert_eq!(not_started.estimated_remaining(), None);
        assert_eq!(complete.percent(), 100);
        assert_eq!(complete.estimated_remaining(), Some(Duration::ZERO));
        assert_eq!(over_complete.estimated_remaining(), Some(Duration::ZERO));
    }

    #[test]
    fn probe_limit_accommodates_single_port_slash_8() {
        assert_eq!(MAX_PROBES, 16_777_214);
    }

    #[test]
    fn progress_schedule_uses_increasing_intervals() {
        assert_eq!(next_progress_deadline(Duration::from_mins(9)), TEN_MINUTES);
        assert_eq!(next_progress_deadline(TEN_MINUTES), Duration::from_mins(20));
        assert_eq!(next_progress_deadline(Duration::from_mins(50)), ONE_HOUR);
        assert_eq!(next_progress_deadline(ONE_HOUR), Duration::from_mins(90));
    }

    #[test]
    fn progress_schedule_skips_missed_deadlines() {
        assert_eq!(
            advance_progress_deadline(ONE_MINUTE, Duration::from_mins(35)),
            Duration::from_mins(40)
        );
    }
}
