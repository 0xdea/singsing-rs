#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../../../README.md"))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/0xdea/singsing-rs/master/.img/logo_singsing.png"
)]

#[cfg(not(target_os = "linux"))]
compile_error!("singsing-rs only supports Linux (see the Compatibility section in README.md)");

use std::any::Any;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fmt, fs, thread};

use anyhow::{Context as _, anyhow, bail};
use ipnet::Ipv4Net;
use pnet::datalink;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum as ipv4_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum as tcp_checksum};
use pnet::packet::{MutablePacket as _, Packet as _};
use pnet::transport::{
    TransportChannelType, TransportReceiver, ipv4_packet_iter, transport_channel,
};

/// The packet length used for scanning.
const PACKET_LEN: usize = 40;
/// The maximum number of probes to send during a scan.
const MAX_PROBES: usize = 16_777_214;
/// One minute duration.
const ONE_MINUTE: Duration = Duration::from_mins(1);
/// Ten minute duration.
const TEN_MINUTES: Duration = Duration::from_mins(10);
/// Thirty minute duration.
const THIRTY_MINUTES: Duration = Duration::from_mins(30);
/// One hour duration.
const ONE_HOUR: Duration = Duration::from_hours(1);

/// The state inferred from a TCP response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PortState {
    /// A SYN/ACK was received.
    Open,
    /// A RST was received.
    Closed,
}

/// One response produced by a scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ScanResult {
    /// The responding host.
    pub host: Ipv4Addr,
    /// The responding TCP port.
    pub port: u16,
    /// The inferred port state.
    pub state: PortState,
}

impl ScanResult {
    /// Creates a scan result for the given host, port, and inferred state.
    #[must_use]
    pub const fn new(host: Ipv4Addr, port: u16, state: PortState) -> Self {
        Self { host, port, state }
    }
}

/// An error that stopped transmission after part of a scan was sent.
#[derive(Debug)]
pub struct IncompleteScanError {
    /// The error that caused the incomplete scan.
    source: anyhow::Error,
    /// The results received from probes sent before transmission stopped.
    partial_results: Vec<ScanResult>,
    /// The number of probes successfully sent before the error.
    probes_sent: usize,
    /// The total number of probes requested by the scan.
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scan stopped after sending {} of {} probes",
            self.probes_sent, self.total_probes
        )
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "`description`/`cause` are deprecated and `type_id`/`provide` should not be overridden"
)]
impl Error for IncompleteScanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Sending progress reported during a scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ScanProgress {
    /// Number of probes sent so far.
    pub probes_sent: usize,
    /// Total number of probes in the scan.
    pub total_probes: usize,
    /// Time elapsed since sending began.
    pub elapsed: Duration,
}

impl ScanProgress {
    /// Creates a progress snapshot from the given probe counts and elapsed time.
    #[must_use]
    pub const fn new(probes_sent: usize, total_probes: usize, elapsed: Duration) -> Self {
        Self {
            probes_sent,
            total_probes,
            elapsed,
        }
    }

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
#[non_exhaustive]
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
pub fn interface_ipv4(name: &str) -> anyhow::Result<Ipv4Addr> {
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
pub fn parse_targets(input: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
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
/// Duplicate ports are removed and the result is returned in ascending order.
///
/// # Errors
///
/// Returns an error for empty items, reversed ranges, port zero, or values
/// larger than 65535.
pub fn parse_ports(input: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = BTreeSet::new();

    for item in input.split(',') {
        if item.is_empty() {
            bail!("empty port in {input:?}");
        }
        let (start, end) = if let Some((start, end)) = item.split_once('-') {
            if end.contains('-') {
                bail!("invalid port range {item:?}");
            }
            (parse_port(start)?, parse_port(end)?)
        } else {
            let port = parse_port(item)?;
            (port, port)
        };
        if start > end {
            bail!("reversed port range {item:?}");
        }
        ports.extend(start..=end);
    }
    Ok(ports.into_iter().collect())
}

/// Reads TCP ports from a services file (normally `/etc/services`).
///
/// Duplicate ports are removed and the result is returned in ascending order.
///
/// # Errors
///
/// Returns an error when the file cannot be read or contains no TCP services.
pub fn ports_from_services(path: impl AsRef<Path>) -> anyhow::Result<Vec<u16>> {
    let contents = fs::read_to_string(path.as_ref())
        .with_context(|| format!("failed to read {}", path.as_ref().display()))?;
    let mut ports = BTreeSet::new();
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
        {
            ports.insert(port);
        }
    }
    if ports.is_empty() {
        bail!("{} contains no TCP services", path.as_ref().display());
    }
    Ok(ports.into_iter().collect())
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
pub fn scan(config: &ScanConfig) -> anyhow::Result<Vec<ScanResult>> {
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
    on_result: impl FnMut(ScanResult) -> anyhow::Result<()> + Send + 'static,
) -> anyhow::Result<Vec<ScanResult>> {
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
    mut on_result: impl FnMut(ScanResult) -> anyhow::Result<()> + Send + 'static,
    mut on_progress: impl FnMut(ScanProgress) -> anyhow::Result<()>,
) -> anyhow::Result<Vec<ScanResult>> {
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
    let send_result = (|| -> anyhow::Result<()> {
        #[expect(
            clippy::iter_over_hash_type,
            reason = "randomized `HashMap` iteration order is deliberate; see README's Transmission order section"
        )]
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

    let mut results = receive_thread.join().map_err(|payload| {
        anyhow!(
            "packet receiver thread panicked: {}",
            describe_panic_payload(&*payload)
        )
    })??;
    results.sort_unstable_by_key(|result| (u32::from(result.host), result.port));
    if let Err(e) = send_result {
        return Err(IncompleteScanError {
            source: e,
            partial_results: results,
            probes_sent,
            total_probes: probe_count,
        }
        .into());
    }
    Ok(results)
}

/// Extracts a human-readable message from a thread panic payload.
///
/// Falls back to a generic message when the payload isn't the common `&str`
/// or `String` shape produced by `panic!`.
fn describe_panic_payload(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic payload")
}

/// TODO.
fn validate_scan(config: &ScanConfig) -> anyhow::Result<usize> {
    validate_probe_count(
        config.targets.len(),
        config.ports.len(),
        config.bandwidth_kib,
    )
}

/// TODO.
fn usable_target_count(network: Ipv4Net) -> Option<usize> {
    let host_bits = 32_u32.checked_sub(u32::from(network.prefix_len()))?;
    match host_bits {
        0 => Some(1),
        1 => Some(2),
        bits => 1_usize.checked_shl(bits)?.checked_sub(2),
    }
}

/// TODO.
fn expected_responses(
    config: &ScanConfig,
    nonce: u32,
    probe_count: usize,
) -> anyhow::Result<HashMap<(Ipv4Addr, u16), u32>> {
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

/// TODO.
fn validate_probe_count(
    target_count: usize,
    port_count: usize,
    bandwidth_kib: u64,
) -> anyhow::Result<usize> {
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

/// TODO.
fn advance_progress_deadline(mut deadline: Duration, elapsed: Duration) -> Duration {
    while deadline <= elapsed {
        deadline = next_progress_deadline(deadline);
    }
    deadline
}

/// TODO.
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

/// TODO.
fn parse_port(input: &str) -> anyhow::Result<u16> {
    let port: u16 = input
        .parse()
        .with_context(|| format!("invalid TCP port {input:?}"))?;
    if port == 0 {
        bail!("TCP port zero is not supported");
    }
    Ok(port)
}

/// TODO.
#[expect(
    clippy::as_conversions,
    reason = "`nonce() % 16384` is always in `0..16384`, so it always fits in a `u16`"
)]
fn source_port() -> u16 {
    49152 + (nonce() % 16384) as u16
}

/// TODO.
fn nonce() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

/// TODO.
fn sequence(host: Ipv4Addr, port: u16, nonce: u32) -> u32 {
    u32::from(host)
        .rotate_left(13)
        .wrapping_add(u32::from(port).rotate_left(3))
        ^ nonce
}

/// TODO.
fn syn_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; PACKET_LEN];

    #[expect(
        clippy::expect_used,
        reason = "`bytes` is exactly `PACKET_LEN`, sized to fit one IPv4 header and one TCP header, so packet construction cannot fail"
    )]
    let mut ipv4 = MutableIpv4Packet::new(&mut bytes).expect("fixed-size IPv4 packet");
    ipv4.set_version(4);
    ipv4.set_header_length(5);
    ipv4.set_total_length(40);
    #[expect(
        clippy::as_conversions,
        reason = "`sequence >> 16` keeps only the top 16 bits, so it always fits in a `u16`"
    )]
    ipv4.set_identification((sequence >> 16) as u16);
    ipv4.set_ttl(64);
    ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4.set_source(source);
    ipv4.set_destination(destination);

    #[expect(
        clippy::expect_used,
        reason = "`bytes` is exactly `PACKET_LEN`, sized to fit one IPv4 header and one TCP header, so packet construction cannot fail"
    )]
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

/// Configuration for receiving packets.
struct ReceiveConfig<'a> {
    /// Map of expected (source, port) pairs to sequence numbers.
    expected: &'a HashMap<(Ipv4Addr, u16), u32>,
    /// Source IP address to filter packets by.
    source: Ipv4Addr,
    /// Source port to filter packets by.
    source_port: u16,
    /// Whether to show closed connections.
    show_closed: bool,
    /// Atomic flag indicating when to stop receiving.
    done: &'a AtomicBool,
    /// Timeout duration for receiving packets.
    timeout: Duration,
}

/// TODO.
fn receive(
    receiver: &mut TransportReceiver,
    config: &ReceiveConfig<'_>,
    on_result: &mut impl FnMut(ScanResult) -> anyhow::Result<()>,
) -> anyhow::Result<Vec<ScanResult>> {
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

/// TODO.
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
#[expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]
#[expect(clippy::unwrap_used, reason = "tests can use `unwrap`")]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::{env, fs, process};

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
        let ipv4 = Ipv4Packet::new(bytes)?;
        classify_response(&ipv4, expected, source, source_port, show_closed, seen)
    }

    fn services_path() -> PathBuf {
        static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

        let number = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!("singsing-rs-services-{}-{number}", process::id()))
    }

    fn services_from(contents: &str) -> anyhow::Result<Vec<u16>> {
        let path = services_path();
        fs::write(&path, contents)?;
        let result = ports_from_services(&path);
        fs::remove_file(path)?;
        result
    }

    #[test]
    fn parses_ports_ranges_and_duplicates() {
        assert_eq!(parse_ports("22,80,79-81").unwrap(), [22, 79, 80, 81]);
    }

    #[test]
    fn rejects_invalid_ports() {
        parse_ports("0").unwrap_err();
        parse_ports("80-79").unwrap_err();
        parse_ports("65536").unwrap_err();
        parse_ports("22,").unwrap_err();
    }

    #[test]
    fn parses_host_and_network() {
        assert_eq!(
            parse_targets("192.168.2.9").unwrap(),
            ["192.168.2.9".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            parse_targets("192.168.2.0/30").unwrap(),
            [
                "192.168.2.1".parse::<Ipv4Addr>().unwrap(),
                "192.168.2.2".parse::<Ipv4Addr>().unwrap()
            ]
        );
        assert_eq!(
            parse_targets("192.168.2.0/31").unwrap(),
            [
                "192.168.2.0".parse::<Ipv4Addr>().unwrap(),
                "192.168.2.1".parse::<Ipv4Addr>().unwrap()
            ]
        );
        assert_eq!(
            parse_targets("192.168.2.7/32").unwrap(),
            ["192.168.2.7".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn normalizes_host_bits_and_rejects_invalid_targets() {
        assert_eq!(
            parse_targets("192.168.2.7/30").unwrap(),
            [
                "192.168.2.5".parse::<Ipv4Addr>().unwrap(),
                "192.168.2.6".parse::<Ipv4Addr>().unwrap()
            ]
        );
        parse_targets("").unwrap_err();
        parse_targets("not-an-address").unwrap_err();
        parse_targets("192.168.2.1/33").unwrap_err();
    }

    #[test]
    fn rejects_oversized_cidr_before_expansion() {
        let slash_8 = "10.0.0.0/8".parse::<Ipv4Net>().unwrap();
        let slash_31 = "192.168.2.0/31".parse::<Ipv4Net>().unwrap();
        let slash_32 = "192.168.2.1/32".parse::<Ipv4Net>().unwrap();

        assert_eq!(usable_target_count(slash_8), Some(MAX_PROBES));
        assert_eq!(usable_target_count(slash_31), Some(2));
        assert_eq!(usable_target_count(slash_32), Some(1));
        parse_targets("10.0.0.0/7").unwrap_err();
        parse_targets("0.0.0.0/0").unwrap_err();
    }

    #[test]
    #[expect(
        clippy::as_conversions,
        reason = "`sequence >> 16` keeps only the top 16 bits, so it always fits in a `u16`"
    )]
    fn builds_valid_syn_packet() {
        let source = "192.168.2.1".parse().unwrap();
        let destination = "172.16.100.2".parse().unwrap();
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
        let source = "192.168.2.1".parse().unwrap();
        let target = "172.16.100.2".parse().unwrap();
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
        let source = "192.168.2.1".parse().unwrap();
        let target = "172.16.100.2".parse().unwrap();
        let other_target = "172.16.100.3".parse().unwrap();
        let source_port = 50000;
        let target_port = 443;
        let sequence = 0x1234_5678_u32;
        let expected = HashMap::from([((target, target_port), sequence)]);
        let invalid_packets = [
            response_packet(
                target,
                "192.168.2.2".parse().unwrap(),
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
        let source = "192.168.2.1".parse().unwrap();
        let target = "172.16.100.2".parse().unwrap();
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
        let source = "192.168.2.1".parse().unwrap();
        let target = "172.16.100.2".parse().unwrap();
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
        let source = "192.168.2.1".parse().unwrap();
        let target = "172.16.100.2".parse().unwrap();
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
        validate_probe_count(257, 65_535, 15).unwrap_err();
        validate_probe_count(MAX_PROBES + 1, 1, 15).unwrap_err();
        validate_probe_count(usize::MAX, 2, 15).unwrap_err();
        validate_probe_count(0, 1, 15).unwrap_err();
        validate_probe_count(1, 0, 15).unwrap_err();
        validate_probe_count(1, 1, 0).unwrap_err();
    }

    #[test]
    fn rejects_duplicate_scan_config_entries() {
        let host = "192.168.2.1".parse().unwrap();
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
    fn parses_tcp_services_and_ignores_other_entries() -> anyhow::Result<()> {
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
        services_from("domain 53/udp\n# comment\nmalformed\n").unwrap_err();
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
            host: "172.16.100.2".parse().unwrap(),
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
            Error::source(&incomplete).unwrap().to_string(),
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
    fn describes_str_panic_payload() {
        let payload: Box<dyn Any + Send> = Box::new("boom");
        assert_eq!(describe_panic_payload(&*payload), "boom");
    }

    #[test]
    fn describes_string_panic_payload() {
        let payload: Box<dyn Any + Send> = Box::new(String::from("boom"));
        assert_eq!(describe_panic_payload(&*payload), "boom");
    }

    #[test]
    fn describes_unrecognized_panic_payload() {
        let payload: Box<dyn Any + Send> = Box::new(42_i32);
        assert_eq!(describe_panic_payload(&*payload), "unknown panic payload");
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
