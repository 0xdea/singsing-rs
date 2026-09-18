#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../../../README.md"))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/0xdea/singsing-rs/master/.img/logo_singsing.png"
)]
#![expect(
    clippy::pub_use,
    reason = "the crate's one `pub use` re-exports a foreign `ipnet` type that already appears \
              in our public API (`TargetsError`), the deliberate exception this lint warns \
              against as a module-layout anti-pattern; `use` items can't carry the attribute \
              themselves, so it's set here instead"
)]

#[cfg(not(target_os = "linux"))]
compile_error!("singsing-rs only supports Linux (see the Compatibility section in README.md)");

use std::any::Any;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::num::ParseIntError;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{fs, io, thread};

use pnet::datalink;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum};
use pnet::packet::{MutablePacket as _, Packet as _};
use pnet::transport::{
    TransportChannelType, TransportReceiver, ipv4_packet_iter, transport_channel,
};

/// The packet length used for scanning.
const PACKET_LEN: usize = 40;
/// The receive buffer's length, reused for every packet read on the raw socket.
///
/// The socket is a `Layer3` raw socket, so the kernel delivers every matching IPv4/TCP packet on
/// the host to it, not just replies to this scan's own probes (unrelated packets are filtered out
/// in userspace by `classify_response`). The buffer must therefore be large enough for the
/// largest packet any such traffic could deliver, not just this scan's own `PACKET_LEN`-sized
/// probes and replies: a too-small buffer silently truncates an oversized read rather than
/// erroring. `1 MiB` comfortably exceeds the largest possible IPv4 packet (65,535 bytes).
const RECEIVE_BUFFER_LEN: usize = 1 << 20;

/// The maximum number of probes to send during a scan.
const MAX_PROBES: usize = 16_777_214;
/// The maximum time to listen for late replies after the final probe.
const MAX_TIMEOUT: Duration = Duration::from_hours(24);

/// One minute duration.
const ONE_MINUTE: Duration = Duration::from_mins(1);
/// Ten minute duration.
const TEN_MINUTES: Duration = Duration::from_mins(10);
/// Thirty minute duration.
const THIRTY_MINUTES: Duration = Duration::from_mins(30);
/// One hour duration.
const ONE_HOUR: Duration = Duration::from_hours(1);

/// A TCP port number.
pub type Port = u16;
/// A TCP sequence or acknowledgement number.
type SeqNum = u32;
/// Maps each target host/port pair to its expected TCP sequence number.
type ExpectedResponses = HashMap<(Ipv4Addr, Port), SeqNum>;

/// The error type returned by `scan`/`scan_with_callback`/`scan_with_callbacks`'s `on_result` and
/// `on_progress` callbacks.
///
/// Callbacks are caller-defined and can fail for reasons this crate can't enumerate in advance, so
/// their error is boxed rather than typed.
pub type CallbackError = Box<dyn Error + Send + Sync>;

/// Foreign types from `ipnet` that appear in this crate's public API (see [`TargetsError`]).
///
/// Re-exported so callers can name them without adding `ipnet` as a separate direct dependency,
/// and so that a semver-breaking `ipnet` upgrade shows up as a `singsing-rs` API change too.
pub use ipnet::{AddrParseError, Ipv4Net};

/// An error resolving a network interface's IPv4 address.
///
/// # Examples
///
/// ```
/// use singsing_rs::{InterfaceError, interface_ipv4};
///
/// let name = "singsing-rs-example-missing-interface";
/// match interface_ipv4(name) {
///     Err(InterfaceError::NotFound { name: n }) => assert_eq!(n, name),
///     other => panic!("unexpected result: {other:?}"),
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InterfaceError {
    /// No interface with the given name exists.
    #[error("network interface {name:?} does not exist")]
    NotFound {
        /// The requested interface name.
        name: String,
    },
    /// The interface exists but has no IPv4 address.
    #[error("network interface {name:?} has no IPv4 address")]
    NoIpv4 {
        /// The requested interface name.
        name: String,
    },
}

/// An error parsing scan targets.
///
/// # Examples
///
/// ```
/// use singsing_rs::{TargetsError, parse_targets};
///
/// assert!(matches!(
///     parse_targets("10.0.0.0/7"),
///     Err(TargetsError::TooLarge { .. })
/// ));
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TargetsError {
    /// The input contained `/` but was not a valid IPv4 network.
    #[error("invalid IPv4 network")]
    InvalidNetwork(#[source] AddrParseError),
    /// The input was not a valid IPv4 address.
    #[error("invalid IPv4 address")]
    InvalidAddress(#[source] AddrParseError),
    /// The network contains more usable addresses than the scan limit allows.
    #[error("{network} contains more than {max} usable addresses; split networks larger than a /8")]
    TooLarge {
        /// The oversized network.
        network: Ipv4Net,
        /// The maximum number of usable addresses.
        max: usize,
    },
}

/// An error parsing or reading scan ports.
///
/// # Examples
///
/// ```
/// use singsing_rs::{PortsError, parse_ports};
///
/// assert!(matches!(parse_ports("0"), Err(PortsError::PortZero)));
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PortsError {
    /// A comma-separated item was empty.
    #[error("empty port in {input:?}")]
    EmptyItem {
        /// The full port list that contained the empty item.
        input: String,
    },
    /// A range contained more than one `-`.
    #[error("invalid port range {item:?}")]
    InvalidRange {
        /// The malformed range item.
        item: String,
    },
    /// A range's start was greater than its end.
    #[error("reversed port range {item:?}")]
    ReversedRange {
        /// The reversed range item.
        item: String,
    },
    /// A port was not a valid `u16`.
    #[error("invalid TCP port {input:?}")]
    InvalidPort {
        /// The unparsable port text.
        input: String,
        /// The underlying integer parse error.
        #[source]
        source: ParseIntError,
    },
    /// Port zero was requested, which is not supported.
    #[error("TCP port zero is not supported")]
    PortZero,
    /// The services file could not be read.
    #[error("failed to read {}", path.display())]
    ServicesFileRead {
        /// The services file path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The services file contained no TCP services.
    #[error("{} contains no TCP services", path.display())]
    NoTcpServices {
        /// The services file path.
        path: PathBuf,
    },
}

/// An error running a scan.
///
/// # Examples
///
/// ```
/// use singsing_rs::{ScanConfig, ScanError, scan};
/// use std::net::Ipv4Addr;
///
/// let config = ScanConfig::new(Vec::new(), vec![80], Ipv4Addr::LOCALHOST);
/// assert!(matches!(scan(&config), Err(ScanError::EmptyScan)));
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// The scan had no targets or no ports.
    #[error("at least one target and one port are required")]
    EmptyScan,
    /// The configured bandwidth was zero.
    #[error("bandwidth must be greater than zero")]
    ZeroBandwidth,
    /// The configured bandwidth overflowed while converting to a packet rate.
    #[error("bandwidth is too large")]
    BandwidthOverflow,
    /// The configured late-reply timeout exceeds the maximum.
    #[error("timeout of {timeout:?} exceeds the maximum of {max:?}")]
    TimeoutTooLarge {
        /// The requested timeout.
        timeout: Duration,
        /// The maximum allowed timeout.
        max: Duration,
    },
    /// Multiplying the target and port counts overflowed `usize`.
    #[error("scan size overflow")]
    ScanSizeOverflow,
    /// The scan exceeds the maximum number of probes.
    #[error(
        "scan contains {probe_count} probes; maximum is {max} \
         (one port on a /8 or all 65,535 ports on a /24); split larger scans"
    )]
    TooManyProbes {
        /// The requested probe count.
        probe_count: usize,
        /// The maximum allowed probe count.
        max: usize,
    },
    /// `ScanConfig` contained a duplicate target/port pair.
    #[error("duplicate host/port pair {host}:{port}; ScanConfig targets and ports must be unique")]
    DuplicatePair {
        /// The duplicated target.
        host: Ipv4Addr,
        /// The duplicated port.
        port: Port,
    },
    /// Creating the raw transport socket failed.
    #[error("failed to create raw socket (run as root or grant CAP_NET_RAW)")]
    SocketCreation(#[source] io::Error),
    /// Receiving a raw packet failed.
    #[error("failed to receive raw packet")]
    Receive(#[source] io::Error),
    /// The packet receiver thread panicked.
    #[error("packet receiver thread panicked: {0}")]
    ReceiverPanicked(String),
    /// Transmission stopped after part of the scan was sent.
    #[error(transparent)]
    Incomplete(IncompleteScanError),
    /// The `on_result` callback returned an error.
    #[error("callback failed")]
    Callback(#[source] CallbackError),
}

/// An error that stopped probe transmission mid-scan.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// The fixed-size SYN packet buffer could not be parsed back into an IPv4 packet.
    #[error("failed to construct IPv4 packet")]
    PacketConstruction,
    /// Sending a probe failed.
    #[error("failed to send SYN to {host}:{port}")]
    Io {
        /// The probe's destination host.
        host: Ipv4Addr,
        /// The probe's destination port.
        port: Port,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The `on_progress` callback returned an error.
    #[error("callback failed")]
    Callback(#[source] CallbackError),
}

/// An error that stopped transmission after part of a scan was executed.
///
/// `IncompleteScanError` has no public constructor; callers only ever obtain one from
/// [`ScanError::Incomplete`], returned by [`scan`]/[`scan_with_callback`]/[`scan_with_callbacks`].
///
/// # Examples
///
/// ```no_run
/// use singsing_rs::{ScanConfig, ScanError, scan};
/// use std::net::Ipv4Addr;
///
/// let config = ScanConfig::new(vec![Ipv4Addr::LOCALHOST], vec![80], Ipv4Addr::LOCALHOST);
/// if let Err(ScanError::Incomplete(incomplete)) = scan(&config) {
///     eprintln!(
///         "sent {} of {} probes before stopping",
///         incomplete.probes_sent(),
///         incomplete.total_probes()
///     );
///     for result in incomplete.partial_results() {
///         println!("{result:?}");
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[error("scan stopped after sending {probes_sent} of {total_probes} probes")]
pub struct IncompleteScanError {
    /// The error that caused the incomplete scan.
    #[source]
    source: SendError,
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

/// Configuration for one SYN scan.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct ScanConfig {
    /// IPv4 addresses to scan.
    ///
    /// Addresses must be unique.
    pub targets: Vec<Ipv4Addr>,
    /// TCP ports to scan.
    ///
    /// Ports must be unique.
    pub ports: Vec<Port>,
    /// Source IPv4 address assigned to the selected interface.
    pub source: Ipv4Addr,
    /// Approximate maximum packet bandwidth in KiB/s.
    ///
    /// [`ScanConfig::new`] defaults this to 15 KiB/s, or approximately 384 probes per second
    /// with the scanner's 40-byte packet accounting.
    pub bandwidth_kib: u64,
    /// Time to listen for late replies after the final probe.
    ///
    /// Capped at 24 hours; [`ScanConfig::new`] defaults this to 30 seconds.
    pub timeout: Duration,
    /// Whether RST responses should be returned.
    pub show_closed: bool,
}

impl ScanConfig {
    /// Creates a configuration with 15 KiB/s bandwidth and a 30-second late-reply timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use singsing_rs::ScanConfig;
    /// use std::net::Ipv4Addr;
    ///
    /// let target: Ipv4Addr = "192.168.2.10".parse()?;
    /// let mut config = ScanConfig::new(vec![target], vec![22, 80, 443], Ipv4Addr::LOCALHOST);
    /// config.show_closed = true;
    ///
    /// assert_eq!(config.bandwidth_kib, 15);
    /// assert!(config.show_closed);
    /// # Ok::<(), std::net::AddrParseError>(())
    /// ```
    #[must_use]
    pub const fn new(targets: Vec<Ipv4Addr>, ports: Vec<Port>, source: Ipv4Addr) -> Self {
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

/// Probe sending progress reported during a scan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
    ///
    /// Returns `None` before the first probe is sent, since no rate can be estimated yet.
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

/// The state inferred from a TCP response.
///
/// # Examples
///
/// ```
/// use singsing_rs::{PortState, ScanResult};
/// use std::net::Ipv4Addr;
///
/// let result = ScanResult::new(Ipv4Addr::LOCALHOST, 443, PortState::Open);
/// match result.state {
///     PortState::Open => println!("{}:{} is open", result.host, result.port),
///     PortState::Closed => println!("{}:{} is closed", result.host, result.port),
///     _ => println!("{}:{} is some other state", result.host, result.port),
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum PortState {
    /// A SYN/ACK was received.
    Open,
    /// A RST was received.
    Closed,
}

/// One response produced by a scan.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct ScanResult {
    /// The responding host.
    pub host: Ipv4Addr,
    /// The responding TCP port.
    pub port: Port,
    /// The inferred port state.
    pub state: PortState,
}

impl ScanResult {
    /// Creates a scan result for the given host, port, and inferred state.
    #[must_use]
    pub const fn new(host: Ipv4Addr, port: Port, state: PortState) -> Self {
        Self { host, port, state }
    }
}

/// Resolves the first IPv4 address assigned to a network interface.
///
/// # Errors
///
/// Returns an error if the interface does not exist or has no IPv4 address.
///
/// # Examples
///
/// ```
/// use singsing_rs::{InterfaceError, interface_ipv4};
/// use std::net::Ipv4Addr;
///
/// assert_eq!(interface_ipv4("lo")?, Ipv4Addr::LOCALHOST);
/// # Ok::<(), InterfaceError>(())
/// ```
pub fn interface_ipv4(name: &str) -> Result<Ipv4Addr, InterfaceError> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|interface| interface.name == name)
        .ok_or_else(|| InterfaceError::NotFound {
            name: name.to_owned(),
        })?;

    interface
        .ips
        .into_iter()
        .find_map(|network| match network.ip() {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| InterfaceError::NoIpv4 {
            name: name.to_owned(),
        })
}

/// Expands an IPv4 address or CIDR into scan targets.
///
/// Network and broadcast addresses are omitted for prefixes from `/0` through `/30`. Both
/// addresses of a `/31` are included, as is the single address of a `/32`, matching
/// [`Ipv4Net::hosts`].
///
/// # Errors
///
/// Returns an error for malformed IPv4/CIDR input or a network containing more usable addresses
/// than a `/8`.
///
/// # Examples
///
/// ```
/// use singsing_rs::parse_targets;
/// use std::net::Ipv4Addr;
///
/// assert_eq!(
///     parse_targets("192.168.2.0/30")?,
///     ["192.168.2.1".parse::<Ipv4Addr>()?, "192.168.2.2".parse()?]
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_targets(input: &str) -> Result<Vec<Ipv4Addr>, TargetsError> {
    let network = if input.contains('/') {
        input.parse().map_err(TargetsError::InvalidNetwork)?
    } else {
        format!("{input}/32")
            .parse()
            .map_err(TargetsError::InvalidAddress)?
    };

    if usable_target_count(network).is_none_or(|count| count > MAX_PROBES) {
        return Err(TargetsError::TooLarge {
            network,
            max: MAX_PROBES,
        });
    }

    Ok(network.hosts().collect())
}

/// Parses comma-separated ports and inclusive ranges such as `21-23,80,443`.
///
/// Duplicate ports are removed and the result is returned in ascending order.
///
/// # Errors
///
/// Returns an error for empty items, reversed ranges, port zero, or values larger than 65535.
///
/// # Examples
///
/// ```
/// use singsing_rs::{PortsError, parse_ports};
///
/// assert_eq!(parse_ports("22,80,79-81")?, [22, 79, 80, 81]);
/// # Ok::<(), PortsError>(())
/// ```
pub fn parse_ports(input: &str) -> Result<Vec<Port>, PortsError> {
    let mut ports = BTreeSet::new();

    for item in input.split(',') {
        if item.is_empty() {
            return Err(PortsError::EmptyItem {
                input: input.to_owned(),
            });
        }

        let (start, end) = if let Some((start, end)) = item.split_once('-') {
            if end.contains('-') {
                return Err(PortsError::InvalidRange {
                    item: item.to_owned(),
                });
            }
            // Port range.
            (parse_port(start)?, parse_port(end)?)
        } else {
            // Single port.
            let port = parse_port(item)?;
            (port, port)
        };

        // After both halves are known to be valid ports, check for a reversed range.
        if start > end {
            return Err(PortsError::ReversedRange {
                item: item.to_owned(),
            });
        }

        // Insert the whole range at once.
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
///
/// # Examples
///
/// ```
/// use singsing_rs::ports_from_services;
/// use std::fs;
///
/// let path = std::env::temp_dir().join("singsing-rs-doctest-services");
/// fs::write(&path, "ssh 22/tcp\ndomain 53/udp\nhttp 80/tcp\n")?;
///
/// let ports = ports_from_services(&path)?;
/// fs::remove_file(&path)?;
///
/// assert_eq!(ports, [22, 80]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn ports_from_services(path: impl AsRef<Path>) -> Result<Vec<Port>, PortsError> {
    let contents =
        fs::read_to_string(path.as_ref()).map_err(|source| PortsError::ServicesFileRead {
            path: path.as_ref().to_path_buf(),
            source,
        })?;
    let mut ports = BTreeSet::new();

    for line in contents.lines() {
        // Break lines into fields, skipping comments and empty lines.
        let mut fields = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();

        // Skip service names and extract valid TCP ports to insert into the set.
        let _service = fields.next();
        if let Some(port_protocol) = fields.next()
            && let Some((port, "tcp")) = port_protocol.split_once('/')
            && let Ok(port) = parse_port(port)
        {
            ports.insert(port);
        }
    }

    if ports.is_empty() {
        return Err(PortsError::NoTcpServices {
            path: path.as_ref().to_path_buf(),
        });
    }

    Ok(ports.into_iter().collect())
}

/// Executes a Linux IPv4 SYN scan.
///
/// No reply means filtered or unreachable and therefore produces no result. Raw sockets require
/// root or `CAP_NET_RAW`.
///
/// # Errors
///
/// Returns an error for an empty or excessively large scan, invalid bandwidth, an excessive
/// timeout, duplicate targets or ports, raw socket permission failures, packet send failures,
/// or receiver failures. A transmission-phase failure is returned as [`IncompleteScanError`],
/// which retains results received for successfully sent probes.
///
/// # Examples
///
/// ```no_run
/// use singsing_rs::{ScanConfig, interface_ipv4, parse_targets, scan};
///
/// let source = interface_ipv4("eth0")?;
/// let targets = parse_targets("192.168.2.10")?;
/// let config = ScanConfig::new(targets, vec![22, 80, 443], source);
///
/// for result in scan(&config)? {
///     println!("{result:?}");
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn scan(config: &ScanConfig) -> Result<Vec<ScanResult>, ScanError> {
    scan_with_callbacks(config, |_| Ok(()), |_| Ok(()))
}

/// Executes a SYN scan and calls `on_result` as each response arrives.
///
/// Results are still returned in sorted order after the scan. The callback is useful for
/// interactive clients that need immediate per-result feedback.
///
/// # Errors
///
/// Returns the same errors as [`scan`], along with errors returned by `on_result`.
///
/// # Examples
///
/// ```no_run
/// use singsing_rs::{ScanConfig, interface_ipv4, parse_targets, scan_with_callback};
///
/// let source = interface_ipv4("eth0")?;
/// let targets = parse_targets("192.168.2.10")?;
/// let config = ScanConfig::new(targets, vec![22, 80, 443], source);
///
/// scan_with_callback(&config, |result| {
///     println!("{result:?}");
///     Ok(())
/// })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn scan_with_callback(
    config: &ScanConfig,
    on_result: impl FnMut(ScanResult) -> Result<(), CallbackError> + Send + 'static,
) -> Result<Vec<ScanResult>, ScanError> {
    scan_with_callbacks(config, on_result, |_| Ok(()))
}

/// Executes a SYN scan with callbacks for results and sending progress.
///
/// `on_result` runs as each response arrives. It needs to be `Send + 'static` because it gets
/// moved into the spawned receiver thread. While probes are being sent, `on_progress` runs every
/// minute for the first ten minutes, every ten minutes through the first hour, and every
/// thirty minutes thereafter.
///
/// # Errors
///
/// Returns the same errors as [`scan`], along with errors returned by either callback.
///
/// # Examples
///
/// ```no_run
/// use singsing_rs::{ScanConfig, interface_ipv4, parse_targets, scan_with_callbacks};
///
/// let source = interface_ipv4("eth0")?;
/// let targets = parse_targets("192.168.2.10")?;
/// let config = ScanConfig::new(targets, vec![22, 80, 443], source);
///
/// scan_with_callbacks(
///     &config,
///     |result| {
///         println!("{result:?}");
///         Ok(())
///     },
///     |progress| {
///         eprintln!("{}% complete", progress.percent());
///         Ok(())
///     },
/// )?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn scan_with_callbacks(
    config: &ScanConfig,
    mut on_result: impl FnMut(ScanResult) -> Result<(), CallbackError> + Send + 'static,
    mut on_progress: impl FnMut(ScanProgress) -> Result<(), CallbackError>,
) -> Result<Vec<ScanResult>, ScanError> {
    // Validate the scan configuration and build the expected responses table.
    let probe_count = validate_scan(config)?;
    let source_port = source_port();
    let nonce = nonce();
    let expected = Arc::new(expected_responses(config, nonce, probe_count)?);

    // Create the transport channel (`Layer3` raw socket).
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut sender, mut receiver) =
        transport_channel(RECEIVE_BUFFER_LEN, protocol).map_err(ScanError::SocketCreation)?;

    // Spawn the receiver thread.
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

    // Compute the send interval based on the requested bandwidth.
    //
    // Unlike `timeout`, `bandwidth_kib` has no upper sanity limit, only the overflow guard below
    // (~u64::MAX / 1024 KiB/s). An extreme but non-overflowing value drives `packets_per_second`
    // high enough that this division floors to zero, making `interval` `Duration::ZERO`; the send
    // loop then never sleeps, so the practical effect is unthrottled sending rather than a panic
    // or incorrect behavior, so no cap is needed.
    let bytes_per_second = config
        .bandwidth_kib
        .checked_mul(1024)
        .ok_or(ScanError::BandwidthOverflow)?;
    let packets_per_second = (bytes_per_second / 40).max(1);
    let interval = Duration::from_nanos(1_000_000_000_u64 / packets_per_second);

    // Send loop.
    //
    // Runs as an inline closure so a mid-loop error can be captured without immediately returning
    // from the outer function. This way, a send failure doesn't abort the receiver early, but just
    // gets folded into the final error once both sides are done, so partial results are not lost.
    let mut next_send = Instant::now();
    let started = next_send;
    let mut next_progress = ONE_MINUTE;
    let mut probes_sent = 0;
    let send_result = (|| -> Result<(), SendError> {
        #[expect(
            clippy::iter_over_hash_type,
            reason = "randomized `HashMap` iteration order is deliberate; see README's Transmission order section"
        )]
        for (&(host, port), &sequence) in expected.iter() {
            // Build one TCP SYN packet and send it.
            let packet = syn_packet(config.source, host, source_port, port, sequence);
            let ipv4_packet =
                MutableIpv4Packet::owned(packet).ok_or(SendError::PacketConstruction)?;
            sender
                .send_to(ipv4_packet, IpAddr::V4(host))
                .map_err(|io_error| SendError::Io {
                    host,
                    port,
                    source: io_error,
                })?;
            probes_sent += 1;

            // Throttle the send loop to the requested bandwidth.
            next_send += interval;
            if let Some(delay) = next_send.checked_duration_since(Instant::now()) {
                thread::sleep(delay);
            }

            // Track progress and invoke the callback if necessary.
            //
            // Unlike a failing `on_result` on the receive side, a failing `on_progress` here stops
            // the send loop like any other send-loop error, so it's preserved as `SendError::Callback`
            // inside `IncompleteScanError` (with partial results and counts), not discarded.
            let now = Instant::now();
            let elapsed = now.duration_since(started);
            if elapsed >= next_progress {
                on_progress(ScanProgress {
                    probes_sent,
                    total_probes: probe_count,
                    elapsed,
                })
                .map_err(SendError::Callback)?;
                next_progress = advance_progress_deadline(next_progress, elapsed);
            }
        }

        Ok(())
    })();

    // Whatever happens, unconditionally mark the send loop as done.
    //
    // Everything this thread wrote to memory before this store is guaranteed to be visible to the
    // receive thread that later does an `Acquire` load on `done`.
    done.store(true, Ordering::Release);

    // Join the receive thread and collect the results.
    //
    // The first `?` (via `map_err`) converts the panic payload to a `ScanError::ReceiverPanicked`.
    // The second `?` propagates any other error from the receive thread.
    let mut results = receive_thread.join().map_err(|payload| {
        ScanError::ReceiverPanicked(describe_panic_payload(&*payload).to_owned())
    })??;

    // Sort the results by host and port.
    results.sort_unstable_by_key(|result| (u32::from(result.host), result.port));

    // If the send loop failed mid-scan, return an `IncompleteScanError` with the collected results.
    if let Err(error) = send_result {
        return Err(ScanError::Incomplete(IncompleteScanError {
            source: error,
            partial_results: results,
            probes_sent,
            total_probes: probe_count,
        }));
    }

    Ok(results)
}

/// Returns the number of usable addresses in an IPv4 network.
///
/// Both addresses of a `/31` count as usable and a `/32` counts as one; otherwise the network
/// and broadcast addresses are excluded. Returns `None` on prefix-length arithmetic overflow.
fn usable_target_count(network: Ipv4Net) -> Option<usize> {
    let host_bits = 32_u32.checked_sub(u32::from(network.prefix_len()))?;

    match host_bits {
        0 => Some(1),
        1 => Some(2),
        bits => 1_usize.checked_shl(bits)?.checked_sub(2),
    }
}

/// Parses a single TCP port, rejecting port zero.
fn parse_port(input: &str) -> Result<Port, PortsError> {
    let port = input.parse().map_err(|source| PortsError::InvalidPort {
        input: input.to_owned(),
        source,
    })?;

    if port == 0 {
        return Err(PortsError::PortZero);
    }

    Ok(port)
}

/// Validates a scan configuration and returns its total probe count.
fn validate_scan(config: &ScanConfig) -> Result<usize, ScanError> {
    validate_probe_count(
        config.targets.len(),
        config.ports.len(),
        config.bandwidth_kib,
        config.timeout,
    )
}

/// Validates scan size and configuration limits, returning the total probe count.
///
/// Rejects an empty target or port list, zero bandwidth, a late-reply timeout above
/// [`MAX_TIMEOUT`], and a target * port product above [`MAX_PROBES`].
fn validate_probe_count(
    target_count: usize,
    port_count: usize,
    bandwidth_kib: u64,
    timeout: Duration,
) -> Result<usize, ScanError> {
    if target_count == 0 || port_count == 0 {
        return Err(ScanError::EmptyScan);
    }
    if bandwidth_kib == 0 {
        return Err(ScanError::ZeroBandwidth);
    }
    if timeout > MAX_TIMEOUT {
        return Err(ScanError::TimeoutTooLarge {
            timeout,
            max: MAX_TIMEOUT,
        });
    }

    let probe_count = target_count
        .checked_mul(port_count)
        .ok_or(ScanError::ScanSizeOverflow)?;
    if probe_count > MAX_PROBES {
        return Err(ScanError::TooManyProbes {
            probe_count,
            max: MAX_PROBES,
        });
    }

    Ok(probe_count)
}

/// Picks a random ephemeral TCP source port in the `49152..=65535` range, reused for every probe in the scan.
#[expect(
    clippy::as_conversions,
    reason = "`nonce() % 16384` is always in `0..16384`, so it always fits in a `u16`"
)]
fn source_port() -> Port {
    49152 + (nonce() % 16384) as u16
}

/// Returns a per-scan random nonce derived from the current sub-second time.
///
/// This nonce is not cryptographically robust, but it is sufficient for our purposes.
fn nonce() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
}

/// Builds the expected-response table mapping each target/port pair to its deterministic sequence
/// number.
///
/// Returns [`ScanError::DuplicatePair`] for a duplicate target/port pair.
fn expected_responses(
    config: &ScanConfig,
    nonce: u32,
    probe_count: usize,
) -> Result<ExpectedResponses, ScanError> {
    let mut expected = HashMap::with_capacity(probe_count);

    for &host in &config.targets {
        for &port in &config.ports {
            if expected
                .insert((host, port), sequence(host, port, nonce))
                .is_some()
            {
                return Err(ScanError::DuplicatePair { host, port });
            }
        }
    }
    Ok(expected)
}

/// Derives the deterministic expected TCP sequence number for a host/port pair, given the nonce.
///
/// This allows to correlate a reply with a probe, without the need to track live per-connection
/// state in memory. This classic stateless-SYN-scanning trick is robust against accidental
/// misclassification, but it does not provide any protection against a deliberately hostile
/// target trying to defeat correlation.
fn sequence(host: Ipv4Addr, port: Port, nonce: u32) -> SeqNum {
    u32::from(host)
        .rotate_left(13)
        .wrapping_add(u32::from(port).rotate_left(3))
        ^ nonce
}

/// Builds a raw 40-byte IPv4/TCP SYN packet for one probe.
fn syn_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: Port,
    destination_port: Port,
    sequence: SeqNum,
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
    tcp.set_checksum(ipv4_checksum(&tcp.to_immutable(), &source, &destination));
    ipv4.set_checksum(checksum(&ipv4.to_immutable()));

    bytes
}

/// Advances a progress deadline past `elapsed`, skipping any missed intervals.
fn advance_progress_deadline(mut deadline: Duration, elapsed: Duration) -> Duration {
    while deadline <= elapsed {
        deadline = next_progress_deadline(deadline);
    }
    deadline
}

/// Returns the next progress deadline after `previous`.
///
/// Follows a growing schedule: every minute for the first ten minutes, every ten minutes through
/// the first hour, then every thirty minutes thereafter.
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

/// Configuration for receiving packets.
struct ReceiveConfig<'a> {
    /// Map of expected (source, port) pairs to sequence numbers.
    expected: &'a ExpectedResponses,
    /// Source IP address to filter packets by.
    source: Ipv4Addr,
    /// Source port to filter packets by.
    source_port: Port,
    /// Whether to show closed connections.
    show_closed: bool,
    /// Atomic flag indicating when to stop receiving.
    done: &'a AtomicBool,
    /// Timeout duration for receiving packets.
    timeout: Duration,
}

/// Reads and classifies raw packets until sending is done and the late-reply timeout elapses,
/// returning accepted results in arrival order.
fn receive(
    receiver: &mut TransportReceiver,
    config: &ReceiveConfig<'_>,
    on_result: &mut impl FnMut(ScanResult) -> Result<(), CallbackError>,
) -> Result<Vec<ScanResult>, ScanError> {
    let mut iterator = ipv4_packet_iter(receiver);
    let mut results = Vec::new();
    let mut seen = HashSet::new();
    let mut deadline = None;

    loop {
        // Check the done flag and set the deadline only once.
        if config.done.load(Ordering::Acquire) && deadline.is_none() {
            deadline = Some(Instant::now() + config.timeout);
        }
        // Break the loop if the deadline has passed.
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }

        // Calculate the wait duration based on the deadline (capped at 100ms).
        let wait = deadline
            .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100));

        // Try to read a packet, blocking for at most `wait`.
        //
        // A genuine I/O error becomes a `ScanError::Receive` and ends the whole scan.
        // If no packet is received within `wait`, continue to the next iteration.
        let Some((ipv4, _)) = iterator
            .next_with_timeout(wait)
            .map_err(ScanError::Receive)?
        else {
            continue;
        };

        // If a packet is received, classify it and add it to the results.
        //
        // If the packet is not a valid response, it is ignored and the scan continues.
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

        // Call the user-defined callback with the accepted result and then add it to the results
        // in raw arrival order. Unlike a send-loop failure, a failing callback here currently
        // discards `results` entirely rather than preserving it via `IncompleteScanError`.
        on_result(result).map_err(ScanError::Callback)?;
        results.push(result);
    }

    Ok(results)
}

/// Correlates one received IPv4 packet against the expected-response table.
///
/// Returns `Some` only for a not-yet-seen reply whose destination address and port match the
/// scan's source, whose source host/port matches an actual probe, and whose acknowledgement
/// number matches the expected sequence.
fn classify_response(
    ipv4: &Ipv4Packet<'_>,
    expected: &ExpectedResponses,
    source: Ipv4Addr,
    source_port: Port,
    show_closed: bool,
    seen: &mut HashSet<(Ipv4Addr, Port)>,
) -> Option<ScanResult> {
    if ipv4.get_destination() != source {
        return None;
    }

    let tcp = TcpPacket::new(ipv4.payload())?;
    let key = (ipv4.get_source(), tcp.get_source());
    let (host, port) = key;
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

    // Return `None` if the key is already seen, to avoid duplicate results.
    if !seen.insert(key) {
        return None;
    }

    Some(ScanResult { host, port, state })
}

/// Extracts a human-readable message from a thread panic payload.
///
/// Falls back to a generic message when the payload isn't the common `&str` or `String` shape
/// produced by `panic!`.
fn describe_panic_payload(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown panic payload")
}

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]
#[expect(clippy::unwrap_used, reason = "tests can use `unwrap`")]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::{env, fs, io, process};

    use super::*;

    fn response_packet(
        remote: Ipv4Addr,
        local: Ipv4Addr,
        remote_port: Port,
        local_port: Port,
        acknowledgement: SeqNum,
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
        expected: &ExpectedResponses,
        source: Ipv4Addr,
        source_port: Port,
        show_closed: bool,
        seen: &mut HashSet<(Ipv4Addr, Port)>,
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
        let result = ports_from_services(&path).map_err(anyhow::Error::from);
        fs::remove_file(path)?;
        result
    }

    #[test]
    fn parses_ports_ranges_and_duplicates() {
        assert_eq!(parse_ports("22,80,79-81").unwrap(), [22, 79, 80, 81]);
    }

    #[test]
    fn rejects_invalid_ports() {
        assert!(matches!(parse_ports("0"), Err(PortsError::PortZero)));
        assert!(matches!(
            parse_ports("80-79"),
            Err(PortsError::ReversedRange { item }) if item == "80-79"
        ));
        assert!(matches!(
            parse_ports("65536"),
            Err(PortsError::InvalidPort { input, .. }) if input == "65536"
        ));
        assert!(matches!(
            parse_ports("22,"),
            Err(PortsError::EmptyItem { input }) if input == "22,"
        ));
        assert!(matches!(
            parse_ports("1-2-3"),
            Err(PortsError::InvalidRange { item }) if item == "1-2-3"
        ));
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
        assert!(matches!(
            parse_targets(""),
            Err(TargetsError::InvalidAddress(_))
        ));
        assert!(matches!(
            parse_targets("not-an-address"),
            Err(TargetsError::InvalidAddress(_))
        ));
        assert!(matches!(
            parse_targets("192.168.2.1/33"),
            Err(TargetsError::InvalidNetwork(_))
        ));
    }

    #[test]
    fn rejects_oversized_cidr_before_expansion() {
        let slash_8 = "10.0.0.0/8".parse::<Ipv4Net>().unwrap();
        let slash_31 = "192.168.2.0/31".parse::<Ipv4Net>().unwrap();
        let slash_32 = "192.168.2.1/32".parse::<Ipv4Net>().unwrap();

        assert_eq!(usable_target_count(slash_8), Some(MAX_PROBES));
        assert_eq!(usable_target_count(slash_31), Some(2));
        assert_eq!(usable_target_count(slash_32), Some(1));
        assert!(matches!(
            parse_targets("10.0.0.0/7"),
            Err(TargetsError::TooLarge { max, .. }) if max == MAX_PROBES
        ));
        assert!(matches!(
            parse_targets("0.0.0.0/0"),
            Err(TargetsError::TooLarge { max, .. }) if max == MAX_PROBES
        ));
    }

    #[test]
    fn resolves_loopback_interface_address() {
        assert_eq!(interface_ipv4("lo").unwrap(), Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn rejects_unknown_interface() {
        let name = "singsing-rs-interface-does-not-exist";

        assert!(matches!(
            interface_ipv4(name),
            Err(InterfaceError::NotFound { name: n }) if n == name
        ));
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
            checksum(&ip_for_checksum.to_immutable())
        );
        let mut tcp_for_checksum = MutableTcpPacket::owned(tcp.packet().to_vec()).unwrap();
        tcp_for_checksum.set_checksum(0);
        assert_eq!(
            tcp.get_checksum(),
            ipv4_checksum(&tcp_for_checksum.to_immutable(), &source, &destination)
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
        let timeout = Duration::from_secs(30);

        assert_eq!(
            validate_probe_count(254, 65_535, 15, timeout).unwrap(),
            16_645_890
        );
        assert_eq!(
            validate_probe_count(256, 65_535, 15, timeout).unwrap(),
            16_776_960
        );
        assert_eq!(
            validate_probe_count(MAX_PROBES, 1, 15, timeout).unwrap(),
            MAX_PROBES
        );
        assert_eq!(validate_probe_count(1, 1, 15, MAX_TIMEOUT).unwrap(), 1);
        assert!(matches!(
            validate_probe_count(257, 65_535, 15, timeout),
            Err(ScanError::TooManyProbes { probe_count: 16_842_495, max }) if max == MAX_PROBES
        ));
        assert!(matches!(
            validate_probe_count(MAX_PROBES + 1, 1, 15, timeout),
            Err(ScanError::TooManyProbes { max, .. }) if max == MAX_PROBES
        ));
        assert!(matches!(
            validate_probe_count(usize::MAX, 2, 15, timeout),
            Err(ScanError::ScanSizeOverflow)
        ));
        assert!(matches!(
            validate_probe_count(0, 1, 15, timeout),
            Err(ScanError::EmptyScan)
        ));
        assert!(matches!(
            validate_probe_count(1, 0, 15, timeout),
            Err(ScanError::EmptyScan)
        ));
        assert!(matches!(
            validate_probe_count(1, 1, 0, timeout),
            Err(ScanError::ZeroBandwidth)
        ));
        assert!(matches!(
            validate_probe_count(1, 1, 15, MAX_TIMEOUT + Duration::from_secs(1)),
            Err(ScanError::TimeoutTooLarge { max, .. }) if max == MAX_TIMEOUT
        ));
    }

    #[test]
    fn timeout_too_large_reports_both_durations() {
        let timeout = MAX_TIMEOUT + Duration::from_secs(1);

        let error = validate_probe_count(1, 1, 15, timeout).unwrap_err();

        assert_eq!(
            error.to_string(),
            format!("timeout of {timeout:?} exceeds the maximum of {MAX_TIMEOUT:?}")
        );
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
        let path = services_path();
        fs::write(&path, "domain 53/udp\n# comment\nmalformed\n").unwrap();
        let error = ports_from_services(&path).unwrap_err();
        fs::remove_file(&path).unwrap();

        assert!(matches!(error, PortsError::NoTcpServices { path: p } if p == path));
    }

    #[test]
    fn reports_missing_services_file_path() {
        let path = services_path();
        let error = ports_from_services(&path).unwrap_err();

        assert!(matches!(
            &error,
            PortsError::ServicesFileRead { path: p, .. } if p == &path
        ));
        assert!(format!("{error:#}").contains(&path.display().to_string()));
    }

    #[test]
    fn incomplete_scan_error_preserves_context() {
        let host = "172.16.100.2".parse().unwrap();
        let partial_result = ScanResult {
            host,
            port: 443,
            state: PortState::Open,
        };
        let incomplete = IncompleteScanError {
            source: SendError::Io {
                host,
                port: 443,
                source: io::Error::other("send failed"),
            },
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
            "failed to send SYN to 172.16.100.2:443"
        );

        let error: anyhow::Error = incomplete.into();
        assert!(error.downcast_ref::<IncompleteScanError>().is_some());
        assert_eq!(
            format!("{error:#}"),
            "scan stopped after sending 7 of 10 probes: \
             failed to send SYN to 172.16.100.2:443: send failed"
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
