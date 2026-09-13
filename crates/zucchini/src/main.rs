#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../../../README.md"))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/0xdea/singsing-rs/master/.img/logo_zucchini.png"
)]

use std::fmt;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use chrono::{DateTime, Duration as ChronoDuration, Local, TimeZone};
use clap::Parser;
use singsing_rs::{
    IncompleteScanError, PortState, ScanConfig, ScanProgress, ScanResult, interface_ipv4,
    parse_ports, parse_targets, ports_from_services, scan_with_callbacks,
};

/// Package name.
const PROGRAM: &str = env!("CARGO_PKG_NAME");
/// Package version.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Package description.
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
/// Package authors.
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// IPv4 scan targets parsed from a `--host` argument.
///
/// Wrapped in a newtype so clap treats a single `--host` occurrence as one parsed value rather than inferring
/// multi-occurrence behavior from a bare `Vec<Ipv4Addr>` field type.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Targets(Vec<Ipv4Addr>);

impl FromStr for Targets {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> anyhow::Result<Self> {
        parse_targets(input).map(Self)
    }
}

/// TCP ports parsed from a `--ports` argument.
///
/// Wrapped in a newtype for the same reason as [`Targets`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ports(Vec<u16>);

impl FromStr for Ports {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> anyhow::Result<Self> {
        parse_ports(input).map(Self)
    }
}

/// Command-line arguments.
#[derive(Debug, Parser)]
#[command(disable_help_flag = true, about = None)]
struct Arguments {
    /// Network interface to use for the scan.
    #[arg(short = 'i', long)]
    interface: String,

    /// IPv4 address or CIDR to scan (e.g., 192.168.0.0/24).
    #[arg(short = 'h', long)]
    host: Targets,

    /// Ports (e.g., 21-23,80,443) [defaults to ports from /etc/services].
    #[arg(short = 'p', long)]
    ports: Option<Ports>,

    /// Display ports that reply with RST.
    #[arg(short = 'c', long)]
    closed: bool,

    /// Usable bandwidth in KiB/s.
    #[arg(short = 'b', long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..))]
    bandwidth: u64,

    /// Seconds to wait after sending the final probe.
    #[arg(short = 't', long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,

    /// Stream scan results as soon as they arrive.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Print command help.
    #[arg(long, action = clap::ArgAction::Help)]
    help: Option<bool>,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[!] Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the main scan logic.
fn run() -> anyhow::Result<()> {
    write_banner()?;

    let args = Arguments::parse();
    let Targets(host) = args.host;
    let ports = args
        .ports
        .map(|Ports(ports)| ports)
        .map_or_else(|| ports_from_services("/etc/services"), Ok)?;
    let source = interface_ipv4(&args.interface)?;

    let mut config = ScanConfig::new(host, ports, source);
    config.bandwidth_kib = args.bandwidth;
    config.timeout = Duration::from_secs(args.timeout);
    config.show_closed = args.closed;

    let probes = config
        .targets
        .len()
        .checked_mul(config.ports.len())
        .context("scan size overflow")?;
    write_scan_summary(probes, &args.interface, source)?;

    let started = Instant::now();
    let verbose = args.verbose;
    let scan_result = scan_with_callbacks(
        &config,
        move |result| {
            if verbose {
                write_verbose_result(result)
            } else {
                Ok(())
            }
        },
        write_progress,
    );

    match scan_result {
        Ok(results) => write_results(&results)?,
        Err(e) => {
            if let Some(incomplete) = e.downcast_ref::<IncompleteScanError>() {
                write_results(incomplete.partial_results())?;
            }
            return Err(e);
        }
    }

    write_done_summary(probes, started.elapsed().as_secs_f64())
}

/// Prints the program banner to stderr, flushed immediately.
fn write_banner() -> anyhow::Result<()> {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    write_banner_to(&mut output)?;
    output.flush().context("failed to flush output stream")
}

/// Writes the program banner to the given output stream.
fn write_banner_to(output: &mut impl Write) -> anyhow::Result<()> {
    write!(
        output,
        "{PROGRAM} {VERSION} - {DESCRIPTION}\nCopyright (c) 2026 {AUTHORS}\n\n"
    )
    .context("failed to write program banner")
}

/// Writes the scan summary to stderr, flushed before the scan starts.
fn write_scan_summary(probes: usize, interface: &str, source: Ipv4Addr) -> anyhow::Result<()> {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    write_scan_summary_to(&mut output, probes, interface, source)?;
    output.flush().context("failed to flush output stream")
}

/// Writes the scan summary to the given output stream.
fn write_scan_summary_to(
    output: &mut impl Write,
    probes: usize,
    interface: &str,
    source: Ipv4Addr,
) -> anyhow::Result<()> {
    writeln!(
        output,
        "Scanning: {probes} host/port pairs via {interface} ({source})..."
    )
    .context("failed to write scan summary")
}

/// Writes the done summary to stderr.
fn write_done_summary(probes: usize, elapsed: f64) -> anyhow::Result<()> {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    write_done_summary_to(&mut output, probes, elapsed)
}

/// Writes the done summary to the given output stream.
fn write_done_summary_to(
    output: &mut impl Write,
    probes: usize,
    elapsed: f64,
) -> anyhow::Result<()> {
    writeln!(
        output,
        "\nDone: {probes} host/port pairs scanned in {elapsed:.1} seconds"
    )
    .context("failed to write scan completion")
}

/// Writes the results to stdout.
fn write_results(results: &[ScanResult]) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_results_to(&mut output, results)
}

/// Writes the results to the given output stream.
fn write_results_to(output: &mut impl Write, results: &[ScanResult]) -> anyhow::Result<()> {
    if !results.is_empty() {
        writeln!(output, "\nScan results:").context("failed to write results heading")?;
    }
    for &result in results {
        write_result_to(output, result, false)?;
    }
    Ok(())
}

/// Writes a verbose scan result to stdout, flushed immediately for live feedback.
fn write_verbose_result(result: ScanResult) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_result_to(&mut output, result, true)?;
    output.flush().context("failed to flush output stream")
}

/// Writes the scan result to the given output stream.
fn write_result_to(
    output: &mut impl Write,
    result: ScanResult,
    verbose: bool,
) -> anyhow::Result<()> {
    let state = match result.state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        _ => "unknown",
    };
    let prefix = if verbose { "[verbose] " } else { "" };
    writeln!(output, "{prefix}{state} {}:{}", result.host, result.port)
        .context("failed to write scan result")
}

/// Writes the scan progress to stderr, flushed immediately.
fn write_progress(progress: ScanProgress) -> anyhow::Result<()> {
    let line = format_progress(progress, Local::now());
    let stderr = io::stderr();
    let mut output = stderr.lock();
    writeln!(output, "{line}").context("failed to write scan progress")?;
    output.flush().context("failed to flush output stream")
}

/// Formats the scan progress as a string.
fn format_progress<Tz>(progress: ScanProgress, now: DateTime<Tz>) -> String
where
    Tz: TimeZone,
    Tz::Offset: fmt::Display,
{
    let eta = progress
        .estimated_remaining()
        .and_then(|remaining| ChronoDuration::from_std(remaining).ok())
        .and_then(|remaining| now.checked_add_signed(remaining))
        .map_or_else(
            || "unknown".to_owned(),
            |eta| eta.format("%a %Y-%m-%d %H:%M:%S %Z").to_string(),
        );
    format!("[stats] {}% done | ETA {eta}", progress.percent())
}

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "panics are allowed in test code")]
#[expect(clippy::unwrap_used, reason = "tests can use `unwrap`")]
mod tests {
    use clap::error::ErrorKind;

    use super::*;

    #[test]
    fn parses_default_options() -> anyhow::Result<()> {
        let arguments =
            Arguments::try_parse_from(["zucchini", "--host", "127.0.0.1", "--interface", "lo"])?;

        assert_eq!(arguments.host, Targets(vec!["127.0.0.1".parse()?]));
        assert_eq!(arguments.interface, "lo");
        assert_eq!(arguments.bandwidth, 15);
        assert!(arguments.ports.is_none());
        assert!(!arguments.closed);
        assert_eq!(arguments.timeout, 30);
        assert!(!arguments.verbose);
        Ok(())
    }

    #[test]
    fn parses_all_scanner_options() -> anyhow::Result<()> {
        let arguments = Arguments::try_parse_from([
            "zucchini",
            "--host",
            "192.168.2.0/24",
            "--interface",
            "eth0",
            "--bandwidth",
            "100",
            "--ports",
            "22,80",
            "--closed",
            "--timeout",
            "60",
            "--verbose",
        ])?;

        assert_eq!(arguments.host, Targets(parse_targets("192.168.2.0/24")?));
        assert_eq!(arguments.interface, "eth0");
        assert_eq!(arguments.bandwidth, 100);
        assert_eq!(arguments.ports, Some(Ports(vec![22, 80])));
        assert!(arguments.closed);
        assert_eq!(arguments.timeout, 60);
        assert!(arguments.verbose);
        Ok(())
    }

    #[test]
    fn rejects_missing_unknown_and_invalid_options() {
        Arguments::try_parse_from(["zucchini", "-i", "lo"]).unwrap_err();
        Arguments::try_parse_from(["zucchini", "-h", "127.0.0.1"]).unwrap_err();
        Arguments::try_parse_from(["zucchini", "-h", "127.0.0.1", "-i", "lo", "--unknown"])
            .unwrap_err();
        Arguments::try_parse_from(["zucchini", "-h", "127.0.0.1", "-i", "lo", "--timeout", "0"])
            .unwrap_err();
        Arguments::try_parse_from([
            "zucchini",
            "-h",
            "127.0.0.1",
            "-i",
            "lo",
            "--bandwidth",
            "0",
        ])
        .unwrap_err();
        Arguments::try_parse_from(["zucchini", "-h", "not-an-address", "-i", "lo"]).unwrap_err();
        Arguments::try_parse_from([
            "zucchini",
            "-h",
            "127.0.0.1",
            "-i",
            "lo",
            "--ports",
            "80-79",
        ])
        .unwrap_err();
    }

    #[test]
    fn formats_banner_scan_and_completion_summaries() -> anyhow::Result<()> {
        let mut output = Vec::new();
        write_banner_to(&mut output)?;
        write_scan_summary_to(&mut output, 3, "eth0", "192.168.2.1".parse()?)?;
        write_done_summary_to(&mut output, 3, 30.14)?;

        assert_eq!(
            String::from_utf8(output)?,
            concat!(
                "zucchini 0.1.0 - A blazing fast Linux IPv4 port scanner\n",
                "Copyright (c) 2026 Marco Ivaldi <raptor@0xdeadbeef.info>\n",
                "\n",
                "Scanning: 3 host/port pairs via eth0 (192.168.2.1)...\n",
                "\n",
                "Done: 3 host/port pairs scanned in 30.1 seconds\n",
            )
        );
        Ok(())
    }

    #[test]
    fn formats_empty_buffered_and_verbose_results() -> anyhow::Result<()> {
        let open = ScanResult {
            host: "172.16.100.2".parse()?,
            port: 443,
            state: PortState::Open,
        };
        let closed = ScanResult {
            host: "172.16.100.3".parse()?,
            port: 80,
            state: PortState::Closed,
        };
        let mut output = Vec::new();
        write_results_to(&mut output, &[])?;
        assert!(output.is_empty());

        write_results_to(&mut output, &[open, closed])?;
        assert_eq!(
            String::from_utf8(output)?,
            concat!(
                "\n",
                "Scan results:\n",
                "open 172.16.100.2:443\n",
                "closed 172.16.100.3:80\n",
            )
        );

        let mut verbose = Vec::new();
        write_result_to(&mut verbose, open, true)?;
        assert_eq!(
            String::from_utf8(verbose)?,
            "[verbose] open 172.16.100.2:443\n"
        );
        Ok(())
    }

    #[test]
    fn formats_progress_with_fixed_time() {
        let now = chrono::Utc
            .with_ymd_and_hms(2026, 1, 1, 12, 0, 0)
            .single()
            .unwrap();
        let progress = ScanProgress {
            probes_sent: 25,
            total_probes: 100,
            elapsed: Duration::from_secs(60),
        };
        let not_started = ScanProgress {
            probes_sent: 0,
            ..progress
        };
        let complete = ScanProgress {
            probes_sent: 100,
            ..progress
        };

        assert_eq!(
            format_progress(progress, now),
            "[stats] 25% done | ETA Thu 2026-01-01 12:03:00 UTC"
        );
        assert_eq!(
            format_progress(not_started, now),
            "[stats] 0% done | ETA unknown"
        );
        assert_eq!(
            format_progress(complete, now),
            "[stats] 100% done | ETA Thu 2026-01-01 12:00:00 UTC"
        );
    }

    #[test]
    fn formats_progress_with_non_utc_offset() {
        let offset = chrono::FixedOffset::east_opt(3600).unwrap();
        let now = offset
            .with_ymd_and_hms(2026, 1, 1, 12, 0, 0)
            .single()
            .unwrap();
        let progress = ScanProgress {
            probes_sent: 25,
            total_probes: 100,
            elapsed: Duration::from_secs(60),
        };

        assert_eq!(
            format_progress(progress, now),
            "[stats] 25% done | ETA Thu 2026-01-01 12:03:00 +01:00"
        );
    }

    #[test]
    fn help_flag_displays_help() {
        let error = Arguments::try_parse_from(["zucchini", "--help"]).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
    }

    #[test]
    fn version_flag_is_unknown() {
        let error =
            Arguments::try_parse_from(["zucchini", "-h", "127.0.0.1", "-i", "lo", "--version"])
                .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }
}
