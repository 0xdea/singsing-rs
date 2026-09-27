#![doc = env!("CARGO_PKG_DESCRIPTION")]
#![doc = ""]
#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/0xdea/singsing-rs/master/.img/logo_zucchini.png"
)]

use std::fmt;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::num::NonZeroU64;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use chrono::{DateTime, Local, TimeZone};
use clap::Parser;
use singsing_rs::{
    CallbackError, Port, PortState, PortsError, ScanConfig, ScanError, ScanProgress, ScanResult,
    TargetsError, interface_ipv4, parse_ports, parse_targets, ports_from_services,
    scan_with_callbacks,
};

/// Binary name.
const PROGRAM: &str = env!("CARGO_BIN_NAME");
/// Package version.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Package description.
const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
/// Package authors.
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// IPv4 scan targets parsed from a `--host` argument.
///
/// Wrapped in a newtype so clap treats a single `--host` occurrence as one parsed value rather
/// than inferring multi-occurrence behavior from a bare `Vec<Ipv4Addr>` field type.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Targets(Vec<Ipv4Addr>);

impl FromStr for Targets {
    type Err = TargetsError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_targets(input).map(Self)
    }
}

/// TCP ports parsed from a `--ports` argument.
///
/// Wrapped in a newtype for the same reason as [`Targets`].
#[derive(Clone, Debug, Eq, PartialEq)]
struct Ports(Vec<Port>);

impl FromStr for Ports {
    type Err = PortsError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_ports(input).map(Self)
    }
}

/// Command-line arguments.
#[derive(Debug, Parser)]
#[command(name = PROGRAM, disable_help_flag = true, about = None)]
struct Arguments {
    /// Network interface to use for the scan.
    #[arg(short = 'i', long)]
    interface: String,
    /// IPv4 address or CIDR to scan (e.g., 192.168.0.0/24).
    #[arg(short = 'h', long)]
    host: Targets,
    /// Ports (e.g., 21-23,80,443) [default: /etc/services].
    #[arg(short = 'p', long)]
    ports: Option<Ports>,
    /// Display ports that reply with RST.
    #[arg(short = 'c', long)]
    closed: bool,
    /// Usable bandwidth in KiB/s.
    #[arg(short = 'b', long, default_value = "15")]
    bandwidth: NonZeroU64,
    /// Seconds to wait for late replies.
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
        Err(error) => {
            eprintln!("[!] Error: {error:#}");
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
    config.show_closed = args.closed;
    config.bandwidth_kib = args.bandwidth;
    config.timeout = Duration::from_secs(args.timeout);

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
            .map_err(|error| to_boxed_error(&error))
        },
        move |progress| write_progress(progress).map_err(|error| to_boxed_error(&error)),
    );

    match scan_result {
        Ok(results) => write_results(&results)?,
        Err(error) => {
            if let ScanError::Incomplete(incomplete) = &error {
                write_incomplete_summary(incomplete.probes_sent(), incomplete.total_probes())?;
                write_results(incomplete.partial_results())?;
            }
            return Err(error.into());
        }
    }

    write_done_summary(probes, started.elapsed().as_secs_f64())
}

/// Adapts an `anyhow::Error` from a `write_*` helper into the boxed error type the scanning
/// library's callbacks expect.
fn to_boxed_error(error: &anyhow::Error) -> CallbackError {
    format!("{error:#}").into()
}

/// Prints the program banner to stderr and flushes the output stream.
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

/// Writes the scan summary to stderr and flushes the output stream before the scan starts.
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

/// Writes the incomplete scan summary to stderr and flushes the output stream before the partial
/// results that follow.
fn write_incomplete_summary(probes_sent: usize, total_probes: usize) -> anyhow::Result<()> {
    let stderr = io::stderr();
    let mut output = stderr.lock();

    write_incomplete_summary_to(&mut output, probes_sent, total_probes)?;
    output.flush().context("failed to flush output stream")
}

/// Writes the incomplete scan summary to the given output stream.
fn write_incomplete_summary_to(
    output: &mut impl Write,
    probes_sent: usize,
    total_probes: usize,
) -> anyhow::Result<()> {
    writeln!(
        output,
        "\nIncomplete: sent {probes_sent} of {total_probes} host/port pairs"
    )
    .context("failed to write incomplete scan summary")
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

/// Writes a verbose scan result to stdout and flushes the output stream for live feedback.
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

/// Writes the scan progress to stderr and flushes the output stream for live feedback.
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
        .and_then(|remaining| chrono::Duration::from_std(remaining).ok())
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

        assert_eq!(
            arguments.host,
            Targets(vec!["127.0.0.1".parse()?]),
            "`--host` should be parsed into targets"
        );
        assert_eq!(
            arguments.interface, "lo",
            "`--interface` should be parsed as is"
        );
        assert_eq!(
            arguments.bandwidth.get(),
            15,
            "bandwidth should default to 15 KiB/s"
        );
        assert!(
            arguments.ports.is_none(),
            "ports should default to none (read from /etc/services)"
        );
        assert!(
            !arguments.closed,
            "closed ports should be hidden by default"
        );
        assert_eq!(
            arguments.timeout, 30,
            "timeout should default to 30 seconds"
        );
        assert!(!arguments.verbose, "verbose mode should be off by default");
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

        assert_eq!(
            arguments.host,
            Targets(parse_targets("192.168.2.0/24")?),
            "`--host` should expand a CIDR into targets"
        );
        assert_eq!(
            arguments.interface, "eth0",
            "`--interface` should be parsed as is"
        );
        assert_eq!(
            arguments.bandwidth.get(),
            100,
            "`--bandwidth` should override the default"
        );
        assert_eq!(
            arguments.ports,
            Some(Ports(vec![22, 80])),
            "`--ports` should be parsed into ports"
        );
        assert!(arguments.closed, "`--closed` should enable closed ports");
        assert_eq!(
            arguments.timeout, 60,
            "`--timeout` should override the default"
        );
        assert!(arguments.verbose, "`--verbose` should enable verbose mode");
        Ok(())
    }

    #[test]
    fn rejects_missing_unknown_and_invalid_options() {
        assert!(
            Arguments::try_parse_from(["zucchini", "-i", "lo"]).is_err(),
            "a missing `--host` should be rejected"
        );
        assert!(
            Arguments::try_parse_from(["zucchini", "-h", "127.0.0.1"]).is_err(),
            "a missing `--interface` should be rejected"
        );
        assert!(
            Arguments::try_parse_from(["zucchini", "-h", "127.0.0.1", "-i", "lo", "--unknown"])
                .is_err(),
            "an unknown option should be rejected"
        );
        assert!(
            Arguments::try_parse_from([
                "zucchini",
                "-h",
                "127.0.0.1",
                "-i",
                "lo",
                "--timeout",
                "0"
            ])
            .is_err(),
            "a zero timeout should be rejected"
        );
        assert!(
            Arguments::try_parse_from([
                "zucchini",
                "-h",
                "127.0.0.1",
                "-i",
                "lo",
                "--bandwidth",
                "0",
            ])
            .is_err(),
            "a zero bandwidth should be rejected"
        );
        assert!(
            Arguments::try_parse_from(["zucchini", "-h", "not-an-address", "-i", "lo"]).is_err(),
            "an invalid target should be rejected"
        );
        assert!(
            Arguments::try_parse_from([
                "zucchini",
                "-h",
                "127.0.0.1",
                "-i",
                "lo",
                "--ports",
                "80-79",
            ])
            .is_err(),
            "an invalid port range should be rejected"
        );
    }

    #[test]
    fn formats_banner_scan_and_completion_summaries() -> anyhow::Result<()> {
        let mut output = Vec::new();
        write_banner_to(&mut output)?;
        write_scan_summary_to(&mut output, 3, "eth0", "192.168.2.1".parse()?)?;
        write_done_summary_to(&mut output, 3, 30.14)?;

        assert_eq!(
            String::from_utf8(output)?,
            format!(
                "{PROGRAM} {VERSION} - {DESCRIPTION}\nCopyright (c) 2026 {AUTHORS}\n\n\
                Scanning: 3 host/port pairs via eth0 (192.168.2.1)...\n\n\
                Done: 3 host/port pairs scanned in 30.1 seconds\n"
            ),
            "banner, scan summary, and done summary output"
        );
        Ok(())
    }

    #[test]
    fn formats_incomplete_summary() -> anyhow::Result<()> {
        let mut output = Vec::new();
        write_incomplete_summary_to(&mut output, 1, 3)?;

        assert_eq!(
            String::from_utf8(output)?,
            "\nIncomplete: sent 1 of 3 host/port pairs\n",
            "incomplete scan summary output"
        );
        Ok(())
    }

    #[test]
    fn formats_empty_buffered_and_verbose_results() -> anyhow::Result<()> {
        let open = ScanResult::new("172.16.100.2".parse()?, 443, PortState::Open);
        let closed = ScanResult::new("172.16.100.3".parse()?, 80, PortState::Closed);
        let mut output = Vec::new();
        write_results_to(&mut output, &[])?;
        assert!(
            output.is_empty(),
            "no results should print nothing, not even the heading"
        );

        write_results_to(&mut output, &[open, closed])?;
        assert_eq!(
            String::from_utf8(output)?,
            concat!(
                "\n",
                "Scan results:\n",
                "open 172.16.100.2:443\n",
                "closed 172.16.100.3:80\n",
            ),
            "buffered results output"
        );

        let mut verbose = Vec::new();
        write_result_to(&mut verbose, open, true)?;
        assert_eq!(
            String::from_utf8(verbose)?,
            "[verbose] open 172.16.100.2:443\n",
            "verbose result output"
        );
        Ok(())
    }

    #[test]
    fn formats_progress_with_fixed_time() {
        let now = chrono::Utc
            .with_ymd_and_hms(2026, 1, 1, 12, 0, 0)
            .single()
            .unwrap();
        let progress = ScanProgress::new(25, 100, Duration::from_secs(60));
        let not_started = ScanProgress::new(0, 100, Duration::from_secs(60));
        let complete = ScanProgress::new(100, 100, Duration::from_secs(60));

        assert_eq!(
            format_progress(progress, now),
            "[stats] 25% done | ETA Thu 2026-01-01 12:03:00 UTC",
            "a partially sent scan should report its ETA"
        );
        assert_eq!(
            format_progress(not_started, now),
            "[stats] 0% done | ETA unknown",
            "a scan with no probes sent should report an unknown ETA"
        );
        assert_eq!(
            format_progress(complete, now),
            "[stats] 100% done | ETA Thu 2026-01-01 12:00:00 UTC",
            "a fully sent scan should report the current time as its ETA"
        );
    }

    #[test]
    fn formats_progress_with_non_utc_offset() {
        let offset = chrono::FixedOffset::east_opt(3600).unwrap();
        let now = offset
            .with_ymd_and_hms(2026, 1, 1, 12, 0, 0)
            .single()
            .unwrap();
        let progress = ScanProgress::new(25, 100, Duration::from_secs(60));

        assert_eq!(
            format_progress(progress, now),
            "[stats] 25% done | ETA Thu 2026-01-01 12:03:00 +01:00",
            "a fixed offset should be formatted as a numeric time zone"
        );
    }

    #[test]
    fn help_flag_displays_help() {
        let error = Arguments::try_parse_from(["zucchini", "--help"]).unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelp,
            "`--help` should display help"
        );
    }

    #[test]
    fn version_flag_is_unknown() {
        let error =
            Arguments::try_parse_from(["zucchini", "-h", "127.0.0.1", "-i", "lo", "--version"])
                .unwrap_err();

        assert_eq!(
            error.kind(),
            ErrorKind::UnknownArgument,
            "`--version` should not be accepted"
        );
    }
}
