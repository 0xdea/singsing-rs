//! Linux IPv4 SYN scanner command.

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{Duration as ChronoDuration, Local};
use clap::Parser;
use singsing_rs::{
    PortState, ScanConfig, ScanProgress, ScanResult, interface_ipv4, parse_ports, parse_targets,
    ports_from_services, scan, scan_with_callbacks,
};

const PROGRAM: &str = "zucchini";

/// Linux IPv4 SYN scanner based on singsing's zucca example.
#[derive(Debug, Parser)]
#[command(name = PROGRAM, version, disable_help_flag = true)]
struct Arguments {
    /// Host or CIDR to scan (for example, 192.168.0.0/24).
    #[arg(short = 'h', long)]
    host: String,

    /// Network interface used for the scan.
    #[arg(short = 'i', long)]
    interface: String,

    /// Usable bandwidth in KiB/s.
    #[arg(short = 'b', long, default_value_t = 15)]
    bandwidth: u64,

    /// Ports (for example, 22,23,40-50,99); defaults to /etc/services.
    #[arg(short = 'p', long)]
    ports: Option<String>,

    /// Display ports which reply with RST.
    #[arg(short = 'c', long)]
    show_closed: bool,

    /// Seconds to wait for replies after sending the final probe.
    #[arg(short = 't', long, default_value_t = 30)]
    timeout: u64,

    /// Stream tagged results and print progress every minute.
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

fn run() -> Result<()> {
    let arguments = Arguments::parse();
    if arguments.timeout == 0 {
        bail!("timeout must be greater than zero");
    }
    let targets = parse_targets(&arguments.host)?;
    let ports = arguments
        .ports
        .as_deref()
        .map(parse_ports)
        .transpose()?
        .map_or_else(|| ports_from_services("/etc/services"), Ok)?;
    let source = interface_ipv4(&arguments.interface)?;

    let mut config = ScanConfig::new(targets, ports, source);
    config.bandwidth_kib = arguments.bandwidth;
    config.timeout = Duration::from_secs(arguments.timeout);
    config.show_closed = arguments.show_closed;

    let probes = config
        .targets
        .len()
        .checked_mul(config.ports.len())
        .context("scan size overflow")?;
    eprintln!(
        "zucchini {} - scanning {probes} host/port pairs via {} ({source})",
        env!("CARGO_PKG_VERSION"),
        arguments.interface
    );
    let started = Instant::now();
    let results = if arguments.verbose {
        scan_with_callbacks(
            &config,
            |result| write_result(result, true, true),
            write_progress,
        )?
    } else {
        scan(&config)?
    };
    if arguments.verbose {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        writeln!(output, "\nFinal scan results:")
            .context("failed to write final results heading")?;
    }
    for result in results {
        write_result(result, false, false)?;
    }
    eprintln!(
        "{probes} ports scanned in {:.1} seconds",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn write_result(result: ScanResult, verbose: bool, flush: bool) -> Result<()> {
    let state = match result.state {
        PortState::Open => "open",
        PortState::Closed => "closed",
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    if verbose {
        writeln!(output, "[verbose] {state} {}:{}", result.host, result.port)
            .context("failed to write verbose scan result")?;
    } else {
        writeln!(output, "{state} {}:{}", result.host, result.port)
            .context("failed to write scan result")?;
    }
    if flush {
        output.flush().context("failed to flush scan result")?;
    }
    Ok(())
}

fn write_progress(progress: ScanProgress) -> Result<()> {
    let eta = progress
        .estimated_remaining()
        .and_then(|remaining| ChronoDuration::from_std(remaining).ok())
        .and_then(|remaining| Local::now().checked_add_signed(remaining))
        .map_or_else(
            || "unknown".to_owned(),
            |eta| eta.format("%a %Y-%m-%d %H:%M:%S %Z").to_string(),
        );
    let stderr = io::stderr();
    let mut output = stderr.lock();
    writeln!(
        output,
        "[verbose] stats: {}% done, ETA {eta}",
        progress.percent(),
    )
    .context("failed to write scan progress")?;
    output.flush().context("failed to flush scan progress")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_verbose_option() -> Result<()> {
        let arguments =
            Arguments::try_parse_from(["zucchini", "-h", "127.0.0.1", "-i", "lo", "-v"])?;

        assert!(arguments.verbose);
        assert_eq!(arguments.timeout, 30);
        Ok(())
    }
}
