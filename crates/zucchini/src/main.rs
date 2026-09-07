//! Linux IPv4 SYN scanner command.

use std::io::{self, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use singsing_rs::{
    PortState, ScanConfig, ScanResult, interface_ipv4, parse_ports, parse_targets,
    ports_from_services, scan, scan_with_callback,
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
    #[arg(short = 't', long, default_value_t = 10)]
    timeout: u64,

    /// Print and flush each result as soon as it is received.
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
    if arguments.verbose {
        scan_with_callback(&config, |result| write_result(result, true))?;
    } else {
        for result in scan(&config)? {
            write_result(result, false)?;
        }
    }
    eprintln!(
        "{probes} ports scanned in {:.1} seconds",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn write_result(result: ScanResult, flush: bool) -> Result<()> {
    let state = match result.state {
        PortState::Open => "open",
        PortState::Closed => "closed",
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "zucchini {state} {}:{}", result.host, result.port)
        .context("failed to write scan result")?;
    if flush {
        output.flush().context("failed to flush scan result")?;
    }
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
        assert_eq!(arguments.timeout, 10);
        Ok(())
    }
}
