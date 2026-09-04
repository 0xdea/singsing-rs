//! Linux IPv4 SYN scanner command.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use singsing_rs::{
    PortState, ScanConfig, interface_ipv4, parse_ports, parse_targets, ports_from_services, scan,
};

const PROGRAM: &str = "zucca";

/// Linux IPv4 SYN scanner, ported from singsing's zucca example.
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
    #[arg(short = 't', long, default_value_t = 3)]
    timeout: u64,

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
        "zucca {} - scanning {probes} host/port pairs via {} ({source})",
        env!("CARGO_PKG_VERSION"),
        arguments.interface
    );
    let started = Instant::now();
    for result in scan(&config)? {
        let state = match result.state {
            PortState::Open => "open",
            PortState::Closed => "closed",
        };
        println!("zucca {state} {}:{}", result.host, result.port);
    }
    eprintln!(
        "{probes} ports scanned in {:.1} seconds",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
