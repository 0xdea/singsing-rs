//! Unprivileged black-box tests for the public singsing-rs API.

use std::net::Ipv4Addr;

use singsing_rs::{ScanConfig, parse_targets, scan};

fn address(input: &str) -> Ipv4Addr {
    input.parse().expect("test address should be valid")
}

fn scan_error(config: &ScanConfig) -> String {
    format!(
        "{:#}",
        scan(config).expect_err("scan should fail before raw socket creation")
    )
}

#[test]
fn rejects_empty_scan_configuration() {
    let source = address("192.0.2.1");
    let no_targets = ScanConfig::new(Vec::new(), vec![443], source);
    let no_ports = ScanConfig::new(vec![source], Vec::new(), source);

    assert!(scan_error(&no_targets).contains("at least one target and one port"));
    assert!(scan_error(&no_ports).contains("at least one target and one port"));
}

#[test]
fn rejects_excessive_scan_before_raw_socket_creation() {
    let source = address("192.0.2.1");
    let targets = vec![source; 257];
    let ports = (1..=u16::MAX).collect();
    let config = ScanConfig::new(targets, ports, source);

    assert!(scan_error(&config).contains("maximum is 16777214"));
}

#[test]
fn rejects_duplicate_targets_and_ports() {
    let source = address("192.0.2.1");
    let duplicate_targets = ScanConfig::new(vec![source, source], vec![443], source);
    let duplicate_ports = ScanConfig::new(vec![source], vec![443, 443], source);

    assert!(scan_error(&duplicate_targets).contains("targets and ports must be unique"));
    assert!(scan_error(&duplicate_ports).contains("targets and ports must be unique"));
}

#[test]
fn rejects_oversized_cidr_without_expanding_it() {
    let error = parse_targets("10.0.0.0/7").expect_err("a /7 should exceed the target limit");

    assert!(
        error
            .to_string()
            .contains("split networks larger than a /8")
    );
}
