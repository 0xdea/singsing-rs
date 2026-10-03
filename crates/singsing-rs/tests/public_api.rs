//! Unprivileged integration tests for the public singsing-rs API.

#![expect(
    clippy::tests_outside_test_module,
    reason = "no need to have a test module for integration tests in `/tests`"
)]
#![expect(clippy::expect_used, reason = "tests can use `expect`")]

use std::net::Ipv4Addr;

use singsing_rs::{Port, ScanConfig, scan};

/// The port used by tests that only need one.
const HTTPS: Port = Port::new(443).unwrap();

/// Parses a test IPv4 address.
fn address(input: &str) -> Ipv4Addr {
    input.parse().expect("test address should be valid")
}

/// Runs a scan that is expected to fail during validation and returns its error
/// message chain.
fn scan_error(config: &ScanConfig) -> String {
    format!(
        "{:#}",
        scan(config).expect_err("scan should fail before raw socket creation")
    )
}

#[test]
fn rejects_empty_scan_configuration() {
    let source = address("192.168.2.1");
    let no_targets = ScanConfig::new(Vec::new(), vec![HTTPS], source);
    let no_ports = ScanConfig::new(vec![source], Vec::new(), source);

    assert!(
        scan_error(&no_targets).contains("at least one target and one port"),
        "a scan without targets should be rejected"
    );
    assert!(
        scan_error(&no_ports).contains("at least one target and one port"),
        "a scan without ports should be rejected"
    );
}

#[test]
fn rejects_excessive_scan_before_raw_socket_creation() {
    let source = address("192.168.2.1");
    let targets = vec![source; 257];
    let ports = (1..=u16::MAX).filter_map(Port::new).collect();
    let config = ScanConfig::new(targets, ports, source);

    assert!(
        scan_error(&config).contains("maximum is 16777214"),
        "all ports on 257 hosts should exceed the probe limit"
    );
}

#[test]
fn rejects_duplicate_targets_and_ports() {
    let source = address("192.168.2.1");
    let duplicate_targets = ScanConfig::new(vec![source, source], vec![HTTPS], source);
    let duplicate_ports = ScanConfig::new(vec![source], vec![HTTPS, HTTPS], source);

    assert!(
        scan_error(&duplicate_targets).contains("targets and ports must be unique"),
        "duplicate targets should be rejected"
    );
    assert!(
        scan_error(&duplicate_ports).contains("targets and ports must be unique"),
        "duplicate ports should be rejected"
    );
}
