//! Unprivileged integration tests for the zucchini binary.

#![expect(
    clippy::tests_outside_test_module,
    reason = "no need to have a test module for integration tests in `/tests`"
)]
#![expect(clippy::expect_used, reason = "tests can use `expect`")]

use std::process::{Command, Output};
use std::str;

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zucchini"))
        .args(arguments)
        .output()
        .expect("zucchini should execute")
}

fn stdout(output: &Output) -> &str {
    str::from_utf8(&output.stdout).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> &str {
    str::from_utf8(&output.stderr).expect("stderr should be UTF-8")
}

#[test]
fn prints_help() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(stdout(&help).contains("Usage: zucchini"));
    assert!(stdout(&help).contains("--host"));
    assert!(stdout(&help).contains("--verbose"));
    assert!(!stdout(&help).contains("--version"));
    assert!(stderr(&help).starts_with("zucchini "));
}

#[test]
fn rejects_version_flag() {
    let output = run(&["--version"]);
    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("unexpected argument '--version'"));
}

#[test]
fn rejects_invalid_cli_before_printing_banner() {
    let missing = run(&[]);
    assert!(!missing.status.success());
    assert!(stdout(&missing).is_empty());
    assert!(stderr(&missing).contains("required arguments"));

    let timeout = run(&["-h", "192.168.2.1", "-i", "lo", "--timeout", "0"]);
    assert!(!timeout.status.success());
    assert!(stdout(&timeout).is_empty());
    assert!(stderr(&timeout).contains("invalid value '0' for '--timeout <TIMEOUT>'"));
}

#[test]
fn reports_invalid_targets_and_ports_before_printing_banner() {
    let target = run(&["-h", "not-an-address", "-i", "lo", "-p", "80"]);
    assert!(!target.status.success());
    assert!(stdout(&target).is_empty());
    assert!(stderr(&target).contains("invalid value 'not-an-address' for '--host <HOST>'"));
    assert!(stderr(&target).contains("invalid IPv4 address"));

    let ports = run(&["-h", "192.168.2.1", "-i", "lo", "-p", "80-79"]);
    assert!(!ports.status.success());
    assert!(stdout(&ports).is_empty());
    assert!(stderr(&ports).contains("invalid value '80-79' for '--ports <PORTS>'"));
    assert!(stderr(&ports).contains("reversed port range"));
}

#[test]
fn rejects_oversized_target_before_expansion() {
    let output = run(&["-h", "10.0.0.0/7", "-i", "lo", "-p", "80"]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("split networks larger than a /8"));
}

#[test]
fn rejects_full_port_slash_23_before_raw_socket() {
    let output = run(&["-h", "192.168.2.0/23", "-i", "lo", "-p", "1-65535"]);

    assert!(!output.status.success());
    assert!(stdout(&output).contains("Scanning: 33422850 host/port pairs"));
    assert!(stderr(&output).contains("maximum is 16777214"));
    assert!(!stderr(&output).contains("failed to create raw socket"));
}

#[test]
fn rejects_zero_bandwidth_before_printing_banner() {
    let output = run(&[
        "-h",
        "192.168.2.1",
        "-i",
        "lo",
        "-p",
        "80",
        "--bandwidth",
        "0",
    ]);

    assert!(!output.status.success());
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("invalid value '0' for '--bandwidth <BANDWIDTH>'"));
    assert!(!stderr(&output).contains("failed to create raw socket"));
}

#[test]
fn reports_nonexistent_interface_without_raw_socket() {
    let output = run(&[
        "-h",
        "192.168.2.1",
        "-i",
        "zucchini-interface-does-not-exist",
        "-p",
        "80",
    ]);

    assert!(!output.status.success());
    assert!(stderr(&output).starts_with("zucchini "));
    assert!(stderr(&output).contains("does not exist"));
    assert!(!stderr(&output).contains("failed to create raw socket"));
    assert!(stdout(&output).is_empty());
}
