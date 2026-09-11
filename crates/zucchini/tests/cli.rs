//! Unprivileged black-box tests for the zucchini command-line interface.

use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zucchini"))
        .args(arguments)
        .output()
        .expect("zucchini should execute")
}

fn stdout(output: &Output) -> &str {
    std::str::from_utf8(&output.stdout).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> &str {
    std::str::from_utf8(&output.stderr).expect("stderr should be UTF-8")
}

#[test]
fn prints_help_and_version() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(stdout(&help).contains("Usage: zucchini"));
    assert!(stdout(&help).contains("--host"));
    assert!(stdout(&help).contains("--verbose"));
    assert!(stderr(&help).is_empty());

    let version = run(&["--version"]);
    assert!(version.status.success());
    assert_eq!(stdout(&version), "zucchini 0.1.0\n");
    assert!(stderr(&version).is_empty());
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
    assert!(stderr(&timeout).contains("timeout must be greater than zero"));
}

#[test]
fn reports_invalid_targets_and_ports_without_raw_socket() {
    let target = run(&["-h", "not-an-address", "-i", "lo", "-p", "80"]);
    assert!(!target.status.success());
    assert!(stdout(&target).starts_with("zucchini 0.1.0"));
    assert!(stderr(&target).contains("invalid IPv4 address"));
    assert!(!stdout(&target).contains("[!] Error"));

    let ports = run(&["-h", "192.168.2.1", "-i", "lo", "-p", "80-79"]);
    assert!(!ports.status.success());
    assert!(stdout(&ports).starts_with("zucchini 0.1.0"));
    assert!(stderr(&ports).contains("reversed port range"));
}

#[test]
fn rejects_oversized_target_before_expansion() {
    let output = run(&["-h", "10.0.0.0/7", "-i", "lo", "-p", "80"]);

    assert!(!output.status.success());
    assert!(stdout(&output).starts_with("zucchini 0.1.0"));
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
fn rejects_zero_bandwidth_before_raw_socket() {
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
    assert!(stderr(&output).contains("bandwidth must be greater than zero"));
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
    assert!(stdout(&output).starts_with("zucchini 0.1.0"));
    assert!(stderr(&output).contains("does not exist"));
    assert!(!stderr(&output).contains("failed to create raw socket"));
}
