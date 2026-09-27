//! Unprivileged integration tests for the zucchini binary.

#![expect(
    clippy::tests_outside_test_module,
    reason = "no need to have a test module for integration tests in `/tests`"
)]
#![expect(clippy::expect_used, reason = "tests can use `expect`")]

use std::process::{Command, Output};
use std::str;

/// Runs the `zucchini` binary with the given arguments and captures its output.
fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zucchini"))
        .args(arguments)
        .output()
        .expect("zucchini should execute")
}

/// Returns a finished process's stdout as UTF-8 text.
fn stdout(output: &Output) -> &str {
    str::from_utf8(&output.stdout).expect("stdout should be UTF-8")
}

/// Returns a finished process's stderr as UTF-8 text.
fn stderr(output: &Output) -> &str {
    str::from_utf8(&output.stderr).expect("stderr should be UTF-8")
}

#[test]
fn prints_help() {
    let help = run(&["--help"]);
    assert!(help.status.success(), "`--help` should succeed");
    assert_eq!(help.status.code(), Some(0), "`--help` should exit with 0");
    assert!(
        stdout(&help).contains("Usage: zucchini"),
        "help should name the `zucchini` binary"
    );
    assert!(
        stdout(&help).contains("--host"),
        "help should list `--host`"
    );
    assert!(
        stdout(&help).contains("--verbose"),
        "help should list `--verbose`"
    );
    assert!(
        !stdout(&help).contains("--version"),
        "help should not list `--version`"
    );
    assert!(
        stderr(&help).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );
}

#[test]
fn rejects_version_flag() {
    let output = run(&["--version"]);
    assert!(!output.status.success(), "`--version` should fail");
    assert!(stdout(&output).is_empty(), "stdout should be empty");
    assert!(
        stderr(&output).contains("unexpected argument '--version'"),
        "`--version` should be reported as an unexpected argument"
    );
}

#[test]
fn rejects_invalid_cli() {
    let missing = run(&[]);
    assert!(!missing.status.success(), "missing arguments should fail");
    assert_eq!(
        missing.status.code(),
        Some(2),
        "a usage error should exit with 2"
    );
    assert!(stdout(&missing).is_empty(), "stdout should be empty");
    assert!(
        stderr(&missing).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );
    assert!(
        stderr(&missing).contains("required arguments"),
        "missing arguments should be reported"
    );

    let timeout = run(&["-h", "192.168.2.1", "-i", "lo", "--timeout", "0"]);
    assert!(!timeout.status.success(), "a zero timeout should fail");
    assert_eq!(
        timeout.status.code(),
        Some(2),
        "a usage error should exit with 2"
    );
    assert!(stdout(&timeout).is_empty(), "stdout should be empty");
    assert!(
        stderr(&timeout).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );
    assert!(
        stderr(&timeout).contains("invalid value '0' for '--timeout <TIMEOUT>'"),
        "a zero timeout should be reported as an invalid value"
    );
}

#[test]
fn rejects_timeout_above_maximum_before_scan() {
    let output = run(&["-h", "192.168.2.1", "-i", "lo", "-p", "80", "-t", "86401"]);

    assert!(!output.status.success(), "an oversized timeout should fail");
    assert_eq!(
        output.status.code(),
        Some(2),
        "a usage error should exit with 2"
    );
    assert!(stdout(&output).is_empty(), "stdout should be empty");
    assert!(
        stderr(&output).contains("invalid value '86401' for '--timeout <TIMEOUT>'"),
        "an oversized timeout should be reported as an invalid value"
    );
    assert!(
        stderr(&output).contains("1..=86400"),
        "the error should state the accepted range"
    );
    assert!(
        !stderr(&output).contains("Scanning:"),
        "an oversized timeout should be rejected before the scan summary"
    );
}

#[test]
fn accepts_maximum_timeout_in_library_validation() {
    // The library checks the timeout before the probe count, so an oversized scan failing on the
    // probe limit (rather than the timeout) proves the CLI's maximum passes the library's own
    // check. It also fails before raw socket creation, so it can't start a real 24-hour scan
    // even when the tests run as root.
    let output = run(&[
        "-h",
        "192.168.2.0/23",
        "-i",
        "lo",
        "-p",
        "1-65535",
        "-t",
        "86400",
    ]);

    assert!(!output.status.success(), "an oversized scan should fail");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a library validation error should exit with 1, not a usage error"
    );
    assert!(
        stderr(&output).contains("maximum is 16777214"),
        "the scan should fail on the probe limit, stderr was: {}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("exceeds the maximum of"),
        "the maximum CLI timeout should pass the library's timeout check"
    );
    assert!(
        !stderr(&output).contains("failed to create raw socket"),
        "the scan should be rejected before raw socket creation"
    );
}

#[test]
fn reports_invalid_targets_and_ports() {
    let target = run(&["-h", "not-an-address", "-i", "lo", "-p", "80"]);
    assert!(!target.status.success(), "an invalid target should fail");
    assert!(stdout(&target).is_empty(), "stdout should be empty");
    assert!(
        stderr(&target).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );
    assert!(
        stderr(&target).contains("invalid value 'not-an-address' for '--host <HOST>'"),
        "an invalid target should be reported as an invalid `--host` value"
    );
    assert!(
        stderr(&target).contains("invalid IPv4 address"),
        "the library's parse error should be included"
    );

    let ports = run(&["-h", "192.168.2.1", "-i", "lo", "-p", "80-79"]);
    assert!(!ports.status.success(), "an invalid port range should fail");
    assert!(stdout(&ports).is_empty(), "stdout should be empty");
    assert!(
        stderr(&ports).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );
    assert!(
        stderr(&ports).contains("invalid value '80-79' for '--ports <PORTS>'"),
        "an invalid port range should be reported as an invalid `--ports` value"
    );
    assert!(
        stderr(&ports).contains("reversed port range"),
        "the library's parse error should be included"
    );
}

#[test]
fn rejects_oversized_target_before_expansion() {
    let output = run(&["-h", "10.0.0.0/7", "-i", "lo", "-p", "80"]);

    assert!(!output.status.success(), "an oversized target should fail");
    assert!(stdout(&output).is_empty(), "stdout should be empty");
    assert!(
        stderr(&output).contains("split networks larger than a /8"),
        "the error should suggest splitting the network"
    );
}

#[test]
fn rejects_full_port_slash_23_before_raw_socket() {
    let output = run(&["-h", "192.168.2.0/23", "-i", "lo", "-p", "1-65535"]);

    assert!(!output.status.success(), "an oversized scan should fail");
    assert!(stdout(&output).is_empty(), "stdout should be empty");
    assert!(
        stderr(&output).contains("Scanning: 33422850 host/port pairs"),
        "the scan summary should report the requested probe count"
    );
    assert!(
        stderr(&output).contains("maximum is 16777214"),
        "the probe limit should be reported"
    );
    assert!(
        !stderr(&output).contains("failed to create raw socket"),
        "the scan should be rejected before raw socket creation"
    );
}

#[test]
fn rejects_zero_bandwidth() {
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

    assert!(!output.status.success(), "a zero bandwidth should fail");
    assert!(stdout(&output).is_empty(), "stdout should be empty");
    assert!(
        stderr(&output).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );
    assert!(
        stderr(&output).contains("invalid value '0' for '--bandwidth <BANDWIDTH>'"),
        "a zero bandwidth should be reported as an invalid value"
    );
    assert!(
        !stderr(&output).contains("failed to create raw socket"),
        "the scan should be rejected before raw socket creation"
    );
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

    assert!(!output.status.success(), "an unknown interface should fail");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a runtime error should exit with 1"
    );
    assert!(
        stderr(&output).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );
    assert!(
        stderr(&output).contains("does not exist"),
        "the unknown interface should be reported"
    );
    assert!(
        !stderr(&output).contains("failed to create raw socket"),
        "the scan should be rejected before raw socket creation"
    );
    assert!(stdout(&output).is_empty(), "stdout should be empty");
}

#[test]
fn defaults_to_services_file_ports_when_omitted() {
    let output = run(&["-h", "192.168.2.1", "-i", "lo"]);

    assert!(
        !output.status.success(),
        "an unprivileged scan should fail at raw socket creation"
    );
    assert!(stdout(&output).is_empty(), "stdout should be empty");
    assert!(
        stderr(&output).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );

    let summary = stderr(&output)
        .lines()
        .find(|line| line.starts_with("Scanning:"))
        .expect("scan summary should print before raw socket creation is attempted");
    let pairs = summary
        .split_whitespace()
        .nth(1)
        .and_then(|count| count.parse::<usize>().ok())
        .expect("scan summary should start with a numeric pair count");

    assert!(
        pairs > 1,
        "expected multiple ports loaded from /etc/services, scan summary was: {summary}"
    );
    assert!(
        stderr(&output).contains("failed to create raw socket"),
        "an unprivileged scan should fail at raw socket creation"
    );
}
