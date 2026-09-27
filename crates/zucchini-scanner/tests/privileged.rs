//! Privileged Linux loopback integration tests for the zucchini binary.

#![cfg(target_os = "linux")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "no need to have a test module for integration tests in `/tests`"
)]
#![expect(clippy::panic, reason = "panics are allowed in test code")]
#![expect(clippy::expect_used, reason = "tests can use `expect`")]

use std::net::{Ipv4Addr, TcpListener};
use std::process::{Command, Output};
use std::str;
use std::sync::atomic::{AtomicU16, Ordering};

use singsing_rs::Port;

/// Binds a TCP listener on the first free loopback port from 20000 upward.
fn loopback_listener() -> TcpListener {
    static NEXT_PORT: AtomicU16 = AtomicU16::new(20_000);

    for _ in 0..10_000 {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
            return listener;
        }
    }
    panic!("no loopback test port available between 20000 and 29999");
}

/// Returns the port a listener is bound to.
fn listener_port(listener: &TcpListener) -> Port {
    let port = listener
        .local_addr()
        .expect("listener should have a local address")
        .port();
    Port::new(port).expect("a bound listener's port should never be zero")
}

/// Returns a loopback port that was free a moment ago and has no listener bound to it.
fn unused_loopback_port() -> Port {
    listener_port(&loopback_listener())
}

/// Runs a fast, short-timeout `zucchini` loopback scan of `port` with any extra arguments.
fn run(port: Port, extra_arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zucchini"))
        .args([
            "--host",
            "127.0.0.1",
            "--interface",
            "lo",
            "--ports",
            &port.to_string(),
            "--bandwidth",
            "1024",
            "--timeout",
            "1",
        ])
        .args(extra_arguments)
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
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn scans_open_port_end_to_end() {
    let listener = loopback_listener();
    let port = listener_port(&listener);
    let output = run(port, &[]);
    let result = format!("open 127.0.0.1:{port}");

    assert!(output.status.success(), "the scan should succeed");
    assert!(
        stderr(&output).starts_with("zucchini "),
        "the banner should be printed to stderr"
    );
    assert!(
        stderr(&output).contains("Scanning: 1 host/port pairs via lo (127.0.0.1)"),
        "the scan summary should be printed to stderr"
    );
    assert!(
        stdout(&output).contains("Scan results:"),
        "the results heading should be printed to stdout"
    );
    assert!(
        stdout(&output).contains(&result),
        "the open port should be printed to stdout"
    );
    assert!(
        stderr(&output).contains("Done: 1 host/port pairs scanned"),
        "the done summary should be printed to stderr"
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn scans_open_port_in_verbose_mode() {
    let listener = loopback_listener();
    let port = listener_port(&listener);
    let output = run(port, &["--verbose"]);
    let result = format!("open 127.0.0.1:{port}");

    assert!(output.status.success(), "the scan should succeed");
    assert!(
        stdout(&output).contains(&format!("[verbose] {result}")),
        "the open port should be streamed as a verbose line"
    );
    assert_eq!(
        stdout(&output).matches(&result).count(),
        2,
        "the open port should be printed once live and once in the final results"
    );
    assert!(
        stdout(&output).contains("\nScan results:\n"),
        "the results heading should follow the verbose lines"
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn reports_closed_port_end_to_end() {
    let port = unused_loopback_port();
    let output = run(port, &["--closed"]);

    assert!(output.status.success(), "the scan should succeed");
    assert!(
        stdout(&output).contains(&format!("closed 127.0.0.1:{port}")),
        "the closed port should be printed with `--closed`, stdout was: {}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("Done: 1 host/port pairs scanned"),
        "the done summary should be printed to stderr"
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn hides_closed_port_by_default_end_to_end() {
    let port = unused_loopback_port();
    let output = run(port, &[]);

    assert!(output.status.success(), "the scan should succeed");
    assert!(
        stdout(&output).is_empty(),
        "the closed port should be hidden without `--closed`, stdout was: {}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("Done: 1 host/port pairs scanned"),
        "the done summary should be printed to stderr"
    );
}
