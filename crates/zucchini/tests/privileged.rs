//! Privileged loopback integration tests for the zucchini binary.

#![cfg(target_os = "linux")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "no need to have a test module for integration tests in `/tests`"
)]
#![expect(clippy::panic, reason = "panics are allowed in test code")]
#![expect(clippy::unwrap_used, reason = "tests can use `unwrap`")]
#![expect(clippy::expect_used, reason = "tests can use `expect`")]

use std::net::{Ipv4Addr, TcpListener};
use std::process::{Command, Output};
use std::str;
use std::sync::atomic::{AtomicU16, Ordering};

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

fn unused_loopback_port() -> u16 {
    let listener = loopback_listener();
    listener
        .local_addr()
        .expect("listener should have a local address")
        .port()
}

fn run(port: u16, extra_arguments: &[&str]) -> Output {
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

fn stdout(output: &Output) -> &str {
    str::from_utf8(&output.stdout).expect("stdout should be UTF-8")
}

fn stderr(output: &Output) -> &str {
    str::from_utf8(&output.stderr).expect("stderr should be UTF-8")
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn scans_open_port_end_to_end() {
    let listener = loopback_listener();
    let port = listener.local_addr().unwrap().port();
    let output = run(port, &[]);
    let result = format!("open 127.0.0.1:{port}");

    assert!(output.status.success());
    assert!(stderr(&output).starts_with("zucchini "));
    assert!(stderr(&output).contains("Scanning: 1 host/port pairs via lo (127.0.0.1)"));
    assert!(stdout(&output).contains("Scan results:"));
    assert!(stdout(&output).contains(&result));
    assert!(stderr(&output).contains("Done: 1 host/port pairs scanned"));
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn scans_open_port_in_verbose_mode() {
    let listener = loopback_listener();
    let port = listener.local_addr().unwrap().port();
    let output = run(port, &["--verbose"]);
    let result = format!("open 127.0.0.1:{port}");

    assert!(output.status.success());
    assert!(stdout(&output).contains(&format!("[verbose] {result}")));
    assert_eq!(stdout(&output).matches(&result).count(), 2);
    assert!(stdout(&output).contains("\nScan results:\n"));
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn reports_closed_port_end_to_end() {
    let port = unused_loopback_port();
    let output = run(port, &["--closed"]);

    assert!(output.status.success());
    assert!(
        stdout(&output).contains(&format!("closed 127.0.0.1:{port}")),
        "stdout was: {}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("Done: 1 host/port pairs scanned"));
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn hides_closed_port_by_default_end_to_end() {
    let port = unused_loopback_port();
    let output = run(port, &[]);

    assert!(output.status.success());
    assert!(
        stdout(&output).is_empty(),
        "stdout was: {}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("Done: 1 host/port pairs scanned"));
}
