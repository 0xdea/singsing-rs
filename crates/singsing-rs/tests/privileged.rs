//! Privileged Linux loopback integration tests for the singsing-rs library.

#![cfg(target_os = "linux")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "no need to have a test module for integration tests in `/tests`"
)]
#![expect(clippy::panic, reason = "panics are allowed in test code")]
#![expect(clippy::unwrap_used, reason = "tests can use `unwrap`")]
#![expect(clippy::expect_used, reason = "tests can use `expect`")]

use std::net::{Ipv4Addr, TcpListener};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use singsing_rs::{
    CallbackError, Port, PortState, ScanConfig, ScanResult, scan, scan_with_callback,
};

/// The late-reply timeout used by every loopback scan.
const TEST_TIMEOUT: Duration = Duration::from_millis(250);

/// Builds a fast, short-timeout loopback scan configuration for the given ports.
fn scan_config(ports: Vec<Port>, show_closed: bool) -> ScanConfig {
    let mut config = ScanConfig::new(vec![Ipv4Addr::LOCALHOST], ports, Ipv4Addr::LOCALHOST);
    config.bandwidth_kib = NonZeroU64::new(1024).unwrap();
    config.timeout = TEST_TIMEOUT;
    config.show_closed = show_closed;
    config
}

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

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn detects_open_loopback_port() {
    let listener = loopback_listener();
    let port = listener_port(&listener);

    assert_eq!(
        scan(&scan_config(vec![port], false)).unwrap(),
        [ScanResult::new(Ipv4Addr::LOCALHOST, port, PortState::Open)],
        "a listening loopback port should be reported as open"
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn controls_closed_loopback_reporting() {
    let port = unused_loopback_port();

    assert!(
        scan(&scan_config(vec![port], false)).unwrap().is_empty(),
        "a closed port should not be reported when `show_closed` is off"
    );
    assert_eq!(
        scan(&scan_config(vec![port], true)).unwrap(),
        [ScanResult::new(
            Ipv4Addr::LOCALHOST,
            port,
            PortState::Closed
        )],
        "a closed port should be reported when `show_closed` is on"
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn sorts_mixed_loopback_results() {
    let first_listener = loopback_listener();
    let second_listener = loopback_listener();
    let first_open = listener_port(&first_listener);
    let second_open = listener_port(&second_listener);
    let closed = unused_loopback_port();
    let mut expected = [
        ScanResult::new(Ipv4Addr::LOCALHOST, first_open, PortState::Open),
        ScanResult::new(Ipv4Addr::LOCALHOST, second_open, PortState::Open),
        ScanResult::new(Ipv4Addr::LOCALHOST, closed, PortState::Closed),
    ];
    expected.sort_unstable_by_key(|result| result.port);

    let results = scan(&scan_config(vec![second_open, closed, first_open], true)).unwrap();

    assert_eq!(
        results, expected,
        "results should be sorted by port regardless of scan order"
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn delivers_callback_and_final_result() {
    let listener = loopback_listener();
    let port = listener_port(&listener);
    let (sender, receiver) = mpsc::channel();

    let results = scan_with_callback(&scan_config(vec![port], false), move |result| {
        sender.send(result).map_err(CallbackError::from)
    })
    .unwrap();
    let callbacks = receiver.into_iter().collect::<Vec<_>>();

    assert_eq!(
        callbacks, results,
        "the callback should see exactly the returned results"
    );
    assert_eq!(results.len(), 1, "one open port should yield one result");
    assert_eq!(
        results[0].state,
        PortState::Open,
        "the result should report the port as open"
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn waits_for_post_transmission_timeout() {
    let port = unused_loopback_port();
    let started = Instant::now();

    let results = scan(&scan_config(vec![port], false)).unwrap();
    let elapsed = started.elapsed();

    assert!(
        results.is_empty(),
        "a closed port should not be reported when `show_closed` is off"
    );
    assert!(
        elapsed >= TEST_TIMEOUT,
        "the scan should wait the late-reply timeout, but took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the scan should not wait much longer than the timeout, but took {elapsed:?}"
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn zero_timeout_returns_promptly() {
    let listener = loopback_listener();
    let port = listener_port(&listener);
    let mut config = scan_config(vec![port], false);
    config.timeout = Duration::ZERO;
    let started = Instant::now();

    let results = scan(&config).unwrap();
    let elapsed = started.elapsed();

    // Whether the loopback SYN/ACK is read before the receiver notices sending is done is a race,
    // so the open port may or may not be reported; the scan must just not hang or misreport.
    assert!(
        elapsed < Duration::from_secs(2),
        "a zero-timeout scan should stop shortly after sending, but took {elapsed:?}"
    );
    assert!(
        results
            .iter()
            .all(|result| *result == ScanResult::new(Ipv4Addr::LOCALHOST, port, PortState::Open)),
        "a zero-timeout scan should only report the open port, but reported {results:?}"
    );
}
