//! Privileged loopback integration tests for the singsing-rs scanner.

#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use singsing_rs::{PortState, ScanConfig, ScanResult, scan, scan_with_callback};

const TEST_TIMEOUT: Duration = Duration::from_millis(250);

fn scan_config(ports: Vec<u16>, show_closed: bool) -> ScanConfig {
    let mut config = ScanConfig::new(vec![Ipv4Addr::LOCALHOST], ports, Ipv4Addr::LOCALHOST);
    config.bandwidth_kib = 1024;
    config.timeout = TEST_TIMEOUT;
    config.show_closed = show_closed;
    config
}

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

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn detects_open_loopback_port() {
    let listener = loopback_listener();
    let port = listener.local_addr().unwrap().port();

    assert_eq!(
        scan(&scan_config(vec![port], false)).unwrap(),
        [ScanResult {
            host: Ipv4Addr::LOCALHOST,
            port,
            state: PortState::Open,
        }]
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn controls_closed_loopback_reporting() {
    let port = unused_loopback_port();

    assert!(scan(&scan_config(vec![port], false)).unwrap().is_empty());
    assert_eq!(
        scan(&scan_config(vec![port], true)).unwrap(),
        [ScanResult {
            host: Ipv4Addr::LOCALHOST,
            port,
            state: PortState::Closed,
        }]
    );
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn sorts_mixed_loopback_results() {
    let first_listener = loopback_listener();
    let second_listener = loopback_listener();
    let first_open = first_listener.local_addr().unwrap().port();
    let second_open = second_listener.local_addr().unwrap().port();
    let closed = unused_loopback_port();
    let mut expected = [
        ScanResult {
            host: Ipv4Addr::LOCALHOST,
            port: first_open,
            state: PortState::Open,
        },
        ScanResult {
            host: Ipv4Addr::LOCALHOST,
            port: second_open,
            state: PortState::Open,
        },
        ScanResult {
            host: Ipv4Addr::LOCALHOST,
            port: closed,
            state: PortState::Closed,
        },
    ];
    expected.sort_unstable_by_key(|result| result.port);

    let results = scan(&scan_config(vec![second_open, closed, first_open], true)).unwrap();

    assert_eq!(results, expected);
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn delivers_callback_and_final_result() {
    let listener = loopback_listener();
    let port = listener.local_addr().unwrap().port();
    let (sender, receiver) = mpsc::channel();

    let results = scan_with_callback(&scan_config(vec![port], false), move |result| {
        sender
            .send(result)
            .map_err(|error| anyhow::anyhow!("failed to forward callback result: {error}"))
    })
    .unwrap();
    let callbacks: Vec<_> = receiver.into_iter().collect();

    assert_eq!(callbacks, results);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].state, PortState::Open);
}

#[test]
#[ignore = "requires Linux and root or CAP_NET_RAW"]
fn waits_for_post_transmission_timeout() {
    let port = unused_loopback_port();
    let started = Instant::now();

    let results = scan(&scan_config(vec![port], false)).unwrap();
    let elapsed = started.elapsed();

    assert!(results.is_empty());
    assert!(elapsed >= TEST_TIMEOUT);
    assert!(elapsed < Duration::from_secs(5));
}
