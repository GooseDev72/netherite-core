use std::collections::BTreeSet;
use std::net::ToSocketAddrs;
use std::time::Instant;

use crate::model::{Evidence, Stage};

pub fn check_dns_resolve(host: &str, port: u16) -> Evidence {
    let started = Instant::now();
    let target = format!("{}:{}", host, port);
    match target.to_socket_addrs() {
        Ok(addrs) => {
            let ips: BTreeSet<String> = addrs.map(|a| a.ip().to_string()).collect();
            if ips.is_empty() {
                Evidence::fail(Stage::DnsResolve, 15.0, format!("DNS empty for {}", host))
                    .with_latency(started.elapsed().as_millis())
            } else {
                Evidence::pass(Stage::DnsResolve, 15.0, format!("DNS {} -> {} addr(s)", host, ips.len()))
                    .with_latency(started.elapsed().as_millis())
                    .with_data("ips", ips.into_iter().collect::<Vec<_>>().join(","))
            }
        }
        Err(e) => Evidence::fail(Stage::DnsResolve, 15.0, format!("DNS failed for {}: {}", host, e))
            .with_latency(started.elapsed().as_millis()),
    }
}

/// Simple consistency check: resolve twice and compare. Catches flaky/local-poisoned resolution.
/// Not definitive, but useful evidence.
pub fn check_dns_consistency(host: &str, port: u16) -> Evidence {
    let t = format!("{}:{}", host, port);
    let r1 = t.to_socket_addrs().map(|a| a.map(|x| x.ip().to_string()).collect::<BTreeSet<_>>());
    let r2 = t.to_socket_addrs().map(|a| a.map(|x| x.ip().to_string()).collect::<BTreeSet<_>>());
    match (r1, r2) {
        (Ok(a), Ok(b)) if a.is_empty() || b.is_empty() => {
            Evidence::warn(Stage::DnsConsistency, 5.0, 0.2, "DNS consistency: empty answer")
        }
        (Ok(a), Ok(b)) => {
            let inter: BTreeSet<_> = a.intersection(&b).cloned().collect();
            if inter.is_empty() {
                Evidence::warn(Stage::DnsConsistency, 5.0, 0.3, format!("DNS answers changed: {:?} vs {:?}", a, b))
            } else if a == b {
                Evidence::pass(Stage::DnsConsistency, 5.0, "DNS answers stable across two resolves")
                    .with_data("ips", a.into_iter().collect::<Vec<_>>().join(","))
            } else {
                Evidence::pass(Stage::DnsConsistency, 5.0, "DNS answers overlap across resolves")
                    .with_data("intersection", inter.into_iter().collect::<Vec<_>>().join(","))
            }
        }
        _ => Evidence::warn(Stage::DnsConsistency, 5.0, 0.4, "DNS consistency check inconclusive"),
    }
}
