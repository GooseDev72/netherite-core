use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::model::{Evidence, Stage};

pub async fn check_tcp(host: &str, port: u16, timeout_ms: u64) -> Evidence {
    let started = std::time::Instant::now();
    let addr = format!("{}:{}", host, port);
    let res = timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await;
    match res {
        Ok(Ok(_stream)) => Evidence::pass(Stage::TcpConnect, 20.0, format!("TCP connected {}", addr))
            .with_latency(started.elapsed().as_millis()),
        Ok(Err(e)) => Evidence::fail(Stage::TcpConnect, 20.0, format!("TCP failed {}: {}", addr, e))
            .with_latency(started.elapsed().as_millis()),
        Err(_) => Evidence::fail(Stage::TcpConnect, 20.0, format!("TCP timeout {}", addr))
            .with_latency(started.elapsed().as_millis()),
    }
}

/// Lightweight transport sanity from metadata (not a full protocol probe).
/// Real protocol probing happens in netherite's xray/mihomo adapters; core records sanity.
pub fn check_transport_sanity(protocol: &str, transport: Option<&str>, tls: Option<&str>) -> Evidence {
    let proto = protocol.to_lowercase();
    let tr = transport.unwrap_or("").to_lowercase();
    let tls_s = tls.unwrap_or("").to_lowercase();

    // Basic sanity rules; intentionally conservative, only reject obvious nonsense.
    if proto.is_empty() {
        return Evidence::fail(Stage::TransportSanity, 5.0, "empty protocol");
    }
    if (proto == "vless" || proto == "trojan") && tr == "grpc" && tls_s.is_empty() {
        return Evidence::warn(Stage::TransportSanity, 5.0, 0.6, "grpc without explicit tls/security field");
    }
    if tr.contains("ws") && tls_s == "none" {
        return Evidence::warn(Stage::TransportSanity, 5.0, 0.7, "ws transport with tls none");
    }
    Evidence::pass(Stage::TransportSanity, 5.0, format!("transport sanity ok: proto={proto} transport={tr} tls={tls_s}"))
}
