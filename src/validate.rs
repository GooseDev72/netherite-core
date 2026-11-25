use std::time::{Duration, Instant};

use reqwest::Client;

use crate::model::{CanaryTarget, Evidence, Stage, ValidationConfig};

/// Run HTTP canary targets. In proxy mode, the caller should pass a client
/// configured with the proxy/tunnel; in direct mode it checks host reachability.
/// Evidence includes per-target details for debug.
pub async fn check_http_canaries(client: &Client, cfg: &ValidationConfig) -> Evidence {
    let started = Instant::now();
    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut details = Vec::new();

    for t in &cfg.canaries {
        let r = probe_one(client, t, cfg.http_timeout).await;
        details.push(format!("{} => {}", t.url, r.detail));
        if r.ok { pass += 1; } else { fail += 1; }
    }

    let total = pass + fail;
    let detail = format!("canary {pass}/{total} pass; {}", details.join(" | "));
    let mut ev = if pass >= cfg.min_canary_pass && total >= cfg.min_canary_total.min(cfg.canaries.len()) {
        // score scales with pass ratio
        Evidence::pass(Stage::HttpCanary, 30.0, detail)
    } else if pass > 0 {
        let ratio = pass as f32 / total.max(1) as f32;
        Evidence::warn(Stage::HttpCanary, 30.0, ratio, detail)
    } else {
        Evidence::fail(Stage::HttpCanary, 30.0, detail)
    };
    ev.latency_ms = Some(started.elapsed().as_millis());
    ev.score = (pass as f32 / total.max(1) as f32).clamp(0.0, 1.0);
    if !matches!(ev.status, crate::model::StageStatus::Fail) && pass < cfg.min_canary_pass {
        ev.status = crate::model::StageStatus::Warn;
    }
    ev.data.insert("pass".into(), pass.to_string());
    ev.data.insert("total".into(), total.to_string());
    ev
}

struct OneResult { ok: bool, detail: String }

async fn probe_one(client: &Client, t: &CanaryTarget, timeout_dur: Duration) -> OneResult {
    let res = tokio::time::timeout(timeout_dur, client.get(&t.url).send()).await;
    match res {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            let ok = if t.expect_any_status { (200..500).contains(&status) } else { status == 204 || (200..300).contains(&status) };
            // Lightweight content integrity: detect obvious captive/block pages on 200
            let integrity_ok = if ok && status == 200 {
                // We don't read body here to keep it cheap; body check can be done by caller.
                true
            } else { ok };
            OneResult { ok: integrity_ok, detail: format!("status={status}") }
        }
        Ok(Err(e)) => OneResult { ok: false, detail: format!("err={e}") },
        Err(_) => OneResult { ok: false, detail: "timeout".into() },
    }
}

/// Content integrity heuristic: flag small/known-bad bodies as captive portal or block page.
/// Caller provides optional body sample and final URL/domain.
pub fn check_content_integrity(body_sample: &str, final_host: Option<&str>) -> Evidence {
    let body = body_sample.to_lowercase();
    let bad_signatures = [
        "captive portal", "login to network", "wifi login", "blocked", "access denied",
        "forbidden", "your request has been blocked", "attention required", "cloudflare",
    ];
    let mut hits = Vec::new();
    for sig in bad_signatures {
        if body.contains(sig) { hits.push(sig); }
    }
    // Cloudflare "attention required" in a canary body is bad; "cloudflare" alone is too broad.
    let strong = hits.iter().any(|s| matches!(*s, "captive portal" | "login to network" | "wifi login" | "your request has been blocked" | "attention required"));
    let host_note = final_host.unwrap_or("unknown");
    if strong {
        Evidence::fail(Stage::ContentIntegrity, 25.0, format!("possible captive/block page on {host_note}: {:?}", hits))
    } else if !hits.is_empty() {
        Evidence::warn(Stage::ContentIntegrity, 10.0, 0.4, format!("suspicious content markers on {host_note}: {:?}", hits))
    } else {
        Evidence::pass(Stage::ContentIntegrity, 10.0, "no captive/block signatures detected")
    }
}

pub fn check_speed_threshold(measured_mbps: Option<f64>, threshold_mbps: f64) -> Evidence {
    match measured_mbps {
        Some(mbps) if mbps >= threshold_mbps => {
            Evidence::pass(Stage::SpeedThreshold, 20.0, format!("{:.2} Mbps >= {:.2}", mbps, threshold_mbps)).with_speed(mbps)
        }
        Some(mbps) => {
            Evidence::fail(Stage::SpeedThreshold, 20.0, format!("{:.2} Mbps < {:.2}", mbps, threshold_mbps)).with_speed(mbps)
        }
        None => Evidence::warn(Stage::SpeedThreshold, 20.0, 0.0, "speed not measured"),
    }
}

/// Stability evidence from multiple latency samples (ms). Lower jitter/variance is better.
pub fn check_stability(samples_ms: &[u128], max_latency_ms: u128) -> Evidence {
    if samples_ms.is_empty() {
        return Evidence::skip(Stage::Stability, "no stability samples");
    }
    let avg = samples_ms.iter().sum::<u128>() as f64 / samples_ms.len() as f64;
    let min = *samples_ms.iter().min().unwrap_or(&0) as f64;
    let max = *samples_ms.iter().max().unwrap_or(&0) as f64;
    let jitter = max - min;
    let detail = format!("stability avg={avg:.0}ms min={min:.0}ms max={max:.0}ms jitter={jitter:.0}ms n={}", samples_ms.len());

    if avg as u128 > max_latency_ms {
        return Evidence::fail(Stage::Stability, 10.0, detail).with_latency(avg as u128);
    }
    // jitter penalty: >1500ms jitter is suspicious for "working"
    let score = if jitter <= 300.0 { 1.0 } else if jitter <= 800.0 { 0.8 } else if jitter <= 1500.0 { 0.5 } else { 0.2 };
    if score >= 0.8 {
        Evidence::pass(Stage::Stability, 10.0, detail).with_latency(avg as u128)
    } else {
        Evidence::warn(Stage::Stability, 10.0, score, detail).with_latency(avg as u128)
    }
}
