use std::time::{Duration, Instant};
use reqwest::Client;
use crate::model::{CanaryTarget, Evidence, Stage, ValidationConfig};

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
        Evidence::pass(Stage::HttpCanary, 30.0, detail)
    } else if pass > 0 {
        Evidence::warn(Stage::HttpCanary, 30.0, pass as f32 / total.max(1) as f32, detail)
    } else {
        Evidence::fail(Stage::HttpCanary, 30.0, detail)
    };
    ev.latency_ms = Some(started.elapsed().as_millis());
    ev.score = (pass as f32 / total.max(1) as f32).clamp(0.0, 1.0);
    if !matches!(ev.status, crate::model::StageStatus::Fail) && pass < cfg.min_canary_pass { ev.status = crate::model::StageStatus::Warn; }
    ev.data.insert("pass".into(), pass.to_string());
    ev.data.insert("total".into(), total.to_string());
    ev
}

struct OneResult { ok: bool, detail: String }
async fn probe_one(client: &Client, t: &CanaryTarget, timeout_dur: Duration) -> OneResult {
    let res = tokio::time::timeout(timeout_dur, client.get(&t.url).send()).await;
    match res {
        Ok(Ok(resp)) => { let status = resp.status().as_u16(); let ok = if t.expect_any_status { (200..500).contains(&status) } else { status == 204 || (200..300).contains(&status) }; OneResult { ok, detail: format!("status={status}") } }
        Ok(Err(e)) => OneResult { ok: false, detail: format!("err={e}") },
        Err(_) => OneResult { ok: false, detail: "timeout".into() },
    }
}
