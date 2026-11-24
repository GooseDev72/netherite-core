use crate::model::{Confidence, Evidence, Stage, StageStatus, ValidationConfig, Verdict};

/// Score evidence and apply hard gates.
/// 
/// Design: WORKING requires passing critical gates AND achieving confidence.
/// This avoids "one lucky 204" false positives.
pub fn classify(evidence: &[Evidence], cfg: &ValidationConfig) -> (Verdict, Confidence) {
    let mut reasons_fail = Vec::new();
    let mut reasons_warn = Vec::new();

    let has = |stage: Stage| evidence.iter().any(|e| e.stage == stage);
    let passed = |stage: Stage| evidence.iter().any(|e| e.stage == stage && matches!(e.status, StageStatus::Pass));
    let failed = |stage: Stage| evidence.iter().any(|e| e.stage == stage && matches!(e.status, StageStatus::Fail));

    // Hard gates
    if cfg.require_dns && has(Stage::DnsResolve) && !passed(Stage::DnsResolve) {
        reasons_fail.push("dns_resolve failed".to_string());
    }
    if cfg.require_tcp && has(Stage::TcpConnect) && !passed(Stage::TcpConnect) {
        reasons_fail.push("tcp_connect failed".to_string());
    }
    if cfg.require_canary && has(Stage::HttpCanary) && !passed(Stage::HttpCanary) {
        reasons_fail.push("http_canary failed".to_string());
    }
    if cfg.require_speed && has(Stage::SpeedThreshold) && !passed(Stage::SpeedThreshold) {
        reasons_fail.push("speed_threshold failed".to_string());
    }
    if failed(Stage::GeofencePolicy) {
        reasons_fail.push("geofence_policy failed".to_string());
    }
    if failed(Stage::GeoConsistency) {
        reasons_fail.push("geo_consistency failed".to_string());
    }
    if failed(Stage::AsnReputation) {
        reasons_fail.push("asn_reputation failed".to_string());
    }
    if failed(Stage::Consensus) {
        reasons_fail.push("consensus failed".to_string());
    }
    if failed(Stage::ContentIntegrity) {
        reasons_fail.push("content_integrity failed".to_string());
    }

    // Weighted confidence score
    let mut weight_sum = 0.0f32;
    let mut score_sum = 0.0f32;
    for e in evidence {
        if matches!(e.status, StageStatus::Skip) { continue; }
        weight_sum += e.weight;
        score_sum += e.weight * e.score;
        if matches!(e.status, StageStatus::Warn | StageStatus::Fail) {
            reasons_warn.push(format!("{:?}: {}", e.stage, e.detail));
        }
    }
    let normalized = if weight_sum > 0.0 { score_sum / weight_sum } else { 0.0 };
    let confidence = Confidence::from_score(normalized);

    // Verdict policy
    let verdict = if !reasons_fail.is_empty() {
        // Distinguish dead vs rejected: rejected means policy/integrity gate
        let rejected = failed(Stage::ContentIntegrity)
            || failed(Stage::TransportSanity)
            || failed(Stage::GeofencePolicy)
            || failed(Stage::GeoConsistency)
            || failed(Stage::AsnReputation);
        if rejected {
            Verdict::Rejected { reasons: dedup_reasons(reasons_fail, reasons_warn) }
        } else {
            Verdict::Dead { reasons: dedup_reasons(reasons_fail, reasons_warn) }
        }
    } else {
        // No hard-gate failures. Require sufficient confidence for WORKING.
        let canary_ok = !cfg.require_canary || passed(Stage::HttpCanary);
        let dns_ok = !cfg.require_dns || passed(Stage::DnsResolve);
        let tcp_ok = !cfg.require_tcp || passed(Stage::TcpConnect);
        let speed_ok = !cfg.require_speed || passed(Stage::SpeedThreshold);
        let stability_ok = !has(Stage::Stability) || passed(Stage::Stability) || evidence.iter().any(|e| e.stage==Stage::Stability && matches!(e.status, StageStatus::Warn));

        if dns_ok && tcp_ok && canary_ok && speed_ok && stability_ok && confidence.score >= cfg.min_working_confidence {
            Verdict::Working
        } else {
            let mut reasons = reasons_warn;
            if confidence.score < cfg.min_working_confidence { reasons.push(format!("confidence {:.2} < {:.2}", confidence.score, cfg.min_working_confidence)); }
            if reasons.is_empty() { reasons.push("insufficient evidence".to_string()); }
            Verdict::Degraded { reasons: dedup(reasons) }
        }
    };

    (verdict, confidence)
}

fn dedup(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v.dedup();
    v
}

fn dedup_reasons(mut a: Vec<String>, mut b: Vec<String>) -> Vec<String> {
    a.append(&mut b);
    dedup(a)
}
