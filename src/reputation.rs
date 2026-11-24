use crate::model::{Evidence, GeoInfo, Stage};

/// Reputation heuristics. No external DB required; caller can enrich GeoInfo.
pub fn check_exit_reputation(exit_geo: Option<&GeoInfo>) -> Evidence {
    let Some(g) = exit_geo else {
        return Evidence::skip(Stage::ExitReputation, "no exit geo for reputation");
    };
    let net = g.network_type.as_deref().unwrap_or("unknown").to_lowercase();
    let org = g.as_org.as_deref().unwrap_or("").to_lowercase();

    // Heuristics: not hard-fail by default, but provide evidence.
    let mut score: f32 = 0.8;
    let mut notes = Vec::new();

    if net.contains("hosting") || net.contains("datacenter") {
        score -= 0.1;
        notes.push("hosting/datacenter network".to_string());
    }
    if org.contains("cloud") || org.contains("vpn") || org.contains("proxy") {
        score -= 0.05;
        notes.push("org suggests cloud/vpn/proxy".to_string());
    }
    if net.contains("residential") || net.contains("mobile") {
        score += 0.1;
        notes.push("residential/mobile network".to_string());
    }
    let score = score.clamp(0.0, 1.0);
    let detail = if notes.is_empty() { format!("exit reputation neutral: net={net}") } else { notes.join(", ") };
    if score >= 0.7 {
        Evidence::pass(Stage::ExitReputation, 8.0, detail).with_data("score", format!("{score:.2}"))
    } else {
        Evidence::warn(Stage::ExitReputation, 8.0, score, detail).with_data("score", format!("{score:.2}"))
    }
}

pub fn check_asn_reputation(exit_geo: Option<&GeoInfo>, deny_asn: &[u32]) -> Evidence {
    let Some(g) = exit_geo else { return Evidence::skip(Stage::AsnReputation, "no exit geo for ASN"); };
    let Some(asn) = g.asn else { return Evidence::skip(Stage::AsnReputation, "no ASN"); };
    if deny_asn.contains(&asn) {
        return Evidence::fail(Stage::AsnReputation, 25.0, format!("ASN {} in deny list", asn));
    }
    Evidence::pass(Stage::AsnReputation, 5.0, format!("ASN {} ok", asn)).with_data("asn", asn.to_string())
}
