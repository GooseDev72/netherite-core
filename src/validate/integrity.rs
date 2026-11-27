use crate::model::{Evidence, Stage};

pub fn check_content_integrity(body_sample: &str, final_host: Option<&str>) -> Evidence {
    let body = body_sample.to_lowercase();
    let bad_signatures = [
        "captive portal", "login to network", "wifi login", "blocked", "access denied",
        "forbidden", "your request has been blocked", "attention required", "cloudflare",
    ];
    let mut hits = Vec::new();
    for sig in bad_signatures { if body.contains(sig) { hits.push(sig); } }
    let strong = hits.iter().any(|s| matches!(*s, "captive portal" | "login to network" | "wifi login" | "your request has been blocked" | "attention required"));
    let host_note = final_host.unwrap_or("unknown");
    if strong { Evidence::fail(Stage::ContentIntegrity, 25.0, format!("possible captive/block page on {host_note}: {:?}", hits)) }
    else if !hits.is_empty() { Evidence::warn(Stage::ContentIntegrity, 10.0, 0.4, format!("suspicious content markers on {host_note}: {:?}", hits)) }
    else { Evidence::pass(Stage::ContentIntegrity, 10.0, "no captive/block signatures detected") }
}
