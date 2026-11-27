use crate::model::{Evidence, Stage, Verdict};

/// Consensus across multiple probe engines/runs. Useful for Xray+Mihomo dual-check.
pub fn check_consensus(verdicts: &[(&str, Verdict)]) -> Evidence {
    if verdicts.is_empty() { return Evidence::skip(Stage::Consensus, "no consensus inputs"); }
    let working = verdicts.iter().filter(|(_, v)| matches!(v, Verdict::Working)).count();
    let dead = verdicts.iter().filter(|(_, v)| matches!(v, Verdict::Dead { .. } | Verdict::Rejected { .. })).count();
    let total = verdicts.len();
    let detail = verdicts.iter().map(|(n,v)| format!("{}={:?}", n, verdict_name(v))).collect::<Vec<_>>().join(", ");

    if working == total {
        Evidence::pass(Stage::Consensus, 20.0, format!("all agree WORKING: {detail}"))
    } else if dead == total {
        Evidence::fail(Stage::Consensus, 20.0, format!("all agree DEAD/REJECTED: {detail}"))
    } else if working > 0 && dead > 0 {
        Evidence::warn(Stage::Consensus, 20.0, 0.4, format!("disagreement: {detail}"))
    } else {
        Evidence::warn(Stage::Consensus, 20.0, 0.6, format!("partial consensus: {detail}"))
    }
}

fn verdict_name(v: &Verdict) -> &'static str {
    match v {
        Verdict::Working => "WORKING",
        Verdict::Degraded { .. } => "DEGRADED",
        Verdict::Dead { .. } => "DEAD",
        Verdict::Rejected { .. } => "REJECTED",
    }
}
