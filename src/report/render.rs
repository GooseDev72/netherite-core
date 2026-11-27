use crate::model::{NodeReport, StageStatus, Verdict};

pub fn render_report(r: &NodeReport) -> String {
    let mut out = String::new();
    let verdict = match &r.verdict {
        Verdict::Working => "WORKING".to_string(),
        Verdict::Degraded { reasons } => format!("DEGRADED ({})", reasons.join("; ")),
        Verdict::Dead { reasons } => format!("DEAD ({})", reasons.join("; ")),
        Verdict::Rejected { reasons } => format!("REJECTED ({})", reasons.join("; ")),
    };
    out.push_str(&format!(
        "node={}://{}:{} verdict={} confidence={:.2} ({})\n",
        r.candidate.protocol, r.candidate.host, r.candidate.port, verdict, r.confidence.score, r.confidence.label
    ));
    for e in &r.evidence {
        let mark = match e.status { StageStatus::Pass => "PASS", StageStatus::Warn => "WARN", StageStatus::Fail => "FAIL", StageStatus::Skip => "SKIP" };
        out.push_str(&format!(
            "  - [{mark}] {:?} score={:.2} weight={:.1} lat={:?} speed={:?} {}\n",
            e.stage, e.score, e.weight, e.latency_ms, e.speed_mbps, e.detail
        ));
    }
    out
}
