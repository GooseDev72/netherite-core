use crate::model::{Evidence, NodeHistory, Stage};

pub fn check_history(history: Option<&NodeHistory>) -> Evidence {
    let Some(h) = history else { return Evidence::skip(Stage::HistoryStability, "no history"); };

    let mut score: f32 = 0.5;
    if h.consecutive_working >= 3 { score += 0.3; }
    else if h.consecutive_working >= 1 { score += 0.15; }
    if h.consecutive_dead >= 3 { score -= 0.3; }
    else if h.consecutive_dead >= 1 { score -= 0.1; }

    if let (Some(avg), Some(last)) = (h.avg_latency_ms, h.avg_latency_ms) {
        let _ = (avg, last);
    }
    let score = score.clamp(0.0, 1.0);
    let detail = format!(
        "history working={} dead={} last={:?}",
        h.consecutive_working, h.consecutive_dead, h.last_verdict
    );
    if score >= 0.75 {
        Evidence::pass(Stage::HistoryStability, 10.0, detail).with_data("score", format!("{score:.2}"))
    } else if score >= 0.4 {
        Evidence::warn(Stage::HistoryStability, 10.0, score, detail).with_data("score", format!("{score:.2}"))
    } else {
        Evidence::warn(Stage::HistoryStability, 10.0, score, detail).with_data("score", format!("{score:.2}"))
    }
}
