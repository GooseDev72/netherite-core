use crate::model::{Evidence, Stage};

pub fn check_stability(samples_ms: &[u128], max_latency_ms: u128) -> Evidence {
    if samples_ms.is_empty() { return Evidence::skip(Stage::Stability, "no stability samples"); }
    let avg = samples_ms.iter().sum::<u128>() as f64 / samples_ms.len() as f64;
    let min = *samples_ms.iter().min().unwrap_or(&0) as f64;
    let max = *samples_ms.iter().max().unwrap_or(&0) as f64;
    let jitter = max - min;
    let detail = format!("stability avg={avg:.0}ms min={min:.0}ms max={max:.0}ms jitter={jitter:.0}ms n={}", samples_ms.len());
    if avg as u128 > max_latency_ms { return Evidence::fail(Stage::Stability, 10.0, detail).with_latency(avg as u128); }
    let score = if jitter <= 300.0 { 1.0 } else if jitter <= 800.0 { 0.8 } else if jitter <= 1500.0 { 0.5 } else { 0.2 };
    if score >= 0.8 { Evidence::pass(Stage::Stability, 10.0, detail).with_latency(avg as u128) }
    else { Evidence::warn(Stage::Stability, 10.0, score, detail).with_latency(avg as u128) }
}
