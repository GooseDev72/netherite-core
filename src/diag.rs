use crate::model::{Evidence, NodeCandidate};

pub fn debug_ev(enabled: bool, c: &NodeCandidate, e: &Evidence) {
    if !enabled { return; }
    eprintln!(
        "[core-debug] {}:{} proto={} stage={:?} status={:?} score={:.2} weight={:.1} lat={:?} speed={:?} detail={}",
        c.host, c.port, c.protocol, e.stage, e.status, e.score, e.weight, e.latency_ms, e.speed_mbps, e.detail
    );
}

pub fn info(msg: impl AsRef<str>) {
    eprintln!("[core] {}", msg.as_ref());
}
