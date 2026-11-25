use crate::model::{Evidence, NodeCandidate, ValidationConfig};

/// Extension point: implement to provide probe evidence from a real proxy tunnel,
/// browser, mobile stack, or custom transport.
/// 
/// Netherite Core is policy/evidence engine; probes are adapters.
#[allow(async_fn_in_trait)]
pub trait Probe: Send + Sync {
    async fn probe(&self, candidate: &NodeCandidate, cfg: &ValidationConfig) -> Vec<Evidence>;
    fn name(&self) -> &'static str { "probe" }
}

/// No-op probe.
pub struct NoopProbe;
impl Probe for NoopProbe {
    async fn probe(&self, _candidate: &NodeCandidate, _cfg: &ValidationConfig) -> Vec<Evidence> { vec![] }
}
