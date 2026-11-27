//! Netherite Core — evidence-based validation engine for proxy/subscription nodes.
//!
//! Unique design goals:
//! - **Evidence, not booleans**: every stage emits structured evidence.
//! - **Hard gates + confidence scoring**: WORKING requires critical gates and confidence.
//! - **Pluggable probes**: adapters (xray/mihomo/browser/mobile) feed evidence.
//! - **Explainable debug traces**: every verdict can be audited.
//!
//! Suitable as a Rust library; Python bindings can wrap this API (pyo3).

pub mod consensus;
pub mod decode;
pub mod diag;
pub mod dns;
pub mod geo;
pub mod history;
pub mod ip2asn;
pub mod model;
pub mod pipeline;
pub mod probe;
pub mod profile;
pub mod report;
pub mod reputation;
pub mod scoring;
pub mod transport;
pub mod v2;
pub mod validate;

pub use model::{
    CanaryTarget, CheckContext, Confidence, Evidence, GeofencePolicy, GeoInfo, NodeCandidate,
    NodeHistory, NodeReport, Stage, StageStatus, ValidationConfig, Verdict,
};
pub use pipeline::CorePipeline;
pub use probe::Probe;
pub use report::render_report;
pub use geo::GeoProvider;
pub use ip2asn::Ip2AsnTable;

#[cfg(feature = "python")]
pub mod python;
