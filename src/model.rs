use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeCandidate {
    pub uri: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub tls: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub claimed_country: Option<String>,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    DnsResolve,
    DnsConsistency,
    TcpConnect,
    TlsHandshake,
    HttpCanary,
    ContentIntegrity,
    SpeedThreshold,
    Stability,
    TransportSanity,
    GeoConsistency,
    GeofencePolicy,
    AsnReputation,
    ExitReputation,
    HistoryStability,
    Consensus,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus { Pass, Warn, Fail, Skip }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub stage: Stage,
    pub status: StageStatus,
    pub weight: f32,
    pub score: f32, // 0.0..=1.0
    pub detail: String,
    #[serde(default)]
    pub latency_ms: Option<u128>,
    #[serde(default)]
    pub speed_mbps: Option<f64>,
    #[serde(default)]
    pub data: BTreeMap<String, String>,
}

impl Evidence {
    pub fn pass(stage: Stage, weight: f32, detail: impl Into<String>) -> Self {
        Self { stage, status: StageStatus::Pass, weight, score: 1.0, detail: detail.into(), latency_ms: None, speed_mbps: None, data: BTreeMap::new() }
    }
    pub fn warn(stage: Stage, weight: f32, score: f32, detail: impl Into<String>) -> Self {
        Self { stage, status: StageStatus::Warn, weight, score: score.clamp(0.0, 1.0), detail: detail.into(), latency_ms: None, speed_mbps: None, data: BTreeMap::new() }
    }
    pub fn fail(stage: Stage, weight: f32, detail: impl Into<String>) -> Self {
        Self { stage, status: StageStatus::Fail, weight, score: 0.0, detail: detail.into(), latency_ms: None, speed_mbps: None, data: BTreeMap::new() }
    }
    pub fn skip(stage: Stage, detail: impl Into<String>) -> Self {
        Self { stage, status: StageStatus::Skip, weight: 0.0, score: 0.0, detail: detail.into(), latency_ms: None, speed_mbps: None, data: BTreeMap::new() }
    }
    pub fn with_latency(mut self, ms: u128) -> Self { self.latency_ms = Some(ms); self }
    pub fn with_speed(mut self, mbps: f64) -> Self { self.speed_mbps = Some(mbps); self }
    pub fn with_data(mut self, k: impl Into<String>, v: impl Into<String>) -> Self { self.data.insert(k.into(), v.into()); self }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Working,
    Degraded { reasons: Vec<String> },
    Dead { reasons: Vec<String> },
    Rejected { reasons: Vec<String> },
}

impl Verdict {
    pub fn is_working(&self) -> bool { matches!(self, Verdict::Working) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Confidence { pub score: f32, pub label: String }
impl Confidence {
    pub fn from_score(score: f32) -> Self {
        let score = score.clamp(0.0, 1.0);
        let label = if score >= 0.80 { "high" } else if score >= 0.50 { "medium" } else { "low" }.to_string();
        Self { score, label }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanaryTarget {
    pub url: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub expect_any_status: bool,
    #[serde(default)]
    pub expect_body_contains: Option<String>,
    #[serde(default)]
    pub profile: Option<String>, // e.g. general/youtube/telegram/github
}
fn default_true() -> bool { true }

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GeoInfo {
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub as_org: Option<String>,
    #[serde(default)]
    pub network_type: Option<String>, // datacenter/residential/mobile/hosting/unknown
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct GeofencePolicy {
    #[serde(default)]
    pub allow_countries: Vec<String>,
    #[serde(default)]
    pub deny_countries: Vec<String>,
    #[serde(default)]
    pub allow_asn: Vec<u32>,
    #[serde(default)]
    pub deny_asn: Vec<u32>,
    #[serde(default)]
    pub deny_network_types: Vec<String>,
    #[serde(default)]
    pub require_exit_geo: bool,
    #[serde(default)]
    pub strict_claimed_country_match: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub connect_timeout: Duration,
    pub http_timeout: Duration,
    pub speed_timeout: Duration,
    pub speed_threshold_mbps: f64,
    pub speed_test_bytes: usize,
    pub min_canary_pass: usize,
    pub min_canary_total: usize,
    pub require_dns: bool,
    pub require_tcp: bool,
    pub require_canary: bool,
    pub require_speed: bool,
    pub max_latency_ms: u128,
    pub stability_samples: usize,
    pub debug: bool,
    #[serde(default)]
    pub canaries: Vec<CanaryTarget>,
    #[serde(default)]
    pub geofence: GeofencePolicy,
    #[serde(default)]
    pub min_working_confidence: f32,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            http_timeout: Duration::from_secs(8),
            speed_timeout: Duration::from_secs(15),
            speed_threshold_mbps: 5.0,
            speed_test_bytes: 1_000_000,
            min_canary_pass: 2,
            min_canary_total: 3,
            require_dns: true,
            require_tcp: true,
            require_canary: true,
            require_speed: false,
            max_latency_ms: 4000,
            stability_samples: 2,
            debug: false,
            canaries: default_canaries(),
            geofence: GeofencePolicy::default(),
            min_working_confidence: 0.75,
        }
    }
}

pub fn default_canaries() -> Vec<CanaryTarget> {
    vec![
        CanaryTarget { url: "https://www.google.com/generate_204".into(), required: true, expect_any_status: false, expect_body_contains: None, profile: Some("general".into()) },
        CanaryTarget { url: "https://github.com".into(), required: true, expect_any_status: true, expect_body_contains: None, profile: Some("github".into()) },
        CanaryTarget { url: "https://t.me".into(), required: false, expect_any_status: true, expect_body_contains: None, profile: Some("telegram".into()) },
        CanaryTarget { url: "https://www.youtube.com".into(), required: false, expect_any_status: true, expect_body_contains: None, profile: Some("youtube".into()) },
        CanaryTarget { url: "https://youtu.be".into(), required: false, expect_any_status: true, expect_body_contains: None, profile: Some("youtube".into()) },
        CanaryTarget { url: "https://www.cloudflare.com/cdn-cgi/trace".into(), required: false, expect_any_status: true, expect_body_contains: None, profile: Some("general".into()) },
        CanaryTarget { url: "https://1.1.1.1/cdn-cgi/trace".into(), required: false, expect_any_status: true, expect_body_contains: None, profile: Some("general".into()) },
    ]
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeHistory {
    pub consecutive_working: u32,
    pub consecutive_dead: u32,
    pub last_verdict: Option<String>,
    pub avg_latency_ms: Option<f64>,
    pub avg_speed_mbps: Option<f64>,
    pub last_seen_epoch_ms: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct CheckContext {
    pub measured_mbps: Option<f64>,
    pub latency_samples_ms: Vec<u128>,
    pub extra_evidence: Vec<Evidence>,
    pub exit_ip: Option<String>,
    pub exit_geo: Option<GeoInfo>,
    pub history: Option<NodeHistory>,
    pub consensus_verdicts: Vec<(String, Verdict)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeReport {
    pub candidate: NodeCandidate,
    pub verdict: Verdict,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub measured_mbps: Option<f64>,
    #[serde(default)]
    pub exit_ip: Option<String>,
    #[serde(default)]
    pub exit_geo: Option<GeoInfo>,
    #[serde(default)]
    pub country: Option<String>,
}

impl NodeReport {
    pub fn is_working(&self) -> bool { self.verdict.is_working() }
}
