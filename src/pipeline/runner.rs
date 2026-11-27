use reqwest::Client;

use crate::consensus::check_consensus;
use crate::diag;
use crate::dns::{check_dns_consistency, check_dns_resolve};
use crate::geo::{check_geo_consistency, check_geofence, GeoProvider};
use std::sync::Arc;
use crate::history::check_history;
use crate::model::{CheckContext, NodeCandidate, NodeReport, ValidationConfig};
use crate::probe::Probe;
use crate::reputation::{check_asn_reputation, check_exit_reputation};
use crate::scoring::classify;
use crate::transport::{check_tcp, check_transport_sanity};
use crate::validate::{check_http_canaries, check_speed_threshold, check_stability};

pub struct CorePipeline {
    cfg: ValidationConfig,
    client: Client,
    geo_provider: Option<Arc<dyn GeoProvider>>,
}

impl CorePipeline {
    pub fn new(cfg: ValidationConfig) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(cfg.http_timeout)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        Ok(Self { cfg, client, geo_provider: None })
    }

    pub fn with_geo_provider(mut self, provider: Arc<dyn GeoProvider>) -> Self {
        self.geo_provider = Some(provider);
        self
    }

    pub fn config(&self) -> &ValidationConfig { &self.cfg }

    pub async fn check_candidate(
        &self,
        candidate: NodeCandidate,
        measured_mbps: Option<f64>,
        latency_samples_ms: &[u128],
        extra_evidence: Vec<crate::model::Evidence>,
    ) -> NodeReport {
        let ctx = CheckContext {
            measured_mbps,
            latency_samples_ms: latency_samples_ms.to_vec(),
            extra_evidence,
            ..Default::default()
        };
        self.check_with_context(candidate, ctx).await
    }

    pub async fn check_with_context(&self, mut candidate: NodeCandidate, mut ctx: CheckContext) -> NodeReport {
        let mut evidence = Vec::new();

        // Resolve exit geo from provider if needed
        if ctx.exit_geo.is_none() {
            if let (Some(ip_s), Some(provider)) = (ctx.exit_ip.as_deref(), self.geo_provider.as_ref()) {
                if let Ok(ip) = ip_s.parse() {
                    ctx.exit_geo = provider.lookup(ip);
                }
            }
        }

        // Transport sanity
        let sanity = check_transport_sanity(&candidate.protocol, candidate.transport.as_deref(), candidate.tls.as_deref());
        diag::debug_ev(self.cfg.debug, &candidate, &sanity);
        evidence.push(sanity);

        // DNS
        if self.cfg.require_dns {
            let dns = check_dns_resolve(&candidate.host, candidate.port);
            diag::debug_ev(self.cfg.debug, &candidate, &dns);
            evidence.push(dns);
            let dns_c = check_dns_consistency(&candidate.host, candidate.port);
            diag::debug_ev(self.cfg.debug, &candidate, &dns_c);
            evidence.push(dns_c);
        }

        // TCP
        if self.cfg.require_tcp {
            let tcp = check_tcp(&candidate.host, candidate.port, self.cfg.connect_timeout.as_millis() as u64).await;
            diag::debug_ev(self.cfg.debug, &candidate, &tcp);
            evidence.push(tcp);
        }

        // HTTP canaries
        if self.cfg.require_canary {
            let canary = check_http_canaries(&self.client, &self.cfg).await;
            diag::debug_ev(self.cfg.debug, &candidate, &canary);
            evidence.push(canary);
        }

        // Speed
        let speed_ev = check_speed_threshold(ctx.measured_mbps, self.cfg.speed_threshold_mbps);
        diag::debug_ev(self.cfg.debug, &candidate, &speed_ev);
        evidence.push(speed_ev);

        // Stability
        let stability = check_stability(&ctx.latency_samples_ms, self.cfg.max_latency_ms);
        diag::debug_ev(self.cfg.debug, &candidate, &stability);
        evidence.push(stability);

        // Geo / geofence / reputation
        let geo_ref = ctx.exit_geo.as_ref();
        let geo_consistency = check_geo_consistency(candidate.claimed_country.as_deref(), geo_ref, self.cfg.geofence.strict_claimed_country_match);
        diag::debug_ev(self.cfg.debug, &candidate, &geo_consistency);
        evidence.push(geo_consistency);

        let geofence = check_geofence(geo_ref, &self.cfg.geofence);
        diag::debug_ev(self.cfg.debug, &candidate, &geofence);
        evidence.push(geofence);

        let asn_rep = check_asn_reputation(geo_ref, &self.cfg.geofence.deny_asn);
        diag::debug_ev(self.cfg.debug, &candidate, &asn_rep);
        evidence.push(asn_rep);

        let exit_rep = check_exit_reputation(geo_ref);
        diag::debug_ev(self.cfg.debug, &candidate, &exit_rep);
        evidence.push(exit_rep);

        // History
        let hist = check_history(ctx.history.as_ref());
        diag::debug_ev(self.cfg.debug, &candidate, &hist);
        evidence.push(hist);

        // Consensus
        if !ctx.consensus_verdicts.is_empty() {
            let refs: Vec<(&str, crate::model::Verdict)> = ctx.consensus_verdicts.iter().map(|(n,v)| (n.as_str(), v.clone())).collect();
            let cons = check_consensus(&refs);
            diag::debug_ev(self.cfg.debug, &candidate, &cons);
            evidence.push(cons);
        }

        // External evidence
        for ev in ctx.extra_evidence {
            diag::debug_ev(self.cfg.debug, &candidate, &ev);
            evidence.push(ev);
        }

        let (verdict, confidence) = classify(&evidence, &self.cfg);
        if self.cfg.debug {
            eprintln!("[core] verdict={} conf={:.2} {}://{}:{}", verdict_name(&verdict), confidence.score, candidate.protocol, candidate.host, candidate.port);
        }

        // fill geo back into candidate metadata for convenience
        if candidate.claimed_country.is_none() {
            if let Some(g) = ctx.exit_geo.as_ref().and_then(|g| g.country.clone()) {
                candidate.claimed_country = Some(g.clone());
            }
        }

        let country = ctx.exit_geo.as_ref().and_then(|g| g.country.clone());
        NodeReport {
            candidate,
            verdict,
            confidence,
            evidence,
            measured_mbps: ctx.measured_mbps,
            exit_ip: ctx.exit_ip.clone(),
            exit_geo: ctx.exit_geo,
            country,
        }
    }

    pub async fn check_with_probe<P: Probe>(&self, candidate: NodeCandidate, probe: &P) -> NodeReport {
        let extra = probe.probe(&candidate, &self.cfg).await;
        self.check_candidate(candidate, None, &[], extra).await
    }
}

fn verdict_name(v: &crate::model::Verdict) -> &'static str {
    match v {
        crate::model::Verdict::Working => "WORKING",
        crate::model::Verdict::Degraded { .. } => "DEGRADED",
        crate::model::Verdict::Dead { .. } => "DEAD",
        crate::model::Verdict::Rejected { .. } => "REJECTED",
    }
}
