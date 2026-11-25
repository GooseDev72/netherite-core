#![allow(unsafe_op_in_unsafe_fn)]
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::net::IpAddr;

use crate::ip2asn::Ip2AsnTable;
use crate::model::{CheckContext, GeoInfo, NodeCandidate, ValidationConfig, Verdict};
use crate::pipeline::CorePipeline;
use crate::report::render_report;

#[pyclass(name = "Ip2AsnTable")]
pub struct PyIp2AsnTable {
    inner: Ip2AsnTable,
}

#[pymethods]
impl PyIp2AsnTable {
    #[staticmethod]
    pub fn load_tsv(path: &str) -> PyResult<Self> {
        let inner = Ip2AsnTable::from_tsv_file(path).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    #[staticmethod]
    pub fn load_gz(path: &str) -> PyResult<Self> {
        let inner = Ip2AsnTable::from_gz_file(path).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    #[staticmethod]
    pub fn download() -> PyResult<Self> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let inner = rt.block_on(Ip2AsnTable::download_iptoasn_combined())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    #[staticmethod]
    #[pyo3(signature = (cache_path, max_age_hours=24))]
    pub fn load_or_download(cache_path: &str, max_age_hours: u64) -> PyResult<Self> {
        let rt = tokio::runtime::Runtime::new().map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let inner = rt.block_on(Ip2AsnTable::load_or_download(cache_path, std::time::Duration::from_secs(max_age_hours * 3600)))
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    pub fn lookup(&self, ip: &str) -> PyResult<Option<PyObject>> {
        let ip: IpAddr = ip.parse().map_err(|e: std::net::AddrParseError| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let Some(info) = self.inner.lookup_ip(ip) else { return Ok(None); };
        Python::with_gil(|py| {
            let d = PyDict::new_bound(py);
            d.set_item("country", info.country)?;
            d.set_item("region", info.region)?;
            d.set_item("city", info.city)?;
            d.set_item("asn", info.asn)?;
            d.set_item("as_org", info.as_org)?;
            d.set_item("network_type", info.network_type)?;
            Ok(Some(d.into_any().unbind()))
        })
    }

    pub fn __len__(&self) -> usize { self.inner.len() }
}

#[pyfunction]
#[pyo3(signature = (uri, protocol, host, port, transport=None, tls=None, sni=None, claimed_country=None, measured_mbps=None, latency_samples_ms=None, exit_ip=None, exit_country=None, exit_asn=None, exit_org=None, geofence_allow=None, geofence_deny=None, strict_geo=false, history_working=0, history_dead=0, debug=false))]
pub fn check_candidate(
    uri: String, protocol: String, host: String, port: u16,
    transport: Option<String>, tls: Option<String>, sni: Option<String>, claimed_country: Option<String>,
    measured_mbps: Option<f64>, latency_samples_ms: Option<Vec<u128>>,
    exit_ip: Option<String>, exit_country: Option<String>, exit_asn: Option<u32>, exit_org: Option<String>,
    geofence_allow: Option<Vec<String>>, geofence_deny: Option<Vec<String>>, strict_geo: bool,
    history_working: u32, history_dead: u32,
    debug: bool,
) -> PyResult<PyObject> {
    let candidate = NodeCandidate {
        uri, protocol, host, port, transport, tls, sni, label: None, source: None, claimed_country, meta: Default::default(),
    };
    let mut cfg = ValidationConfig::default();
    cfg.debug = debug;
    cfg.require_speed = measured_mbps.is_some();
    if let Some(a) = geofence_allow { cfg.geofence.allow_countries = a; }
    if let Some(d) = geofence_deny { cfg.geofence.deny_countries = d; }
    cfg.geofence.strict_claimed_country_match = strict_geo;

    let exit_geo = if exit_country.is_some() || exit_asn.is_some() || exit_org.is_some() {
        Some(GeoInfo { country: exit_country, region: None, city: None, asn: exit_asn, as_org: exit_org, network_type: None })
    } else { None };
    let history = if history_working > 0 || history_dead > 0 {
        Some(crate::model::NodeHistory { consecutive_working: history_working, consecutive_dead: history_dead, ..Default::default() })
    } else { None };

    let ctx = CheckContext {
        measured_mbps,
        latency_samples_ms: latency_samples_ms.unwrap_or_default(),
        extra_evidence: vec![],
        exit_ip,
        exit_geo,
        history,
        consensus_verdicts: vec![],
    };

    let rt = tokio::runtime::Runtime::new().map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let report = rt.block_on(async move {
        let pipeline = CorePipeline::new(cfg).map_err(|e| e.to_string())?;
        Ok::<_, String>(pipeline.check_with_context(candidate, ctx).await)
    }).map_err(pyo3::exceptions::PyRuntimeError::new_err)?;

    Python::with_gil(|py| {
        let d = PyDict::new_bound(py);
        let verdict = match &report.verdict {
            Verdict::Working => "WORKING",
            Verdict::Degraded { .. } => "DEGRADED",
            Verdict::Dead { .. } => "DEAD",
            Verdict::Rejected { .. } => "REJECTED",
        };
        let conf_label = report.confidence.label.clone();
        let country = report.country.clone();
        let rendered = render_report(&report);
        d.set_item("verdict", verdict)?;
        d.set_item("confidence", report.confidence.score)?;
        d.set_item("confidence_label", conf_label)?;
        d.set_item("measured_mbps", report.measured_mbps)?;
        d.set_item("exit_ip", report.exit_ip.clone())?;
        d.set_item("country", country)?;
        d.set_item("report", rendered)?;
        Ok(d.into_any().unbind())
    })
}

#[pymodule]
pub fn netherite_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIp2AsnTable>()?;
    m.add_function(wrap_pyfunction!(check_candidate, m)?)?;
    Ok(())
}
