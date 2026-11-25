use crate::model::{Evidence, GeofencePolicy, GeoInfo, Stage};
use std::net::IpAddr;

/// Pluggable geo/ASN provider (IP2ASN DB, MaxMind, API, etc.)
pub trait GeoProvider: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> Option<GeoInfo>;
}

pub fn check_geofence(exit_geo: Option<&GeoInfo>, policy: &GeofencePolicy) -> Evidence {
    let Some(g) = exit_geo else {
        if policy.require_exit_geo {
            return Evidence::fail(Stage::GeofencePolicy, 25.0, "exit geo required but missing");
        }
        return Evidence::skip(Stage::GeofencePolicy, "no exit geo");
    };

    let country = g.country.as_deref().unwrap_or("UNKNOWN").to_uppercase();
    let asn = g.asn;
    let net_type = g.network_type.as_deref().unwrap_or("unknown").to_lowercase();

    if !policy.deny_countries.is_empty() && policy.deny_countries.iter().any(|c| c.eq_ignore_ascii_case(&country)) {
        return Evidence::fail(Stage::GeofencePolicy, 30.0, format!("country {} denied by geofence", country));
    }
    if !policy.allow_countries.is_empty() && !policy.allow_countries.iter().any(|c| c.eq_ignore_ascii_case(&country)) {
        return Evidence::fail(Stage::GeofencePolicy, 30.0, format!("country {} not in geofence allowlist", country));
    }
    if let Some(asn) = asn {
        if policy.deny_asn.contains(&asn) {
            return Evidence::fail(Stage::GeofencePolicy, 30.0, format!("ASN {} denied by geofence", asn));
        }
        if !policy.allow_asn.is_empty() && !policy.allow_asn.contains(&asn) {
            return Evidence::fail(Stage::GeofencePolicy, 30.0, format!("ASN {} not in geofence allowlist", asn));
        }
    }
    if !policy.deny_network_types.is_empty() && policy.deny_network_types.iter().any(|n| n.eq_ignore_ascii_case(&net_type)) {
        return Evidence::fail(Stage::GeofencePolicy, 20.0, format!("network type {} denied by geofence", net_type));
    }

    Evidence::pass(Stage::GeofencePolicy, 15.0, format!("geofence ok: country={} asn={:?} net={}", country, asn, net_type))
        .with_data("country", country)
        .with_data("network_type", net_type)
}

pub fn check_geo_consistency(claimed_country: Option<&str>, exit_geo: Option<&GeoInfo>, strict: bool) -> Evidence {
    let Some(claimed) = claimed_country.map(|c| c.trim().to_uppercase()).filter(|c| !c.is_empty()) else {
        return Evidence::skip(Stage::GeoConsistency, "no claimed country");
    };
    let Some(g) = exit_geo else {
        return Evidence::warn(Stage::GeoConsistency, 10.0, 0.5, format!("claimed {} but exit geo missing", claimed));
    };
    let actual = g.country.as_deref().unwrap_or("UNKNOWN").to_uppercase();
    if actual == "UNKNOWN" {
        return Evidence::warn(Stage::GeoConsistency, 10.0, 0.5, format!("claimed {} but exit country unknown", claimed));
    }
    if actual == claimed {
        return Evidence::pass(Stage::GeoConsistency, 10.0, format!("claimed country matches exit: {}", actual))
            .with_data("country", actual);
    }
    if strict {
        return Evidence::fail(Stage::GeoConsistency, 20.0, format!("claimed {} != exit {}", claimed, actual));
    }
    Evidence::warn(Stage::GeoConsistency, 10.0, 0.2, format!("geo mismatch: claimed {} != exit {}", claimed, actual))
        .with_data("claimed", claimed)
        .with_data("actual", actual)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::GeofencePolicy;
    #[test]
    fn geofence_deny_country() {
        let geo = GeoInfo { country: Some("RU".into()), region: None, city: None, asn: Some(123), as_org: None, network_type: None };
        let pol = GeofencePolicy { deny_countries: vec!["RU".into()], ..Default::default() };
        let ev = check_geofence(Some(&geo), &pol);
        assert!(matches!(ev.status, crate::model::StageStatus::Fail));
    }
}
