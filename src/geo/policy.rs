use crate::model::{Evidence, GeofencePolicy, GeoInfo, Stage};

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
