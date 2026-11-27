use crate::model::{Evidence, GeoInfo, Stage};

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
    use crate::model::{GeofencePolicy, GeoInfo};
    use crate::geo::check_geofence;
    #[test]
    fn geofence_deny_country() {
        let geo = GeoInfo { country: Some("RU".into()), region: None, city: None, asn: Some(123), as_org: None, network_type: None };
        let pol = GeofencePolicy { deny_countries: vec!["RU".into()], ..Default::default() };
        let ev = check_geofence(Some(&geo), &pol);
        assert!(matches!(ev.status, crate::model::StageStatus::Fail));
    }
}
