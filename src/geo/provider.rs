use crate::model::GeoInfo;
use std::net::IpAddr;

/// Pluggable geo/ASN provider (IP2ASN DB, MaxMind, API, etc.)
pub trait GeoProvider: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> Option<GeoInfo>;
}
