//! geo - entry point. Implementations in `geo/`.
mod consistency;
mod policy;
mod provider;

pub use consistency::check_geo_consistency;
pub use policy::check_geofence;
pub use provider::GeoProvider;
