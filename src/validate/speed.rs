use crate::model::{Evidence, Stage};

pub fn check_speed_threshold(measured_mbps: Option<f64>, threshold_mbps: f64) -> Evidence {
    match measured_mbps {
        Some(mbps) if mbps >= threshold_mbps => Evidence::pass(Stage::SpeedThreshold, 20.0, format!("{:.2} Mbps >= {:.2}", mbps, threshold_mbps)).with_speed(mbps),
        Some(mbps) => Evidence::fail(Stage::SpeedThreshold, 20.0, format!("{:.2} Mbps < {:.2}", mbps, threshold_mbps)).with_speed(mbps),
        None => Evidence::warn(Stage::SpeedThreshold, 20.0, 0.0, "speed not measured"),
    }
}
