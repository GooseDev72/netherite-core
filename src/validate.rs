//! Validation stages - entry point. Implementations live in `validate/`.

mod canary;
mod integrity;
mod speed;
mod stability;

pub use canary::check_http_canaries;
pub use integrity::check_content_integrity;
pub use speed::check_speed_threshold;
pub use stability::check_stability;
