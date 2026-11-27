//! Entry point for encrypted/wrapped link decoding.
//! Implementation lives in `decode/`.

mod happ;
mod incy;

pub use happ::{decode_happ, decode_v2raytun, unwrap_wrapped};
pub use incy::decode_incy;

/// Try to decode/decrypt any supported wrapper/encrypted link.
/// Returns decoded plaintext/inner link(s) if recognized, otherwise None.
pub fn decode_any(input: &str) -> Option<String> {
    let t = input.trim();
    if t.is_empty() { return None; }
    if let Some(v) = decode_incy(t) { return Some(v); }
    if let Some(v) = decode_happ(t) { return Some(v); }
    if let Some(v) = decode_v2raytun(t) { return Some(v); }
    unwrap_wrapped(t)
}

/// Decode possibly encoded subscription content into plain text.
/// Handles happ://, v2raytun://, incy:// links found in text.
pub fn decode_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let t = line.trim();
        if let Some(decoded) = decode_any(t) {
            out.push_str(&decoded);
            if !decoded.ends_with('\n') { out.push('\n'); }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_any_none_on_plain() {
        assert!(decode_any("vless://uuid@host:443").is_none());
        assert!(decode_any("https://example.com/sub").is_none());
    }

    #[test]
    fn unwrap_happ_add() {
        let u = unwrap_wrapped("happ://add/https%3A%2F%2Fexample.com%2Fsub").unwrap();
        assert_eq!(u, "https://example.com/sub");
    }

    #[test]
    fn unwrap_v2raytun_import() {
        let u = unwrap_wrapped("v2raytun://import/https://example.com/sub").unwrap();
        assert_eq!(u, "https://example.com/sub");
    }

    #[test]
    fn decode_text_passthrough() {
        let t = "vless://a@b:1\n#comment\n";
        let out = decode_text(t);
        assert!(out.contains("vless://a@b:1"));
    }

    #[test]
    fn decode_any_handles_unicode_prefix() {
        assert!(decode_any("🇫🇮 Finland node").is_none());
        assert!(decode_any("hello 🌍 happ://notreal").is_none());
    }
}
