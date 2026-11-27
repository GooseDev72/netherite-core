use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use flate2::read::GzDecoder;

use crate::model::GeoInfo;

#[derive(Clone, Debug)]
pub struct Ip2AsnRowV4 { pub start: u32, pub end: u32, pub asn: Option<u32>, pub country: Option<String>, pub as_org: Option<String> }
#[derive(Clone, Debug)]
pub struct Ip2AsnRowV6 { pub start: u128, pub end: u128, pub asn: Option<u32>, pub country: Option<String>, pub as_org: Option<String> }

/// Open IP2ASN table (iptoasn.com combined TSV format).
/// Format: range_start\trange_end\tAS_number\tcountry_code\tAS_description
#[derive(Clone, Debug, Default)]
pub struct Ip2AsnTable {
    v4: Vec<Ip2AsnRowV4>,
    v6: Vec<Ip2AsnRowV6>,
}

impl Ip2AsnTable {
    pub fn new() -> Self { Self::default() }

    pub fn from_tsv_reader<R: BufRead>(reader: R) -> std::io::Result<Self> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 5 { continue; }
            let asn = parts[2].parse::<u32>().ok().filter(|a| *a != 0);
            let country = {
                let c = parts[3].trim();
                if c.is_empty() || c.eq_ignore_ascii_case("none") { None } else { Some(c.to_uppercase()) }
            };
            let as_org = {
                let o = parts[4].trim();
                if o.is_empty() || o.eq_ignore_ascii_case("not routed") { None } else { Some(o.to_string()) }
            };
            if parts[0].contains(':') {
                if let (Some(start), Some(end)) = (crate::ip2asn::parse::parse_ipv6(parts[0]), crate::ip2asn::parse::parse_ipv6(parts[1])) {
                    v6.push(Ip2AsnRowV6 { start, end, asn, country, as_org });
                }
            } else if let (Some(start), Some(end)) = (crate::ip2asn::parse::parse_ipv4(parts[0]), crate::ip2asn::parse::parse_ipv4(parts[1])) {
                v4.push(Ip2AsnRowV4 { start, end, asn, country, as_org });
            }
        }
        v4.sort_by_key(|r| r.start);
        v6.sort_by_key(|r| r.start);
        Ok(Self { v4, v6 })
    }

    pub fn from_tsv_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::from_tsv_reader(BufReader::new(File::open(path.as_ref())?))
    }
    pub fn from_gz_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::from_tsv_reader(BufReader::new(GzDecoder::new(File::open(path.as_ref())?)))
    }
    pub fn from_gz_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        Self::from_tsv_reader(BufReader::new(GzDecoder::new(bytes)))
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Option<GeoInfo> {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(u32::from(v4)),
            IpAddr::V6(v6) => self.lookup_v6(u128::from(v6)),
        }
    }

    pub fn lookup_v4(&self, ip: u32) -> Option<GeoInfo> {
        let idx = match self.v4.binary_search_by_key(&ip, |r| r.start) { Ok(i) => i, Err(0) => return None, Err(i) => i - 1 };
        for r in &self.v4[idx.saturating_sub(2)..(idx+2).min(self.v4.len())] {
            if ip >= r.start && ip <= r.end {
                return Some(GeoInfo { country: r.country.clone(), region: None, city: None, asn: r.asn, as_org: r.as_org.clone(), network_type: crate::ip2asn::parse::infer_network_type(r.as_org.as_deref()) });
            }
        }
        None
    }

    pub fn lookup_v6(&self, ip: u128) -> Option<GeoInfo> {
        let idx = match self.v6.binary_search_by_key(&ip, |r| r.start) { Ok(i) => i, Err(0) => return None, Err(i) => i - 1 };
        for r in &self.v6[idx.saturating_sub(2)..(idx+2).min(self.v6.len())] {
            if ip >= r.start && ip <= r.end {
                return Some(GeoInfo { country: r.country.clone(), region: None, city: None, asn: r.asn, as_org: r.as_org.clone(), network_type: crate::ip2asn::parse::infer_network_type(r.as_org.as_deref()) });
            }
        }
        None
    }

    pub fn len(&self) -> usize { self.v4.len() + self.v6.len() }
    pub fn is_empty(&self) -> bool { self.v4.is_empty() && self.v6.is_empty() }

    pub const IPTOASN_COMBINED_URL: &'static str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";

    pub async fn download_iptoasn_combined() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let bytes = reqwest::get(Self::IPTOASN_COMBINED_URL).await?.error_for_status()?.bytes().await?;
        Ok(Self::from_gz_bytes(&bytes)?)
    }

    pub async fn download_to_cache(cache_path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = cache_path.as_ref();
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        let bytes = reqwest::get(Self::IPTOASN_COMBINED_URL).await?.error_for_status()?.bytes().await?;
        fs::write(path, &bytes)?;
        Ok(Self::from_gz_bytes(&bytes)?)
    }

    /// Load from cache if fresh, else download. `max_age` controls freshness.
    pub async fn load_or_download(cache_path: impl AsRef<Path>, max_age: Duration) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = cache_path.as_ref();
        if path.exists() {
            if let Ok(meta) = fs::metadata(path) {
                if let Ok(modified) = meta.modified() {
                    if SystemTime::now().duration_since(modified).unwrap_or(max_age) <= max_age {
                        return Ok(Self::from_gz_file(path)?);
                    }
                }
            }
        }
        Self::download_to_cache(path).await
    }
}

impl crate::geo::GeoProvider for Ip2AsnTable {
    fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> { self.lookup_ip(ip) }
}





#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_and_lookup_v4() {
        let tsv = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n";
        let table = Ip2AsnTable::from_tsv_reader(tsv.as_bytes()).unwrap();
        let g = table.lookup_ip("8.8.8.8".parse().unwrap()).unwrap();
        assert_eq!(g.country.as_deref(), Some("US"));
        assert_eq!(g.asn, Some(15169));
    }
}
