pub fn parse_ipv4(s: &str) -> Option<u32> {
    let mut p = s.trim().split('.');
    let a = p.next()?.parse::<u32>().ok()?;
    let b = p.next()?.parse::<u32>().ok()?;
    let c = p.next()?.parse::<u32>().ok()?;
    let d = p.next()?.parse::<u32>().ok()?;
    if p.next().is_some() || a>255||b>255||c>255||d>255 { return None; }
    Some((a<<24)|(b<<16)|(c<<8)|d)
}

pub fn parse_ipv6(s: &str) -> Option<u128> {
    let s = s.trim();
    let (left, right) = if let Some((l,r)) = s.split_once("::") { (l,r) } else { (s, "") };
    let parse_side = |side: &str| -> Option<Vec<u16>> {
        if side.is_empty() { return Some(vec![]); }
        side.split(':').map(|h| u16::from_str_radix(h, 16).ok()).collect()
    };
    let mut l = parse_side(left)?;
    let r = parse_side(right)?;
    if s.contains("::") {
        let fill = 8usize.checked_sub(l.len()+r.len())?;
        l.extend(std::iter::repeat(0u16).take(fill));
        l.extend(r);
    } else if l.len()!=8 { return None; }
    if l.len()!=8 { return None; }
    let mut v: u128 = 0;
    for part in l { v = (v<<16) | part as u128; }
    Some(v)
}

pub fn infer_network_type(as_org: Option<&str>) -> Option<String> {
    let o = as_org?.to_lowercase();
    let hosting = ["hosting","cloud","server","datacenter","data center","digitalocean","ovh","hetzner","amazon","google","microsoft","azure","akamai","cloudflare","vultr","linode","leaseweb"];
    let mobile = ["mobile","cellular","telecom","wireless","lte","5g"];
    let residential = ["broadband","isp","fibre","fiber","cable","adsl","residential"];
    if hosting.iter().any(|k| o.contains(k)) { return Some("hosting".to_string()); }
    if mobile.iter().any(|k| o.contains(k)) { return Some("mobile".to_string()); }
    if residential.iter().any(|k| o.contains(k)) { return Some("residential".to_string()); }
    Some("unknown".to_string())
}
