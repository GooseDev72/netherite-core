use crate::model::CanaryTarget;

pub fn filter_canaries<'a>(canaries: &'a [CanaryTarget], profile: Option<&str>) -> Vec<&'a CanaryTarget> {
    match profile {
        None | Some("") | Some("all") => canaries.iter().collect(),
        Some(p) => {
            let p = p.to_lowercase();
            let filtered: Vec<_> = canaries.iter().filter(|c| c.profile.as_deref().map(|x| x.to_lowercase()) == Some(p.clone()) || c.profile.as_deref() == Some("general".into())).collect();
            if filtered.is_empty() { canaries.iter().collect() } else { filtered }
        }
    }
}
