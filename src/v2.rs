use crate::model::NodeCandidate;

/// Convert a v2keylib Node into a core NodeCandidate.
pub fn node_to_candidate(node: &v2keylib::node::Node, source: Option<String>) -> NodeCandidate {
    let protocol = format!("{:?}", node.protocol).to_lowercase();
    let transport = Some(format!("{:?}", node.transport.kind)).filter(|s| !s.is_empty() && s != "none");
    let tls = Some(format!("{:?}", node.security)).filter(|s| s.to_lowercase() != "none");
    let uri = format!("{}://{}:{}", protocol, node.address, node.port);
    NodeCandidate {
        uri,
        protocol,
        host: node.address.clone(),
        port: node.port,
        transport,
        tls,
        sni: node.sni.clone(),
        label: node.label.clone(),
        source,
        claimed_country: node.extra.get("country").cloned(),
        meta: node.extra.clone(),
    }
}

/// Parse a URI/link into a core NodeCandidate using v2keylib.
pub fn parse_uri(uri: &str, source: Option<String>) -> Result<NodeCandidate, String> {
    let node = v2keylib::links::parse(uri).map_err(|e| e.to_string())?;
    let mut c = node_to_candidate(&node, source);
    c.uri = uri.to_string();
    Ok(c)
}
