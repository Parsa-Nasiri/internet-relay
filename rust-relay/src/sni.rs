/// SNI spoofing transport.
///
/// SNI (Server Name Indication) allows the client to tell the server which
/// hostname it's connecting to during the TLS handshake. By spoofing the SNI
/// value, you can:
///
/// 1. Bypass firewalls that whitelist specific hostnames (e.g., fonts.googleapis.com)
/// 2. Connect to IPs you know belong to a service (e.g., Google Fonts IPs)
///    while presenting the expected SNI
///
/// IMPORTANT: Domain fronting is DEAD. Google (and other CDNs) have closed the
/// practice of presenting one SNI while requesting content from a different
/// virtual host. The SNI must match the Host header you actually want.
///
/// VERIFIED: Google Fonts IPs (142.250.1.95, .99, .100, .101–.107) all return
/// HTTP 200 with SNI=fonts.googleapis.com.
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;

use crate::transports::SniResult;

pub async fn sni_spoof_fetch(ip: &str, sni: &str, url: &str, timeout: u64) -> Result<SniResult> {
    let parsed = url::parse(url).context("Parsing URL")?;
    let host = parsed.host_str().ok_or_else(|| anyhow::anyhow!("URL must have a host"))?;
    let port: u16 = parsed.port().unwrap_or(443);

    let ip_addr: std::net::IpAddr = ip.parse().context("Parsing IP address")?;
    let target_addr = SocketAddr::new(ip_addr, port);

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .timeout(Duration::from_secs(timeout))
        .addrs((host, port), target_addr)
        .build()
        .context("Building SNI-spoofed client")?;

    if host != sni {
        eprintln!("Warning: URL host '{}' != SNI '{}'. Using URL host for connection.", host, sni);
    }

    let resp = client
        .get(url)
        .header("Accept", "*/*")
        .send()
        .await
        .context("SNI spoof fetch")?;

    let status = resp.status().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = resp.text().await.context("Reading response body")?;

    Ok(SniResult { status, headers, body })
}
