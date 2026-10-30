/// SNI spoofing transport.
///
/// SNI (Server Name Indication) allows the client to tell the server which
/// hostname it is connecting to during the TLS handshake. By connecting to a
/// specific IP while presenting the expected SNI, you can:
///
/// 1. Bypass firewalls that whitelist specific hostnames (e.g., fonts.googleapis.com)
/// 2. Connect to IPs known to belong to a service while presenting the expected SNI.
///
/// IMPORTANT: Domain fronting is DEAD. Google (and other CDNs) validate that the
/// SNI matches the Host header. The SNI must match the host you actually request.
///
/// VERIFIED: Google Fonts IPs (142.250.1.95, .99, .100, .101-.107) all return
/// HTTP 200 with SNI=fonts.googleapis.com using `curl --resolve`.
use anyhow::{Context, Result};
use std::process::Command;
use std::time::Duration;
use tokio::task::spawn_blocking;

use crate::transports::SniResult;

/// Fetch a URL via SNI spoofing — connects to `ip` while presenting `sni` (or
/// the URL host) as the TLS Server Name.
///
/// The connection is made with `curl --resolve <host>:<port>:<ip> <url>`,
/// which is proven to work and avoids reqwest's removed `addrs` method.
pub async fn sni_spoof_fetch(ip: &str, sni: &str, url: &str, timeout: u64) -> Result<SniResult> {
    let parsed = url::Url::parse(url).context("Parsing URL")?;
    let host = parsed.host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must have a host"))?;
    let port = parsed.port().unwrap_or(443);
    let resolve_arg = format!("{}:{}:{}", host, port, ip);

    let url_owned = url.to_string();
    let resolve_owned = resolve_arg.clone();
    let timeout_owned = timeout;

    let output = spawn_blocking(move || {
        Command::new("curl")
            .arg("--resolve")
            .arg(&resolve_owned)
            .arg("--max-time")
            .arg(timeout_owned.to_string())
            .arg("--silent")
            .arg("--show-error")
            .arg("--dump-header")
            .arg("-")
            .arg(&url_owned)
            .output()
    })
    .await??;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("curl failed: {}", stderr.trim());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    split_headers_and_body(&text, sni, &host)
}

/// Parse a full HTTP response (status line + headers + body) from curl output.
fn split_headers_and_body(text: &str, expected_sni: &str, host: &str) -> Result<SniResult> {
    if host != expected_sni {
        eprintln!(
            "Warning: URL host '{}' != SNI '{}'. Using URL host for SNI.",
            host, expected_sni
        );
    }

    let (header_str, body) = if let Some(idx) = text.find("\r\n\r\n") {
        (text[..idx].to_string(), text[idx + 4..].to_string())
    } else {
        // Fallback: try \n\n
        match text.find("\n\n") {
            Some(idx) => (text[..idx].to_string(), text[idx + 2..].to_string()),
            None => (String::new(), text.to_string()),
        }
    };

    let lines: Vec<&str> = header_str.lines().collect();
    let status = lines.first()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("000")
        .to_string();

    let headers: Vec<(String, String)> = lines
        .iter()
        .skip(1)
        .filter(|line| line.contains(':'))
        .filter_map(|line| {
            let mut parts = line.splitn(2, ':');
            let key = parts.next()?.trim().to_string();
            let val = parts.next()?.trim().to_string();
            if key.is_empty() { None } else { Some((key, val)) }
        })
        .collect();

    Ok(SniResult { status, headers, body })
}
