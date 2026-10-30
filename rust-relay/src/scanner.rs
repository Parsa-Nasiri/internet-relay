use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::Semaphore;
use std::sync::Arc;

pub struct IpScanner {
    pub sni: String,
    pub path: String,
    pub port: u16,
    pub timeout: Duration,
}

pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub accessible: bool,
    pub http_code: String,
    pub error: Option<String>,
}

impl IpScanner {
    pub fn new(sni: String, path: String, timeout_secs: u64) -> Self {
        Self {
            sni,
            path: path.trim_start_matches('/').to_string(),
            port: 443,
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn parse_range(&self, range_str: &str) -> Vec<String> {
        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() == 2 {
            let (base, start_end) = parts[0].rsplit_once('.').unwrap();
            let start: u32 = start_end.parse().unwrap();
            let end: u32 = parts[1].parse().unwrap();
            (start..=end).map(|i| format!("{}.{}", base, i)).collect()
        } else if range_str.contains('*') {
            let prefix = range_str.trim_end_matches('*').trim_end_matches('.');
            (1..=254).map(|i| format!("{}.{}", prefix, i)).collect()
        } else {
            vec![range_str.to_string()]
        }
    }

    pub fn parse_cidr(&self, cidr: &str) -> Vec<String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 { return vec![cidr.to_string()]; }
        let base = Ipv4Addr::from_str(parts[0]).unwrap();
        let prefix_len: u32 = parts[1].parse().unwrap_or(32);
        let base_u32 = u32::from_be_bytes(base.octets());
        let mask = if prefix_len == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - prefix_len) };
        let network = base_u32 & mask;
        let num_hosts = 1u32 << (32 - prefix_len);
        (1..num_hosts.saturating_sub(1))
            .map(|i| Ipv4Addr::from((network + i).to_be_bytes()).to_string())
            .collect()
    }

    pub async fn scan_batch(
        ips: &[String],
        concurrency: usize,
        scanner: &IpScanner,
    ) -> Result<Vec<ScanResult>> {
        let client_template = reqwest::Client::builder()
            .user_agent("blackout-relay/scanner")
            .timeout(scanner.timeout)
            .danger_accept_invalid_certs(true)
            .build()?;
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let mut handles = Vec::new();
        for ip in ips {
            let client = client_template.clone();
            let semaphore = semaphore.clone();
            let scan = Scan {
                ip: ip.clone(),
                sni: scanner.sni.clone(),
                path: scanner.path.clone(),
                port: scanner.port,
                timeout: scanner.timeout,
                client: Arc::new(client),
            };
            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await.unwrap();
                scan.run().await
            });
            handles.push(handle);
        }
        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap_or(ScanResult {
                ip: "unknown".to_string(), port: 0, accessible: false,
                http_code: "error".to_string(), error: Some("Task panicked".to_string()),
            }));
        }
        Ok(results)
    }
}

struct Scan {
    ip: String,
    sni: String,
    path: String,
    port: u16,
    timeout: Duration,
    client: Arc<reqwest::Client>,
}

impl Scan {
    async fn run(&self) -> ScanResult {
        let ip_addr: std::net::IpAddr = match self.ip.parse() {
            Ok(ip) => ip,
            Err(_) => return ScanResult {
                ip: self.ip.clone(), port: self.port, accessible: false,
                http_code: "000".to_string(), error: Some("Invalid IP".to_string()),
            },
        };
        let target_addr = SocketAddr::new(ip_addr, self.port);
        let client = reqwest::Client::builder()
            .user_agent("blackout-relay/scanner")
            .timeout(self.timeout)
            .danger_accept_invalid_certs(true)
            .addrs((self.sni.as_str(), self.port), target_addr)
            .build()
            .unwrap_or_else(|_| self.client.as_ref().clone());
        let url = format!("https://{}/{}", self.sni, self.path);
        match client.get(&url).send().await {
            Ok(resp) => {
                let code = resp.status().to_string();
                let ok = resp.status().is_success();
                ScanResult { ip: self.ip.clone(), port: self.port, accessible: ok, http_code: code, error: None }
            }
            Err(e) => ScanResult {
                ip: self.ip.clone(), port: self.port, accessible: false,
                http_code: "000".to_string(), error: Some(e.to_string()),
            },
        }
    }
}
