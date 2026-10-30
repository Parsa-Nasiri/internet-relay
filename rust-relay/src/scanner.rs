/// IP scanner for finding accessible Google Fonts IPs and other Google infrastructure.
///
/// Uses `curl --resolve` with `--connect-timeout` to check each IP.
/// This is proven to work in environments where domain fronting is blocked
/// but direct IP access with correct SNI works.
use anyhow::Result;
use std::process::Command;
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
        use std::net::Ipv4Addr;
        use std::str::FromStr;
        let base = Ipv4Addr::from_str(parts[0]).unwrap();
        let prefix_len: u32 = parts[1].parse().unwrap_or(32);
        let base_u32 = u32::from_be_bytes(base.octets());
        let mask = if prefix_len == 0 { 0 } else { 0xFFFFFFFFu32 << (32 - prefix_len) };
        let network = base_u32 & mask;
        let num_hosts = 1u32 << (32 - prefix_len);
        (1..num_hosts.saturating_sub(1))
            .map(|i| {
                Ipv4Addr::from((network + i).to_be_bytes()).to_string()
            })
            .collect()
    }

    pub async fn scan_batch(
        ips: &[String],
        concurrency: usize,
        scanner: &IpScanner,
    ) -> Result<Vec<ScanResult>> {
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let mut handles = Vec::new();

        for ip in ips {
            let semaphore = semaphore.clone();
            let scan = Scan {
                ip: ip.clone(),
                sni: scanner.sni.clone(),
                path: scanner.path.clone(),
                port: scanner.port,
                timeout: scanner.timeout,
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
}

impl Scan {
    async fn run(&self) -> ScanResult {
        let resolve_arg = format!("{}:{}:{}", self.sni, self.port, self.ip);
        let url = format!("https://{}/{}", self.sni, self.path);
        let connect_timeout = (self.timeout.as_secs().min(5)).to_string();
        let max_time = self.timeout.as_secs().to_string();
        let resolve = resolve_arg.clone();
        let url_s = url.clone();
        // On Windows curl doesn't understand /dev/null
        let null_path: &'static str = if cfg!(windows) { "nul" } else { "/dev/null" };
        let null_owned = null_path.to_string();

        let result = tokio::task::spawn_blocking(move || {
            Command::new("curl")
                .arg("--resolve")
                .arg(&resolve)
                .arg("--connect-timeout")
                .arg(&connect_timeout)
                .arg("--max-time")
                .arg(&max_time)
                .arg("--silent")
                .arg("--write-out")
                .arg("%{http_code}")
                .arg("--output")
                .arg(&null_owned)
                .arg(&url_s)
                .output()
        })
        .await;

        match result {
            Ok(Ok(output)) => {
                let http_code = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr);
                // curl exit code 0 or http_code starting with 2 = accessible
                // (Don't rely solely on exit code — curl may warn on body write to nul)
                let ok = http_code.starts_with('2');
                ScanResult {
                    ip: self.ip.clone(),
                    port: self.port,
                    accessible: ok,
                    http_code: if http_code.is_empty() { "000".to_string() } else { http_code },
                    error: if ok { None } else { Some(stderr.trim().to_string()) },
                }
            }
            Ok(Err(e)) => ScanResult {
                ip: self.ip.clone(),
                port: self.port,
                accessible: false,
                http_code: "000".to_string(),
                error: Some(e.to_string()),
            },
            Err(e) => ScanResult {
                ip: self.ip.clone(),
                port: self.port,
                accessible: false,
                http_code: "000".to_string(),
                error: Some(e.to_string()),
            },
        }
    }
}
