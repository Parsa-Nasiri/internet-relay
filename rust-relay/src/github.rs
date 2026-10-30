/// GitHub Actions relay transport.
///
/// Architecture: the GitHub Actions runner has full internet access. We file
/// a request as `requests/<request_id>.json` via the GitHub Contents API,
/// trigger the `relay.yml` workflow (it auto-triggers on push to `requests/`),
/// and poll `raw.githubusercontent.com` for `responses/<request_id>.{txt,meta,headers}`.
///
/// Endpoints needed from the restricted network:
///   - api.github.com            (200 — confirmed accessible)
///   - raw.githubusercontent.com (301/200 — confirmed accessible)
///   - github.com                (200 — confirmed accessible)
use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::transports::{FetchRequest, FetchResult};

const GITHUB_API: &str = "https://api.github.com";
const RAW_URL: &str = "https://raw.githubusercontent.com";

#[derive(Serialize, Deserialize, Debug)]
struct GitHubFile {
    #[allow(dead_code)]
    name: String,
    sha: String,
    #[allow(dead_code)]
    content: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiResponse {
    #[allow(dead_code)]
    content: Option<String>,
    #[allow(dead_code)]
    encoding: Option<String>,
    sha: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "type")]
    file_type: Option<String>,
    #[allow(dead_code)]
    size: Option<u64>,
}

/// The GitHub relay. No token needed for public repos. The runner uses its
/// built-in GITHUB_TOKEN to commit responses.
pub struct GitHubRelay {
    owner_repo: String,
    client: reqwest::Client,
}

impl GitHubRelay {
    pub fn new(owner_repo: &str) -> Self {
        Self {
            owner_repo: owner_repo.to_string(),
            client: reqwest::Client::builder()
                .user_agent("blackout-relay/rust")
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    /// Submit a request to the repo (creates `requests/<id>.json`).
    async fn submit_request(&self, req: &FetchRequest) -> Result<String> {
        let request_id = format!(
            "req_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let payload = serde_json::to_string(&req).context("Serializing request")?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);

        let path = format!("requests/{}.json", request_id);
        let url = format!("{}/repos/{}/contents/{}", GITHUB_API, self.owner_repo, path);

        let body = serde_json::json!({
            "message": format!("Relay request: {}", request_id),
            "content": encoded,
            "branch": "main",
        });

        let resp = self
            .client
            .put(&url)
            .header("Accept", "application/vnd.github+json")
            .json(&body)
            .send()
            .await
            .context("Submitting request to GitHub")?;

        let status_code = resp.status();
        if !status_code.is_success() {
            let txt = resp.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error ({}, {}): {}", status_code, status_code, txt);
        }

        Ok(request_id)
    }

    /// Only submit the request without waiting for a response.
    pub async fn submit_only(&self, req: FetchRequest) -> Result<()> {
        let id = self.submit_request(&req).await?;
        println!("Submitted request ID: {}", id);
        println!("Poll at: {}/{}/main/responses/{}.txt", RAW_URL, self.owner_repo, id);
        Ok(())
    }

    /// Submit a request and poll for the response.
    /// Returns after up to `max_wait` seconds polling every `poll_interval`.
    pub async fn fetch(&self, req: FetchRequest) -> Result<FetchResult> {
        let request_id = self.submit_request(&req).await?;
        eprintln!("Request submitted: {} — waiting for runner...", request_id);

        let max_wait = 150u64;
        let poll_interval = 5u64;
        let mut elapsed = 0u64;

        let client = &self.client;
        loop {
            tokio::time::sleep(Duration::from_secs(poll_interval)).await;
            elapsed += poll_interval;

            let resp_url = format!("{}/{}/main/responses/{}.txt", RAW_URL, self.owner_repo, request_id);
            let resp = client
                .get(&resp_url)
                .header("Accept", "*/*")
                .send()
                .await;

            if let Ok(r) = resp {
                if r.status().is_success() {
                    let body = r.text().await.context("Reading response body")?;

                    // Fetch metadata
                    let meta_url = format!("{}/{}/main/responses/{}.meta", RAW_URL, self.owner_repo, request_id);
                    let meta = match client.get(&meta_url).send().await {
                        Ok(resp) => resp.text().await.unwrap_or_default(),
                        Err(_) => String::new(),
                    };

                    let status = meta
                        .lines()
                        .find(|l| l.starts_with("HTTP_CODE="))
                        .and_then(|l| l.strip_prefix("HTTP_CODE="))
                        .unwrap_or("200")
                        .to_string();

                    // Fetch response headers
                    let hdr_url = format!("{}/{}/main/responses/{}.headers", RAW_URL, self.owner_repo, request_id);
                    let header_str = match client.get(&hdr_url).send().await {
                        Ok(resp) => resp.text().await.unwrap_or_default(),
                        Err(_) => String::new(),
                    };

                    let headers = parse_header_lines(&header_str);
                    return Ok(FetchResult { status, body, headers });
                }
            }

            if elapsed >= max_wait {
                anyhow::bail!(
                    "Timed out after {}s waiting for GitHub Actions response.\n\
                     Request ID: {}. Check https://github.com/{}/actions",
                    elapsed, request_id, self.owner_repo
                );
            }
        }
    }
}

fn parse_header_lines(s: &str) -> Vec<(String, String)> {
    s.lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ':');
            let key = parts.next()?.trim().to_string();
            let val = parts.next()?.trim().to_string();
            if key.is_empty() || val.is_empty() {
                None
            } else {
                Some((key, val))
            }
        })
        .collect()
}
