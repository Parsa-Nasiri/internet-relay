/// Google Apps Script relay transport.
///
/// Deploy a Google Apps Script web app that uses UrlFetchApp.fetch() to proxy
/// requests through Google's infrastructure. The script URL is accessible from
/// restricted networks (script.google.com → 302).
///
/// Apps Script relay limitations:
/// - No HTTPS response body return (text only) — Apps Script returns text only
/// - 20,000 URL Fetch calls/day (consumer) / 100,000 (Workspace)
/// - 6 min execution timeout per request
/// - HTTP-only: cannot serve as a SOCKS proxy
///
/// Apps Script code:
/// ```javascript
/// function doGet(e) {
///   var url = e.parameter.url;
///   var response = UrlFetchApp.fetch(url);
///   return ContentService.createTextOutput(response.getContentText());
/// }
/// ```
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Duration;

use crate::transports::{FetchRequest, FetchResult};

pub struct AppsScriptRelay {
    script_url: String,
    client: reqwest::Client,
}

impl AppsScriptRelay {
    pub fn new(script_url: &str) -> Self {
        Self {
            script_url: script_url.to_string(),
            client: reqwest::Client::builder()
                .user_agent("blackout-relay/rust")
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap(),
        }
    }
}

impl AppsScriptRelay {
    pub async fn fetch(&self, req: FetchRequest) -> Result<FetchResult> {
        let mut params = HashMap::new();
        params.insert("url", req.url.clone());

        let result = if req.method == "POST" {
            // Apps Script doGet doesn't handle POST well; use a POST endpoint
            // or fall back to GET with the URL as a parameter
            self.client
                .get(&self.script_url)
                .query(&params)
                .header("Accept", "*/*")
                .send()
                .await
                .context("Apps Script relay request")?
        } else {
            self.client
                .get(&self.script_url)
                .query(&params)
                .header("Accept", "*/*")
                .send()
                .await
                .context("Apps Script relay request")?
        };

        let status = result.status().to_string();
        let body = result.text().await.context("Reading Apps Script response")?;

        // Apps Script relay returns only text — no response headers from upstream
        Ok(FetchResult {
            status,
            body,
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        })
    }
}
