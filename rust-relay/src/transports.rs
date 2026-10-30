/// Transport trait — all relay methods implement this.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A fetch request to be performed by a transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
}

impl FetchRequest {
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            method: method.to_uppercase(),
            url: url.to_string(),
            headers: HashMap::new(),
            body: String::new(),
        }
    }

    pub fn body(mut self, body: String) -> Self {
        self.body = body;
        self
    }

    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn headers(mut self, h: HashMap<String, String>) -> Self {
        self.headers = h;
        self
    }
}

/// The result of a fetch.
#[derive(Debug, Clone)]
pub struct FetchResult {
    pub status: String,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

/// Trait for all transport methods.
pub trait Transport {
    /// Submit a request. Returns the result when complete.
    fn fetch(&self, req: FetchRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<FetchResult>> + Send>>;
}

/// SNI spoofed connection result (used by sni::SNIConnection).
pub struct SniResult {
    pub status: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}
