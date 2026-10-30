/// V2Ray configuration generator.
///
/// Generates server and client V2Ray configs for when you have a server
/// (e.g., Cloud Run with WebSocket, or a VPS) to set up a full TCP/UDP tunnel.
///
/// Cloud Run + V2Ray architecture (the recommended real-time tunnel):
/// 1. Deploy V2Ray server on Cloud Run with WebSocket + TLS
/// 2. Client connects via SOCKS proxy to V2Ray client
/// 3. V2Ray client tunnels traffic to Cloud Run WebSocket endpoint
/// 4. Cloud Run forwards to V2Ray server, which makes the outbound request
///
/// Cloud Run is reachable from this network (run.googleapis.com → 403, needs auth)
use anyhow::{Context, Result};
use serde_json::json;
use std::path::Path;

pub struct V2RayConfig;

impl V2RayConfig {
    /// Generate server and client configs, return as serde_json Values.
    pub fn generate(listen: &str, server: &str, uuid: &str) -> (serde_json::Value, serde_json::Value) {
        let server_config = json!({
            "inbounds": [{
                "port": 8080,
                "listen": "0.0.0.0",
                "protocol": "vless",
                "settings": {
                    "users": [{
                        "id": uuid,
                        "level": 0,
                        "flow": "xtls-rprx-vision"
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "xtls",
                    "xtlsSettings": {
                        "alpn": ["http/1.1"]
                    },
                    "wsSettings": {
                        "path": "/ws"
                    }
                }
            }],
            "outbounds": [{
                "protocol": "freedom",
                "settings": {}
            }]
        });

        let client_config = json!({
            "inbounds": [{
                "port": listen,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": true,
                    "ip": "127.0.0.1"
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"]
                }
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server.split(':').next().unwrap_or("localhost"),
                        "port": server.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(443),
                        "users": [{
                            "id": uuid,
                            "flow": "xtls-rprx-vision",
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": server.split(':').next().unwrap_or("localhost"),
                        "alpn": ["h2", "http/1.1"]
                    },
                    "wsSettings": {
                        "path": "/ws",
                        "headers": {
                            "Host": server.split(':').next().unwrap_or("localhost")
                        }
                    }
                }
            }]
        });

        (server_config, client_config)
    }

    pub fn write_to_dir(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).context("Creating config directory")?;

        // Generate with placeholder values
        let (server, client) = Self::generate("127.0.0.1:1080", "your-server.com:443", "b5e89d3e-6d62-4f3a-9a2b-7e8f9c0d1e2f");

        let server_path = dir.join("server.json");
        let client_path = dir.join("config.json");

        std::fs::write(&server_path, serde_json::to_string_pretty(&server)?)
            .context("Writing server config")?;
        std::fs::write(&client_path, serde_json::to_string_pretty(&client)?)
            .context("Writing client config")?;

        // Also write a README
        let readme = dir.join("README.md");
        std::fs::write(&readme, r#"# V2Ray Configurations

## Server (deploy on Cloud Run or VPS)
- File: `server.json`
- Listens on port 8080 (Cloud Run expects this)
- Uses VLESS + WebSocket + XTLS

## Client (run locally)
- File: `config.json`
- Listens on `127.0.0.1:1080`
- SOCKS5 proxy for browser/system use

## Usage

### Start V2Ray client (after replacing server UUID and address)
```bash
v2ray -config=config.json
```

### Use as SOCKS proxy
Set your browser/system proxy to `127.0.0.1:1080`.

### Cloud Run deployment (needs `gcloud` and billing)
```bash
gcloud run deploy v2ray --source=. --region=us-central1
```
"#).context("Writing README")?;

        Ok(())
    }
}
