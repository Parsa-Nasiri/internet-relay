/// V2Ray configuration generator.
///
/// Generates server and client V2Ray configs for when you have a server
/// (e.g., Cloud Run with WebSocket, or a VPS) to set up a full TCP/UDP tunnel.
///
/// Cloud Run + V2Ray architecture (recommended real-time tunnel):
/// 1. Deploy V2Ray server on Cloud Run with WebSocket + TLS
/// 2. Client connects via SOCKS proxy to V2Ray client
/// 3. V2Ray client tunnels traffic to Cloud Run WebSocket endpoint
/// 4. Cloud Run forwards to V2Ray server, which makes the outbound request
///
/// Cloud Run is reachable from this network (run.googleapis.com -> 403, needs auth)
use anyhow::{Context, Result};
use serde_json::json;
use std::path::Path;

pub struct V2RayConfig;

impl V2RayConfig {
    /// Generate server and client configs, return as serde_json Values.
    pub fn generate(listen: &str, server: &str, uuid: &str) -> (serde_json::Value, serde_json::Value) {
        let server_host = server.split(':').next().unwrap_or("localhost");
        let server_port = server.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);

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
                        "address": server_host,
                        "port": server_port,
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
                        "serverName": server_host,
                        "alpn": ["h2", "http/1.1"]
                    },
                    "wsSettings": {
                        "path": "/ws",
                        "headers": {
                            "Host": server_host
                        }
                    }
                }
            }]
        });

        (server_config, client_config)
    }

    /// Write server and client configs to `dir` as `server.json` and `config.json`.
    pub fn write_to_dir(listen: &str, server: &str, uuid: &str, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).context("Creating config directory")?;
        let (server_config, client_config) = Self::generate(listen, server, uuid);

        let server_path = dir.join("server.json");
        let client_path = dir.join("config.json");

        std::fs::write(&server_path, serde_json::to_string_pretty(&server_config)?)
            .context("Writing server config")?;
        std::fs::write(&client_path, serde_json::to_string_pretty(&client_config)?)
            .context("Writing client config")?;

        // Also write a README
        let readme = dir.join("README.md");
        std::fs::write(&readme, "# V2Ray Configurations\n\n## Server (deploy on Cloud Run or VPS)\n- File: `server.json`\n- Port 8080 (Cloud Run expects this)\n- VLESS + WebSocket + XTLS\n\n## Client (run locally)\n- File: `config.json`\n- SOCKS5 proxy on the listen port\n\n## Usage\n```bash\nv2ray -config=config.json\n```\nSet system/browser proxy to the listen address.\n").context("Writing README")?;

        Ok(())
    }
}
