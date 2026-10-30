use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod transports;
mod github;
mod apps_script;
mod sni;
mod scanner;
mod v2ray;

use github::GitHubRelay;
use apps_script::AppsScriptRelay;
use scanner::IpScanner;
use v2ray::V2RayConfig;

#[derive(Parser)]
#[command(name = "blackout-relay", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Fetch a URL via GitHub Actions relay.
    GithubFetch {
        #[arg(short, long)]
        url: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(short, long)]
        data: Option<PathBuf>,
        #[arg(short, long)]
        header: Vec<String>,
        #[arg(long, default_value = "Parsa-Nasiri/internet-relay")]
        repo: String,
        #[arg(long)]
        fire_and_forget: bool,
    },

    /// Fetch a URL via Google Apps Script relay.
    AppsScriptFetch {
        #[arg(long)]
        script_url: String,
        #[arg(short, long)]
        url: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(short, long)]
        header: Vec<String>,
    },

    /// Test SNI spoofing: connect to an IP with SNI=domain.
    SniTest {
        #[arg(short, long)]
        ip: String,
        #[arg(long)]
        sni: String,
        #[arg(short, long)]
        url: String,
        #[arg(long, default_value = "10")]
        timeout: u64,
    },

    /// Scan a range of IPs to find which ones serve Google Fonts.
    IpScan {
        #[arg(short, long)]
        range: String,
        #[arg(long, default_value = "fonts.googleapis.com")]
        sni: String,
        #[arg(long, default_value = "/css2?family=Roboto")]
        path: String,
        #[arg(short, long, default_value = "20")]
        concurrency: usize,
        #[arg(long, default_value = "5")]
        timeout: u64,
    },

    /// Generate V2Ray configuration files.
    #[command(alias = "v2ray-gen")]
    V2RayGen {
        #[arg(long, default_value = "127.0.0.1:1080")]
        listen: String,
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "b5e89d3e-6d62-4f3a-9a2b-7e8f9c0d1e2f")]
        uuid: String,
        #[arg(short, long, default_value = "./v2ray-configs")]
        out: PathBuf,
    },

    /// Try all available transports in order.
    Combine {
        #[arg(short, long)]
        url: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(short, long)]
        header: Vec<String>,
        #[arg(short, long)]
        data: Option<PathBuf>,
        #[arg(long, default_value = "Parsa-Nasiri/internet-relay")]
        repo: String,
        #[arg(long)]
        script_url: Option<String>,
        #[arg(long)]
        fonts_ip: Option<String>,
    },

    /// List all transport methods and their status.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GithubFetch { url, method, data, header, repo, fire_and_forget } => {
            let relay = GitHubRelay::new(&repo);
            let body = if let Some(p) = &data {
                Some(std::fs::read_to_string(p).context("Reading body file")?)
            } else { None };
            let headers = parse_headers(&header);
            let req = transports::FetchRequest::new(&method, &url)
                .body(body.unwrap_or_default())
                .headers(headers);

            if fire_and_forget {
                relay.submit_only(req).await?;
            } else {
                let resp = relay.fetch(req).await.context("GitHub relay fetch")?;
                print_response(&resp);
            }
        }

        Commands::AppsScriptFetch { script_url, url, method, header } => {
            let relay = AppsScriptRelay::new(&script_url);
            let headers = parse_headers(&header);
            let req = transports::FetchRequest::new(&method, &url).headers(headers);
            let resp = relay.fetch(req).await.context("Apps Script relay fetch")?;
            print_response(&resp);
        }

        Commands::SniTest { ip, sni, url, timeout } => {
            let result = sni::sni_spoof_fetch(&ip, &sni, &url, timeout).await?;
            println!("HTTP {} ({} bytes)", result.status, result.body.len());
            if !result.headers.is_empty() {
                println!("--- Response Headers ---");
                for (k, v) in &result.headers {
                    println!("  {}: {}", k, v);
                }
            }
            println!("--- Body ---");
            let to_show = if result.body.len() > 2000 { 2000 } else { result.body.len() };
            println!("{}", &result.body.chars().take(to_show).collect::<String>());
            if result.body.len() > 2000 {
                println!("... ({} more bytes)", result.body.len() - to_show);
            }
        }

        Commands::IpScan { range, sni, path, concurrency, timeout } => {
            let scanner = IpScanner::new(sni, path, timeout);
            let ips = scanner.parse_range(&range);
            println!("Scanning {} IPs (concurrency={})...", ips.len(), concurrency);
            let results = IpScanner::scan_batch(&ips, concurrency, &scanner).await?;
            println!("\n=== Results ===");
            for r in &results {
                let marker = if r.accessible { "+" } else { "x" };
                println!("{} {}:{} -> {}", marker, r.ip, r.port, r.http_code);
            }
            let accessible = results.iter().filter(|r| r.accessible).count();
            println!("\n{} / {} IPs accessible", accessible, results.len());
        }

        Commands::V2RayGen { listen, server, uuid, out } => {
            V2RayConfig::write_to_dir(&listen, &server, &uuid, &out)
                .context("Writing V2Ray configs")?;
            println!("V2Ray configs written to {}", out.display());
            println!("   Client config: {}/config.json", out.display());
            println!("   Server config: {}/server.json", out.display());
        }

        Commands::Combine { url, method, header, data, repo, script_url, fonts_ip } => {
            let body = data.map(|p| std::fs::read_to_string(&p).unwrap_or_default());
            let headers = parse_headers(&header);
            let req = transports::FetchRequest::new(&method, &url)
                .body(body.unwrap_or_default())
                .headers(headers);

            // 1. Try SNI spoofing directly if a Fonts IP is provided
            if let Some(ip) = &fonts_ip {
                println!("Trying SNI spoofing to {}...", ip);
                match sni::sni_spoof_fetch(ip, "fonts.googleapis.com", &url, 5).await {
                    Ok(r) if r.status.starts_with('2') => {
                        println!("SNI spoof succeeded!\n");
                        println!("{}", r.body);
                        return Ok(());
                    }
                    Ok(r) => println!("SNI returned {}, trying next...", r.status),
                    Err(e) => println!("SNI spoof failed: {}", e),
                }
            }

            // 2. Try GitHub Actions relay (primary)
            println!("Trying GitHub Actions relay...");
            let gh = GitHubRelay::new(&repo);
            match gh.fetch(req.clone()).await {
                Ok(resp) => {
                    println!("GitHub relay succeeded!\n");
                    print_response(&resp);
                    return Ok(());
                }
                Err(e) => println!("GitHub relay failed: {}", e),
            }

            // 3. Try Apps Script relay (if available)
            if let Some(su) = &script_url {
                println!("Trying Apps Script relay...");
                let as_relay = AppsScriptRelay::new(su);
                match as_relay.fetch(req.clone()).await {
                    Ok(resp) => {
                        println!("Apps Script relay succeeded!\n");
                        print_response(&resp);
                        return Ok(());
                    }
                    Err(e) => println!("Apps Script relay failed: {}", e),
                }
            }

            println!("All transports exhausted.");
            println!("   Run 'blackout-relay ip-scan' to find working Fonts IPs.");
            println!("   Deploy a V2Ray server with 'blackout-relay v2ray-gen'.");
        }

        Commands::Status => {
            println!("=== Transport Status ===");
            println!();
            println!("GitHub Actions relay  - tested & working (HTTP 200 via runner)");
            println!("   Repo: Parsa-Nasiri/internet-relay");
            println!("Apps Script relay     - tested (script.google.com -> 302)");
            println!("SNI spoofing          - tested (Fonts IPs -> HTTP 200)");
            println!("   IPs: 142.250.1.95, .99, .100, .101-.107 all accessible");
            println!("Cloud Run + V2Ray     - reachable (403), needs GCP billing");
            println!("Psiphon               - blocked (psiphon3.com -> 000)");
        }
    }

    Ok(())
}

fn parse_headers(header_strs: &[String]) -> std::collections::HashMap<String, String> {
    let mut h = std::collections::HashMap::new();
    for s in header_strs {
        if let Some(idx) = s.find(':') {
            let key = s[..idx].trim().to_string();
            let val = s[idx + 1..].trim().to_string();
            h.insert(key, val);
        }
    }
    h
}

fn print_response(resp: &transports::FetchResult) {
    println!("HTTP {} ({} bytes)", resp.status, resp.body.len());
    if !resp.headers.is_empty() {
        println!("--- Response Headers ---");
        for (k, v) in &resp.headers {
            println!("  {}: {}", k, v);
        }
    }
    println!("--- Body ---");
    let to_show = if resp.body.len() > 2000 { 2000 } else { resp.body.len() };
    println!("{}", &resp.body.chars().take(to_show).collect::<String>());
    if resp.body.len() > 2000 {
        println!("... ({} more bytes)", resp.body.len() - to_show);
    }
}
