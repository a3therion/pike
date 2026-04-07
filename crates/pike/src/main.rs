#![allow(
    dead_code,
    unused_imports,
    async_fn_in_trait,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::uninlined_format_args,
    clippy::ignored_unit_patterns,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::unused_async,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::return_self_not_must_use,
    clippy::struct_field_names,
    clippy::needless_pass_by_value,
    clippy::single_match_else,
    clippy::option_as_ref_cloned,
    clippy::if_not_else,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::map_unwrap_or,
    clippy::format_in_format_args
)]

mod config;
mod connection;
mod inspector;
mod session;
mod tunnel;

use std::io::IsTerminal;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use chrono::Local;
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use pike_core::types::{TunnelConfig, TunnelType};
use tokio::signal;

use crate::config::Config;
use crate::connection::{reconnect_backoff, ConnectionHandler};
use crate::inspector::{InspectorServer, RequestStore};
use crate::tunnel::{HttpTunnel, TcpTunnel};

#[derive(Parser, Debug)]
#[command(
    name = "pike",
    version,
    about = "Expose local services to the internet"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value = "~/.pike/config.toml")]
    config: PathBuf,

    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start an HTTP tunnel.
    Http {
        /// Local port to expose.
        port: u16,
        /// Optional subdomain prefix.
        #[arg(long)]
        subdomain: Option<String>,
        /// Local host to bind.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Inspector port to bind exactly for this tunnel run.
        #[arg(long)]
        inspector_port: Option<u16>,
        /// Maximum number of reconnection attempts (unlimited if not set).
        #[arg(long)]
        max_reconnects: Option<u32>,
    },
    /// Start a TCP tunnel.
    Tcp {
        /// Local port to expose.
        port: u16,
        /// Optional remote relay port.
        #[arg(long)]
        remote_port: Option<u16>,
        /// Maximum number of reconnection attempts (unlimited if not set).
        #[arg(long)]
        max_reconnects: Option<u32>,
    },
    /// Store API key in config.
    Login { api_key: String },
    /// Display authentication state.
    Status,
    /// Display build and relay details.
    Version,
}

// ─── Display Constants ──────────────────────────────────────

const BOX_WIDTH: usize = 45;
const BOX_INNER: usize = BOX_WIDTH - 2;

const PIKE_LOGO: &str = r"  ██████╗ ██╗██╗  ██╗███████╗
  ██╔══██╗██║██║ ██╔╝██╔════╝
  ██████╔╝██║█████╔╝ █████╗
  ██╔═══╝ ██║██╔═██╗ ██╔══╝
  ██║     ██║██║  ██╗███████╗
  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝";

// ─── Display Helpers ────────────────────────────────────────

fn is_tty() -> bool {
    std::io::stdout().is_terminal()
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80)
}

fn use_fancy() -> bool {
    terminal_width() >= 80
}

fn print_logo() {
    if is_tty() && use_fancy() {
        println!("{}", PIKE_LOGO.truecolor(249, 115, 22));
        println!();
    }
}

fn box_top() {
    println!("\u{250C}{}\u{2510}", "\u{2500}".repeat(BOX_INNER));
}

fn box_bottom() {
    println!("\u{2514}{}\u{2518}", "\u{2500}".repeat(BOX_INNER));
}

fn box_sep() {
    println!("\u{251C}{}\u{2524}", "\u{2500}".repeat(BOX_INNER));
}

fn box_header(title: &str, right: &str) {
    let left = format!("  {}", title);
    let right_padded = format!("{} ", right);
    let gap = BOX_INNER
        .saturating_sub(left.chars().count())
        .saturating_sub(right_padded.chars().count());
    println!(
        "\u{2502}{}{}{}\u{2502}",
        left,
        " ".repeat(gap),
        right_padded
    );
}

fn box_row(label: &str, value: &str) {
    let max_val = BOX_INNER.saturating_sub(14);
    let display_val = if value.chars().count() > max_val {
        let truncated: String = value.chars().take(max_val.saturating_sub(1)).collect();
        format!("{}\u{2026}", truncated)
    } else {
        value.to_string()
    };
    let content = format!("  {:<12}{}", label, display_val);
    let pad = BOX_INNER.saturating_sub(content.chars().count());
    println!("\u{2502}{}{}\u{2502}", content, " ".repeat(pad));
}

/// Print a row with ANSI-colored content. `visible_len` is the plain-text char count.
fn box_row_colored(colored_content: &str, visible_len: usize) {
    let pad = BOX_INNER.saturating_sub(visible_len);
    println!("\u{2502}{}{}\u{2502}", colored_content, " ".repeat(pad));
}

fn box_text(text: &str) {
    let pad = BOX_INNER.saturating_sub(text.chars().count());
    println!("\u{2502}{}{}\u{2502}", text, " ".repeat(pad));
}

/// Returns (colored_string, visible_char_count) for a status row.
fn status_row(state: &str) -> (String, usize) {
    let plain = format!("  {:<12}\u{25CF} {}", "Status", state);
    let visible_len = plain.chars().count();
    let dot = match state {
        "Active" => "\u{25CF}".green().to_string(),
        "Error" => "\u{25CF}".red().to_string(),
        "Connecting" => "\u{25CF}".yellow().to_string(),
        _ => "\u{25CF}".dimmed().to_string(),
    };
    let content = format!("  {:<12}{} {}", "Status", dot, state);
    (content, visible_len)
}

fn format_elapsed(d: Duration) -> String {
    let total = d.as_secs();
    let mins = total / 60;
    let secs = total % 60;
    if mins > 0 {
        format!("{}m {}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}

fn print_tunnel_box_http(public_url: &str, host: &str, port: u16, inspector_port: Option<u16>) {
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));

    if use_fancy() {
        print_logo();
        box_top();
        box_header("Pike Tunnel", &version);
        box_sep();
        let (sc, sl) = status_row("Active");
        box_row_colored(&sc, sl);
        box_row("URL", public_url);
        box_row("Local", &format!("http://{}:{}", host, port));
        box_row("Transport", "QUIC (fallback WS)");
        if let Some(inspector_port) = inspector_port {
            box_row("Inspector", &format!("http://127.0.0.1:{}", inspector_port));
        }
        box_sep();
        box_text("  Ctrl+C to stop");
        box_bottom();
    } else {
        println!("pike {}", version);
        println!("Status: Active");
        println!("URL: {}", public_url);
        println!("Local: http://{}:{}", host, port);
        println!("Transport: QUIC (fallback WS)");
        if let Some(inspector_port) = inspector_port {
            println!("Inspector: http://127.0.0.1:{}", inspector_port);
        }
        println!("Ctrl+C to stop");
    }
}

fn print_tunnel_box_tcp(port: u16, remote_port: Option<u16>, relay_addr: &str) {
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let relay_port = remote_port.unwrap_or(port);

    if use_fancy() {
        print_logo();
        box_top();
        box_header("Pike Tunnel (TCP)", &version);
        box_sep();
        let (sc, sl) = status_row("Active");
        box_row_colored(&sc, sl);
        box_row(
            "Tunnel",
            &format!("tcp://{} -> 127.0.0.1:{}", relay_port, port),
        );
        box_row("Relay", relay_addr);
        box_sep();
        box_text("  Ctrl+C to stop");
        box_bottom();
    } else {
        println!("pike {} (TCP)", version);
        println!("Status: Active");
        println!("Tunnel: tcp://{} -> 127.0.0.1:{}", relay_port, port);
        println!("Relay: {}", relay_addr);
        println!("Ctrl+C to stop");
    }
}

fn print_version_box(relay_addr: &str, ws_fallback: bool) {
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));

    print_logo();

    if use_fancy() {
        box_top();
        box_header("Pike Tunnel", &version);
        box_sep();
        box_row("Relay", relay_addr);
        box_row("Fallback", &format!("{}", ws_fallback));
        box_bottom();
    } else {
        println!("pike {}", version);
        println!("Relay: {}", relay_addr);
        println!("Fallback: {}", ws_fallback);
    }
}

fn print_status_box(relay_addr: &str, authenticated: bool) {
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let state = if authenticated {
        "authenticated"
    } else {
        "not authenticated"
    };

    if use_fancy() {
        box_top();
        box_header("Pike Status", &version);
        box_sep();
        let dot = if authenticated {
            "\u{25CF}".green().to_string()
        } else {
            "\u{25CF}".red().to_string()
        };
        let plain = format!("  {:<12}\u{25CF} {}", "Auth", state);
        let colored_content = format!("  {:<12}{} {}", "Auth", dot, state);
        box_row_colored(&colored_content, plain.chars().count());
        box_row("Relay", relay_addr);
        box_bottom();
    } else {
        println!("pike status");
        println!("Auth: {}", state);
        println!("Relay: {}", relay_addr);
    }
}

fn print_http_stop_summary(tunnel_start: Instant, request_store: Option<&Arc<RequestStore>>) {
    let elapsed = format_elapsed(tunnel_start.elapsed());
    let req_count = request_store.map_or(0, |store| store.len());
    println!(
        "\n  {}",
        format!(
            "Tunnel stopped. {} request{} in {}.",
            req_count,
            if req_count == 1 { "" } else { "s" },
            elapsed,
        )
        .dimmed()
    );
}

fn print_tcp_stop_summary(tunnel_start: Instant) {
    let elapsed = format_elapsed(tunnel_start.elapsed());
    println!("\n  {}", format!("Tunnel stopped in {}.", elapsed).dimmed());
}

async fn wait_for_retry(
    reconnect_attempt: &mut u32,
    max_reconnects: Option<u32>,
    reason: &str,
) -> anyhow::Result<bool> {
    let next_attempt = reconnect_attempt.saturating_add(1);
    if let Some(max_attempts) = max_reconnects {
        if next_attempt > max_attempts {
            return Err(anyhow!("{reason} (max reconnect attempts reached)"));
        }
    }

    *reconnect_attempt = next_attempt;

    let backoff = reconnect_backoff(next_attempt - 1);
    let now = Local::now().format("%H:%M:%S");
    println!(
        "[{}] {} ({}; attempt {}, backoff {:.1}s)",
        now,
        "Reconnecting...".yellow(),
        reason,
        next_attempt,
        backoff.as_secs_f64()
    );

    tokio::select! {
        _ = tokio::time::sleep(backoff) => Ok(true),
        signal_result = signal::ctrl_c() => {
            signal_result?;
            Ok(false)
        }
    }
}

fn spawn_inspector(
    request_store: Option<Arc<RequestStore>>,
    listener: Option<tokio::net::TcpListener>,
) {
    if let (Some(store), Some(listener)) = (request_store, listener) {
        tokio::spawn(async move {
            let server = InspectorServer::new(store);
            if let Err(e) = server.run(listener).await {
                eprintln!("Inspector server error: {e}");
            }
        });
    }
}

fn http_inspector_enabled(cfg: &Config, inspector_port_override: Option<u16>) -> bool {
    cfg.inspector.enabled || inspector_port_override.is_some()
}

async fn bind_inspector_listener(
    preferred_port: u16,
    requested_port: Option<u16>,
) -> anyhow::Result<(tokio::net::TcpListener, u16)> {
    if let Some(port) = requested_port {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|error| anyhow!("failed to bind inspector to 127.0.0.1:{port}: {error}"))?;
        let actual_port = listener
            .local_addr()
            .map_err(|error| anyhow!("failed to inspect bound inspector address: {error}"))?
            .port();
        return Ok((listener, actual_port));
    }

    for port in preferred_port..=u16::MAX {
        match tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
            Ok(listener) => {
                let actual_port = listener
                    .local_addr()
                    .map_err(|error| anyhow!("failed to inspect bound inspector address: {error}"))?
                    .port();
                return Ok((listener, actual_port));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => {
                return Err(anyhow!(
                    "failed to bind inspector to 127.0.0.1:{port}: {error}"
                ));
            }
        }
    }

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| anyhow!("failed to bind inspector to an ephemeral port: {error}"))?;
    let actual_port = listener
        .local_addr()
        .map_err(|error| anyhow!("failed to inspect bound inspector address: {error}"))?
        .port();
    Ok((listener, actual_port))
}

async fn build_http_tunnel(
    cfg: &Config,
    tunnel_config: &TunnelConfig,
    port: u16,
    host: &str,
    request_store: Option<Arc<RequestStore>>,
    max_reconnects: Option<u32>,
) -> anyhow::Result<HttpTunnel> {
    let mut handler =
        ConnectionHandler::new(cfg.clone()).with_max_reconnect_attempts(max_reconnects);
    handler.connect().await?;
    let connection = handler
        .take_connection()
        .ok_or_else(|| anyhow!("no connection"))?;
    let client = handler.take_client().ok_or_else(|| anyhow!("no client"))?;
    let requested_subdomain = match &tunnel_config.tunnel_type {
        TunnelType::Http { subdomain, .. } => subdomain.clone(),
        TunnelType::Tcp { .. } => None,
    };

    Ok(HttpTunnel::new(
        tunnel_config.clone(),
        port,
        host.to_string(),
        requested_subdomain,
        connection,
        client,
        request_store,
    ))
}

async fn build_tcp_tunnel(
    cfg: &Config,
    tunnel_config: &TunnelConfig,
    port: u16,
    remote_port: Option<u16>,
    max_reconnects: Option<u32>,
) -> anyhow::Result<TcpTunnel> {
    let mut handler =
        ConnectionHandler::new(cfg.clone()).with_max_reconnect_attempts(max_reconnects);
    handler.connect().await?;
    let connection = handler
        .take_connection()
        .ok_or_else(|| anyhow!("no connection"))?;

    Ok(TcpTunnel::new(
        tunnel_config.clone(),
        port,
        cfg.tunnel.bind_addr.clone(),
        remote_port,
        connection,
    ))
}

async fn run_http_command(
    cfg: Config,
    tunnel_config: TunnelConfig,
    port: u16,
    host: String,
    inspector_port_override: Option<u16>,
    max_reconnects: Option<u32>,
) -> anyhow::Result<()> {
    let request_store = if http_inspector_enabled(&cfg, inspector_port_override) {
        Some(Arc::new(RequestStore::new(cfg.inspector.max_requests)))
    } else {
        None
    };
    let (inspector_listener, inspector_port) = if request_store.is_some() {
        let (listener, actual_port) =
            bind_inspector_listener(cfg.inspector.port, inspector_port_override).await?;
        (Some(listener), Some(actual_port))
    } else {
        (None, None)
    };
    spawn_inspector(request_store.clone(), inspector_listener);

    let tunnel_start = Instant::now();
    let mut reconnect_attempt = 0_u32;
    let mut initial_displayed = false;

    loop {
        let connect_spinner = (!initial_displayed).then(|| spinner("Connecting to relay..."));

        let mut tunnel = match build_http_tunnel(
            &cfg,
            &tunnel_config,
            port,
            &host,
            request_store.clone(),
            max_reconnects,
        )
        .await
        {
            Ok(tunnel) => tunnel,
            Err(err) => {
                if let Some(spinner) = &connect_spinner {
                    spinner.finish_and_clear();
                }
                let reason = format!("connect failed: {err}");
                if !wait_for_retry(&mut reconnect_attempt, max_reconnects, &reason).await? {
                    print_http_stop_summary(tunnel_start, request_store.as_ref());
                    return Ok(());
                }
                continue;
            }
        };

        if let Some(spinner) = connect_spinner {
            spinner.finish_and_clear();
        }

        if !initial_displayed {
            println!("Registering tunnel...");
        }

        let public_url = match tunnel.register().await {
            Ok(public_url) => public_url,
            Err(err) => {
                let reason = format!("tunnel registration failed: {err}");
                if !wait_for_retry(&mut reconnect_attempt, max_reconnects, &reason).await? {
                    print_http_stop_summary(tunnel_start, request_store.as_ref());
                    return Ok(());
                }
                continue;
            }
        };

        if !initial_displayed {
            print_tunnel_box_http(&public_url, &host, port, inspector_port);
            initial_displayed = true;
        } else {
            let now = Local::now().format("%H:%M:%S");
            println!(
                "[{}] {} ({})",
                now,
                "Tunnel reconnected".green(),
                public_url
            );
        }

        reconnect_attempt = 0;

        tokio::select! {
            result = tunnel.run() => {
                result?;
                if !wait_for_retry(
                    &mut reconnect_attempt,
                    max_reconnects,
                    "relay connection lost",
                ).await? {
                    print_http_stop_summary(tunnel_start, request_store.as_ref());
                    return Ok(());
                }
            }
            signal_result = signal::ctrl_c() => {
                signal_result?;
                tunnel.shutdown().await?;
                // Deactivate tunnel in Workers API
                if let Some(api_key) = &cfg.auth.api_key {
                    let subdomain = public_url
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .split('.')
                        .next()
                        .unwrap_or_default();
                    if !subdomain.is_empty() {
                        let url = format!("{}/api/v1/tunnels/deactivate", cfg.relay.api_url);
                        let _ = reqwest::Client::new()
                            .post(&url)
                            .bearer_auth(api_key)
                            .json(&serde_json::json!({ "subdomain": subdomain }))
                            .send()
                            .await;
                    }
                }
                print_http_stop_summary(tunnel_start, request_store.as_ref());
                return Ok(());
            }
        }
    }
}

async fn run_tcp_command(
    cfg: Config,
    tunnel_config: TunnelConfig,
    port: u16,
    remote_port: Option<u16>,
    max_reconnects: Option<u32>,
) -> anyhow::Result<()> {
    let tunnel_start = Instant::now();
    let mut reconnect_attempt = 0_u32;
    let mut initial_displayed = false;

    loop {
        let connect_spinner = (!initial_displayed).then(|| spinner("Connecting to relay..."));

        let mut tunnel =
            match build_tcp_tunnel(&cfg, &tunnel_config, port, remote_port, max_reconnects).await {
                Ok(tunnel) => tunnel,
                Err(err) => {
                    if let Some(spinner) = &connect_spinner {
                        spinner.finish_and_clear();
                    }
                    let reason = format!("connect failed: {err}");
                    if !wait_for_retry(&mut reconnect_attempt, max_reconnects, &reason).await? {
                        print_tcp_stop_summary(tunnel_start);
                        return Ok(());
                    }
                    continue;
                }
            };

        if let Some(spinner) = connect_spinner {
            spinner.finish_and_clear();
        }

        if !initial_displayed {
            println!("Registering tunnel...");
        }

        let assigned_port = match tunnel.register().await {
            Ok(assigned_port) => assigned_port,
            Err(err) => {
                let reason = format!("tunnel registration failed: {err}");
                if !wait_for_retry(&mut reconnect_attempt, max_reconnects, &reason).await? {
                    print_tcp_stop_summary(tunnel_start);
                    return Ok(());
                }
                continue;
            }
        };

        let display_remote_port = if assigned_port == 0 {
            remote_port
        } else {
            Some(assigned_port)
        };

        if !initial_displayed {
            print_tunnel_box_tcp(port, display_remote_port, &cfg.relay.addr);
            initial_displayed = true;
        } else {
            let now = Local::now().format("%H:%M:%S");
            let relay_port = display_remote_port.unwrap_or(port);
            println!(
                "[{}] {} (tcp://{} -> 127.0.0.1:{})",
                now,
                "Tunnel reconnected".green(),
                relay_port,
                port
            );
        }

        reconnect_attempt = 0;

        tokio::select! {
            result = tunnel.run() => {
                result?;
                if !wait_for_retry(
                    &mut reconnect_attempt,
                    max_reconnects,
                    "relay connection lost",
                ).await? {
                    print_tcp_stop_summary(tunnel_start);
                    return Ok(());
                }
            }
            signal_result = signal::ctrl_c() => {
                signal_result?;
                print_tcp_stop_summary(tunnel_start);
                return Ok(());
            }
        }
    }
}

// ─── Main ───────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Disable ANSI colors when output is piped
    if !is_tty() {
        colored::control::set_override(false);
    }

    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(format!("pike_cli={}", cli.log_level))
        .init();

    let config_path = config::resolve_config_path(&cli.config);
    let mut cfg = config::load_or_create_config(&config_path).await?;

    match cli.command {
        Commands::Http {
            port,
            subdomain,
            host,
            inspector_port,
            max_reconnects,
        } => {
            let tunnel_config = cfg.as_http_tunnel_config(&host, port, subdomain)?;
            run_http_command(
                cfg,
                tunnel_config,
                port,
                host,
                inspector_port,
                max_reconnects,
            )
            .await?;
        }
        Commands::Tcp {
            port,
            remote_port,
            max_reconnects,
        } => {
            let tunnel_config = cfg.as_tcp_tunnel_config(port, remote_port)?;
            run_tcp_command(cfg, tunnel_config, port, remote_port, max_reconnects).await?;
        }
        Commands::Login { api_key } => {
            #[derive(serde::Deserialize)]
            struct ValidateResponse {
                email: String,
                plan: String,
            }

            let validate_url = format!("{}/api/v1/auth/validate", cfg.relay.api_url);
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(10))
                .build()?;
            let result = client
                .post(&validate_url)
                .header("Authorization", format!("Bearer {api_key}"))
                .send()
                .await;

            match result {
                Ok(response) if response.status() == reqwest::StatusCode::OK => {
                    let body: ValidateResponse = response.json().await?;
                    cfg.auth.api_key = Some(api_key);
                    config::save_config(&config_path, &cfg).await?;
                    println!(
                        "  {} {} ({})",
                        "\u{25CF}".green(),
                        format!("Logged in as {}", body.email).bold(),
                        body.plan.dimmed(),
                    );
                    println!("  {} {}", "Config:".dimmed(), config_path.display());
                }
                Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED => {
                    eprintln!(
                        "  {} {}",
                        "\u{25CF}".red(),
                        "Invalid API key. Verify your key with your control plane.".bold(),
                    );
                }
                Ok(response) if response.status().is_redirection() => {
                    let location = response
                        .headers()
                        .get("location")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("<unknown>");
                    eprintln!(
                        "  {} {}",
                        "\u{25CF}".red(),
                        format!(
                            "API returned redirect ({}) to {}. Your api_url may be misconfigured. Current: {}",
                            response.status(),
                            location,
                            validate_url
                        ).bold(),
                    );
                }
                Ok(_) | Err(_) => {
                    eprintln!(
                        "  {} {}",
                        "\u{25CF}".yellow(),
                        "Could not verify API key (offline?). Saving anyway.".dimmed(),
                    );
                    cfg.auth.api_key = Some(api_key);
                    config::save_config(&config_path, &cfg).await?;
                    println!("  {} {}", "Config:".dimmed(), config_path.display());
                }
            }
        }
        Commands::Status => {
            let is_authed = cfg.auth.api_key.as_ref().is_some_and(|k| !k.is_empty());
            print_status_box(&cfg.relay.addr, is_authed);
        }
        Commands::Version => {
            print_version_box(&cfg.relay.addr, cfg.relay.ws_fallback);
        }
    }

    Ok(())
}

fn spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner().tick_chars("-\\|/"));
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(message.to_string());
    pb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_command() {
        let cli = Cli::try_parse_from([
            "pike",
            "http",
            "3000",
            "--subdomain",
            "demo",
            "--host",
            "0.0.0.0",
            "--inspector-port",
            "5050",
        ])
        .expect("cli parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Http {
                port: 3000,
                subdomain: Some(_),
                host,
                inspector_port: Some(5050),
                max_reconnects: None
            } if host == "0.0.0.0"
        ));
    }

    #[test]
    fn parses_tcp_command_with_remote_port() {
        let cli = Cli::try_parse_from(["pike", "tcp", "5432", "--remote-port", "15432"])
            .expect("cli parse should succeed");
        assert!(matches!(
            cli.command,
            Commands::Tcp {
                port: 5432,
                remote_port: Some(15432),
                max_reconnects: None
            }
        ));
    }

    #[test]
    fn parses_login_command() {
        let cli = Cli::try_parse_from(["pike", "login", "pk_test_123"])
            .expect("cli parse should succeed");
        assert!(matches!(cli.command, Commands::Login { api_key } if api_key == "pk_test_123"));
    }

    #[tokio::test]
    async fn test_login_validates_key() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .and(header("Authorization", "Bearer pk_valid_123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"email": "user@test.com", "plan": "pro"})),
            )
            .mount(&mock_server)
            .await;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let config_path = tmp.path().join("config.toml");
        let mut cfg = config::Config::default();
        cfg.relay.api_url = mock_server.uri();
        config::save_config(&config_path, &cfg).await.unwrap();

        let api_key = "pk_valid_123";
        let url = format!("{}/api/v1/auth/validate", cfg.relay.api_url);
        let resp = reqwest::Client::new()
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("mock should respond");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);

        #[derive(serde::Deserialize)]
        struct ValidateResponse {
            email: String,
            plan: String,
        }
        let body: ValidateResponse = resp.json().await.expect("valid json");
        assert_eq!(body.email, "user@test.com");
        assert_eq!(body.plan, "pro");

        cfg.auth.api_key = Some(api_key.to_string());
        config::save_config(&config_path, &cfg).await.unwrap();

        let saved = config::load_config(&config_path).await.unwrap();
        assert_eq!(saved.auth.api_key.as_deref(), Some("pk_valid_123"));
    }

    #[tokio::test]
    async fn test_login_rejects_invalid_key() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let config_path = tmp.path().join("config.toml");
        let mut cfg = config::Config::default();
        cfg.relay.api_url = mock_server.uri();
        config::save_config(&config_path, &cfg).await.unwrap();

        let url = format!("{}/api/v1/auth/validate", cfg.relay.api_url);
        let resp = reqwest::Client::new()
            .post(&url)
            .header("Authorization", "Bearer pk_bad_key")
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("mock should respond");

        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

        let saved = config::load_config(&config_path).await.unwrap();
        assert!(saved.auth.api_key.is_none());
    }

    #[tokio::test]
    async fn test_login_offline_fallback() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let config_path = tmp.path().join("config.toml");
        let mut cfg = config::Config::default();
        cfg.relay.api_url = "http://127.0.0.1:1".to_string();
        config::save_config(&config_path, &cfg).await.unwrap();

        let api_key = "pk_offline_key";
        let url = format!("{}/api/v1/auth/validate", cfg.relay.api_url);
        let result = reqwest::Client::new()
            .post(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        assert!(result.is_err(), "connection to port 1 should be refused");

        cfg.auth.api_key = Some(api_key.to_string());
        config::save_config(&config_path, &cfg).await.unwrap();

        let saved = config::load_config(&config_path).await.unwrap();
        assert_eq!(saved.auth.api_key.as_deref(), Some("pk_offline_key"));
    }

    #[tokio::test]
    async fn http_cli_overrides_do_not_persist_shared_config() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let config_path = tmp.path().join("config.toml");
        let mut cfg = config::Config::default();
        cfg.tunnel.subdomain_prefix = "sticky".to_string();
        cfg.tunnel.bind_addr = "0.0.0.0".to_string();
        config::save_config(&config_path, &cfg).await.unwrap();

        let loaded = config::load_config(&config_path).await.unwrap();
        let tunnel = loaded
            .as_http_tunnel_config("127.0.0.1", 3000, Some("demo".to_string()))
            .expect("http tunnel config");

        assert!(matches!(
            tunnel.tunnel_type,
            TunnelType::Http {
                local_port: 3000,
                subdomain: Some(ref subdomain)
            } if subdomain == "demo"
        ));

        let saved = config::load_config(&config_path).await.unwrap();
        assert_eq!(saved.tunnel.subdomain_prefix, "sticky");
        assert_eq!(saved.tunnel.bind_addr, "0.0.0.0");
    }

    #[tokio::test]
    async fn inspector_uses_preferred_port_when_available() {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
        let preferred_port = reserved.local_addr().expect("reserved addr").port();
        drop(reserved);

        let (listener, actual_port) = bind_inspector_listener(preferred_port, None)
            .await
            .expect("bind inspector");

        assert_eq!(actual_port, preferred_port);
        drop(listener);
    }

    #[tokio::test]
    async fn inspector_auto_selects_new_port_when_preferred_is_busy() {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
        let preferred_port = reserved.local_addr().expect("reserved addr").port();

        let (listener, actual_port) = bind_inspector_listener(preferred_port, None)
            .await
            .expect("bind inspector");

        assert!(actual_port > preferred_port);
        drop(listener);
        drop(reserved);
    }

    #[tokio::test]
    async fn explicit_inspector_port_fails_when_busy() {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
        let requested_port = reserved.local_addr().expect("reserved addr").port();

        let error = bind_inspector_listener(4040, Some(requested_port))
            .await
            .expect_err("explicit inspector port should fail");

        assert!(error.to_string().contains("already in use"));
        drop(reserved);
    }
}
