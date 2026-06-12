use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use colored::Colorize;
use tokio::net::TcpStream;

use crate::config::{self, Config};
use crate::connection::ConnectionHandler;

#[derive(Debug, Clone, Copy)]
pub struct DoctorOptions {
    pub reachability: bool,
    pub timeout: Duration,
}

#[derive(Debug, Default)]
struct DoctorSummary {
    warnings: usize,
    failures: usize,
}

impl DoctorSummary {
    fn record(&mut self, status: CheckStatus) {
        match status {
            CheckStatus::Warn => self.warnings += 1,
            CheckStatus::Fail => self.failures += 1,
            CheckStatus::Ok | CheckStatus::Skip => {}
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl CheckStatus {
    fn marker(self) -> String {
        match self {
            Self::Ok => "\u{25CF}".green().to_string(),
            Self::Warn => "\u{25CF}".yellow().to_string(),
            Self::Fail => "\u{25CF}".red().to_string(),
            Self::Skip => "\u{25CF}".dimmed().to_string(),
        }
    }
}

pub async fn run_doctor(config_path: &Path, options: DoctorOptions) -> Result<()> {
    println!("{}", "Pike doctor".bold());
    println!(
        "  {} {}",
        "Version:".dimmed(),
        format!("v{}", env!("CARGO_PKG_VERSION"))
    );

    let mut summary = DoctorSummary::default();
    let (cfg, config_ok) = check_config(config_path, &mut summary).await;
    check_auth(&cfg, config_ok, &mut summary);
    let relay_addrs = check_relay_dns(&cfg, &mut summary).await;
    check_api_health(&cfg, options.timeout, &mut summary).await;
    check_local_version_context(&mut summary);
    check_reachability(
        &cfg,
        relay_addrs.as_ref().ok().map(Vec::as_slice),
        options,
        &mut summary,
    )
    .await;

    println!();
    if summary.failures == 0 && summary.warnings == 0 {
        println!("  {} {}", "\u{25CF}".green(), "All checks passed".bold());
    } else {
        println!(
            "  {} {}",
            "\u{25CF}".yellow(),
            format!(
                "Doctor found {} failure{} and {} warning{}.",
                summary.failures,
                if summary.failures == 1 { "" } else { "s" },
                summary.warnings,
                if summary.warnings == 1 { "" } else { "s" },
            )
            .bold()
        );
    }

    Ok(())
}

async fn check_config(config_path: &Path, summary: &mut DoctorSummary) -> (Config, bool) {
    if !config_path.exists() {
        print_check(
            summary,
            CheckStatus::Fail,
            "Config",
            &format!(
                "missing at {}; run `pike login <api_key>` to create it",
                config_path.display()
            ),
        );
        return (Config::default(), false);
    }

    match config::load_config(config_path).await {
        Ok(cfg) => {
            print_check(
                summary,
                CheckStatus::Ok,
                "Config",
                &format!("loaded {}", config_path.display()),
            );
            (cfg, true)
        }
        Err(error) => {
            print_check(
                summary,
                CheckStatus::Fail,
                "Config",
                &format!(
                    "could not load {}; using defaults for remaining checks: {error}",
                    config_path.display()
                ),
            );
            (Config::default(), false)
        }
    }
}

fn check_auth(cfg: &Config, config_ok: bool, summary: &mut DoctorSummary) {
    if cfg.auth.api_key.as_ref().is_some_and(|key| !key.is_empty()) {
        print_check(summary, CheckStatus::Ok, "Auth", "API key is present");
    } else if config_ok {
        print_check(
            summary,
            CheckStatus::Fail,
            "Auth",
            "no API key configured; run `pike login <api_key>`",
        );
    } else {
        print_check(
            summary,
            CheckStatus::Skip,
            "Auth",
            "skipped because config is missing or invalid",
        );
    }
}

async fn check_relay_dns(cfg: &Config, summary: &mut DoctorSummary) -> Result<Vec<SocketAddr>, ()> {
    match tokio::net::lookup_host(&cfg.relay.addr).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            if let Some(first) = addrs.first() {
                print_check(
                    summary,
                    CheckStatus::Ok,
                    "Relay DNS",
                    &format!(
                        "{} resolved to {} ({} address{})",
                        cfg.relay.addr,
                        first,
                        addrs.len(),
                        if addrs.len() == 1 { "" } else { "es" },
                    ),
                );
                Ok(addrs)
            } else {
                print_check(
                    summary,
                    CheckStatus::Fail,
                    "Relay DNS",
                    &format!("{} resolved to no addresses", cfg.relay.addr),
                );
                Err(())
            }
        }
        Err(error) => {
            print_check(
                summary,
                CheckStatus::Fail,
                "Relay DNS",
                &format!("failed to resolve {}: {error}", cfg.relay.addr),
            );
            Err(())
        }
    }
}

async fn check_api_health(cfg: &Config, timeout: Duration, summary: &mut DoctorSummary) {
    let health_url = format!("{}/health", cfg.relay.api_url.trim_end_matches('/'));
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            print_check(
                summary,
                CheckStatus::Fail,
                "API Health",
                &format!("failed to create HTTP client: {error}"),
            );
            return;
        }
    };

    match client.get(&health_url).send().await {
        Ok(response) if response.status().is_success() => {
            print_check(
                summary,
                CheckStatus::Ok,
                "API Health",
                &format!("{} returned {}", health_url, response.status()),
            );
        }
        Ok(response) if response.status().is_redirection() => {
            let location = response
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<unknown>");
            print_check(
                summary,
                CheckStatus::Warn,
                "API Health",
                &format!(
                    "{} redirected with {} to {}; check relay.api_url",
                    health_url,
                    response.status(),
                    location
                ),
            );
        }
        Ok(response) if response.status().is_server_error() => {
            print_check(
                summary,
                CheckStatus::Fail,
                "API Health",
                &format!("{} returned {}", health_url, response.status()),
            );
        }
        Ok(response) => {
            print_check(
                summary,
                CheckStatus::Warn,
                "API Health",
                &format!(
                    "{} was reachable but returned {}",
                    health_url,
                    response.status()
                ),
            );
        }
        Err(error) => {
            print_check(
                summary,
                CheckStatus::Fail,
                "API Health",
                &format!("failed to reach {}: {error}", health_url),
            );
        }
    }
}

fn check_local_version_context(summary: &mut DoctorSummary) {
    match env::current_exe() {
        Ok(current_exe) => {
            print_check(
                summary,
                CheckStatus::Ok,
                "Binary",
                &format!("running {}", current_exe.display()),
            );
            check_path_binary(&current_exe, summary);
        }
        Err(error) => {
            print_check(
                summary,
                CheckStatus::Warn,
                "Binary",
                &format!("could not inspect current executable: {error}"),
            );
        }
    }
}

fn check_path_binary(current_exe: &Path, summary: &mut DoctorSummary) {
    let path_pike = find_pike_in_path();
    let Some(path_pike) = path_pike else {
        print_check(
            summary,
            CheckStatus::Warn,
            "PATH",
            "`pike` was not found in PATH; direct invocations still work",
        );
        return;
    };

    let current_canonical = current_exe
        .canonicalize()
        .unwrap_or_else(|_| current_exe.to_path_buf());
    let path_canonical = path_pike
        .canonicalize()
        .unwrap_or_else(|_| path_pike.clone());
    if current_canonical == path_canonical {
        print_check(
            summary,
            CheckStatus::Ok,
            "PATH",
            &format!("shell resolves pike to {}", path_pike.display()),
        );
    } else {
        print_check(
            summary,
            CheckStatus::Warn,
            "PATH",
            &format!(
                "shell resolves pike to {}, but this run used {}",
                path_pike.display(),
                current_exe.display()
            ),
        );
    }
}

fn find_pike_in_path() -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    let binary_name = format!("pike{}", env::consts::EXE_SUFFIX);
    env::split_paths(&path)
        .map(|dir| dir.join(&binary_name))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

async fn check_reachability(
    cfg: &Config,
    relay_addrs: Option<&[SocketAddr]>,
    options: DoctorOptions,
    summary: &mut DoctorSummary,
) {
    if !options.reachability {
        print_check(
            summary,
            CheckStatus::Skip,
            "Reachability",
            "skipped; pass `--reachability` to probe relay TCP and QUIC/UDP",
        );
        return;
    }

    let Some(relay_addr) = relay_addrs.and_then(|addrs| addrs.first()).copied() else {
        print_check(
            summary,
            CheckStatus::Skip,
            "Relay TCP",
            "skipped because relay DNS failed",
        );
        print_check(
            summary,
            CheckStatus::Skip,
            "Relay QUIC",
            "skipped because relay DNS failed",
        );
        return;
    };

    match tokio::time::timeout(options.timeout, TcpStream::connect(relay_addr)).await {
        Ok(Ok(_stream)) => {
            print_check(
                summary,
                CheckStatus::Ok,
                "Relay TCP",
                &format!("connected to {}", relay_addr),
            );
        }
        Ok(Err(error)) => {
            print_check(
                summary,
                CheckStatus::Fail,
                "Relay TCP",
                &format!("failed to connect to {}: {error}", relay_addr),
            );
        }
        Err(_) => {
            print_check(
                summary,
                CheckStatus::Fail,
                "Relay TCP",
                &format!("timed out connecting to {}", relay_addr),
            );
        }
    }

    if cfg.auth.api_key.as_ref().is_none_or(|key| key.is_empty()) {
        print_check(
            summary,
            CheckStatus::Skip,
            "Relay QUIC",
            "skipped because no API key is configured",
        );
        return;
    }

    let mut handler = ConnectionHandler::new(cfg.clone());
    match tokio::time::timeout(options.timeout, handler.connect()).await {
        Ok(Ok(())) => {
            let _ = handler.graceful_shutdown().await;
            print_check(
                summary,
                CheckStatus::Ok,
                "Relay QUIC",
                "connected and authenticated over QUIC/UDP",
            );
        }
        Ok(Err(error)) => {
            print_check(
                summary,
                CheckStatus::Fail,
                "Relay QUIC",
                &format!("QUIC/auth check failed: {error}"),
            );
        }
        Err(_) => {
            print_check(
                summary,
                CheckStatus::Fail,
                "Relay QUIC",
                "timed out during QUIC/auth check",
            );
        }
    }
}

fn print_check(summary: &mut DoctorSummary, status: CheckStatus, label: &str, detail: &str) {
    summary.record(status);
    println!(
        "  {} {:<14} {}",
        status.marker(),
        format!("{label}:").bold(),
        detail
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_check_rejects_missing_paths() {
        assert!(!is_executable_file(Path::new(
            "/definitely/not/a/pike/binary"
        )));
    }
}
