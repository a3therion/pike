use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Subcommand;
use pike_core::types::TunnelId;
use uuid::Uuid;

use crate::registry::ClientRegistry;

#[derive(Debug, Clone, Subcommand)]
pub enum AdminCommand {
    Ban { user_id: String },
    Unban { user_id: String },
    Suspend { tunnel_id: String },
    ListBans,
}

pub async fn run_admin_command(cmd: AdminCommand, registry: Arc<ClientRegistry>) -> Result<()> {
    match cmd {
        AdminCommand::Ban { user_id } => {
            registry
                .abuse_detector
                .ban_user(user_id.clone())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            registry
                .kill_user_tunnels(&user_id)
                .await
                .with_context(|| format!("failed to kill tunnels for user {user_id}"))?;
            println!("User {user_id} banned");
        }
        AdminCommand::Unban { user_id } => {
            registry
                .abuse_detector
                .unban_user(user_id.clone())
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("User {user_id} unbanned");
        }
        AdminCommand::Suspend { tunnel_id } => {
            let parsed = Uuid::from_str(&tunnel_id)
                .with_context(|| format!("invalid tunnel id {tunnel_id}"))?;
            registry
                .abuse_detector
                .suspend_tunnel(TunnelId(parsed))
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("Tunnel {tunnel_id} suspended");
        }
        AdminCommand::ListBans => {
            let bans = registry.abuse_detector.list_bans();
            for user_id in bans {
                println!("Banned: {user_id}");
            }
        }
    }

    Ok(())
}
