//! Private IPv4 networks over native WireGuard. The Worker is the control
//! plane; this module enrolls devices with locally generated keys, prints
//! standard client configurations, manages routes and grants, and runs the
//! Linux hub and site gateways. IPv4 only, one hub per network, UDP transport.
mod api;
mod gateway;
mod keys;
mod model;
mod render;

use crate::config::Config;
use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::path::Path;

use api::{Api, ApiError, Member, MemberConfig, Network, Status};
use keys::MemberState;
use model::{
    parse_client_cidr, parse_route_cidr, role_from_str, validate_endpoint, validate_ifname,
    validate_name, PublicKey,
};

#[derive(Subcommand, Debug)]
pub enum NetworkCommand {
    /// Create a network with an explicit private client address pool.
    Create {
        name: String,
        /// Client pool, for example 100.96.0.0/24 (/20 to /29, RFC 1918 or 100.64/10).
        #[arg(long)]
        client_cidr: String,
    },
    /// Delete a network; every member, route and grant goes with it.
    Delete { name: String },
    /// List networks.
    List,
    /// Show members, routes, grants and gateway freshness.
    Status {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Enroll this device. The private key is generated here and never sent.
    Join {
        name: String,
        /// Member name (1-32 lowercase letters, digits, hyphens).
        #[arg(long = "as")]
        member: String,
        #[arg(long, default_value = "client", value_parser = ["client", "site", "hub"])]
        role: String,
        /// Hub only: public UDP endpoint host:port that peers connect to.
        #[arg(long)]
        endpoint: Option<String>,
        /// Hub only: local UDP listen port (defaults to the endpoint port).
        #[arg(long)]
        listen_port: Option<u16>,
        /// Enroll a public key generated elsewhere (for example in the WireGuard app).
        #[arg(long)]
        public_key: Option<String>,
    },
    /// Print the standard WireGuard (wg-quick) configuration for an enrolled client or site.
    Config {
        name: String,
        #[arg(long = "as")]
        member: String,
    },
    /// Revoke this device and delete its local key. The key is kept whenever
    /// the control plane does not confirm the revocation.
    Leave {
        name: String,
        #[arg(long = "as")]
        member: String,
        /// Also discard the local key and record when the control plane cannot
        /// confirm the revocation (deleted network, another account's key,
        /// pending enrollment). A still-active member must then be revoked
        /// with `pike network revoke`.
        #[arg(long)]
        forget_local: bool,
    },
    /// Revoke a member; a revoked key can never re-enroll.
    Revoke { name: String, member: String },
    /// Routes owned by site gateways.
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
    /// Allow a client to reach one owned route (all IP protocols).
    Grant {
        name: String,
        #[arg(long)]
        client: String,
        /// Exact owned route, for example 10.10.0.0/24.
        #[arg(long)]
        to: String,
    },
    /// Remove a grant; existing flows stop within the lease.
    Ungrant {
        name: String,
        #[arg(long)]
        client: String,
        #[arg(long)]
        to: String,
    },
    /// Run the hub gateway (Linux, CAP_NET_ADMIN, networks:run key).
    Hub {
        name: String,
        #[arg(long = "as")]
        member: String,
    },
    /// Run a site gateway for a LAN (Linux, CAP_NET_ADMIN, networks:run key).
    Site {
        name: String,
        #[arg(long = "as")]
        member: String,
        /// LAN interface the owned routes live behind.
        #[arg(long)]
        lan_if: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum RouteCommand {
    /// Claim a private subnet for a site; overlaps are refused atomically.
    Add {
        name: String,
        cidr: String,
        #[arg(long)]
        via: String,
    },
    /// Withdraw a route and every grant that targets it.
    Withdraw { name: String, cidr: String },
}

fn explain(error: ApiError) -> anyhow::Error {
    anyhow!("{error}")
}

async fn network_by_name(api: &Api, name: &str) -> Result<Network> {
    validate_name(name)?;
    #[derive(serde::Deserialize)]
    struct List {
        networks: Vec<Network>,
    }
    let list: List = api.get("/networks").await.map_err(explain)?;
    list.networks
        .into_iter()
        .find(|n| n.name == name)
        .with_context(|| format!("network {name} not found"))
}

async fn status(api: &Api, network: &Network) -> Result<Status> {
    api.get(&format!("/networks/{}", network.id))
        .await
        .map_err(explain)
}

fn active_member<'a>(status: &'a Status, name: &str) -> Result<&'a Member> {
    status
        .members
        .iter()
        .find(|m| m.name == name && m.status == "active")
        .with_context(|| format!("active member {name} not found"))
}

/// The member (active or revoked) holding this device's public key, if the
/// control plane recorded one. Used to reconcile a pending enrollment whose
/// answer was lost: a key is enrolled at most once per network, so a match is
/// the enrollment this device started, or proof that the key is spent.
async fn remote_by_key(api: &Api, state: &MemberState) -> Result<Option<Member>, ApiError> {
    let current: Status = api.get(&format!("/networks/{}", state.network_id)).await?;
    Ok(current
        .members
        .into_iter()
        .find(|m| m.public_key == state.public_key))
}

#[derive(serde::Deserialize)]
struct WrappedConfig {
    config: MemberConfig,
}

async fn member_config(api: &Api, network_id: &str, member_id: &str) -> Result<MemberConfig> {
    let wrapped: WrappedConfig = api
        .get(&format!(
            "/networks/{network_id}/members/{member_id}/config"
        ))
        .await
        .map_err(explain)?;
    Ok(wrapped.config)
}

/// A 4xx answer to an enrollment is the control plane refusing it: nothing
/// was committed. Everything else (no answer, an unreadable answer, a 5xx)
/// may hide a committed enrollment.
fn refused_definitively(error: &ApiError) -> bool {
    matches!(error, ApiError::Rejected { status, .. } if (400..500).contains(status))
}

fn pending_advice(network: &str, member: &str) -> String {
    format!("rerun `pike network join {network} --as {member}` to finish it, or `pike network leave {network} --as {member} --forget-local` to discard the local key")
}

fn render_client(config: &MemberConfig, private_key: Option<&str>) -> Result<String> {
    let hub = config
        .hub
        .as_ref()
        .context("the network has no active hub yet; enroll one with --role hub")?;
    let endpoint = validate_endpoint(hub.endpoint.as_deref().context("hub endpoint missing")?)?;
    let allowed = config
        .allowed_ips
        .iter()
        .map(|c| c.parse())
        .collect::<Result<Vec<_>>>()?;
    Ok(render::client_conf(
        private_key,
        config.member.address.parse()?,
        PublicKey::parse(&hub.public_key)?.as_str(),
        &endpoint,
        &allowed,
    ))
}

fn print_status(status: &Status) {
    let n = &status.network;
    println!(
        "{} {} client pool {} revision {}",
        "network".bold(),
        n.name,
        n.client_cidr,
        n.revision
    );
    let gateway = |g: &api::GatewayView| {
        if !g.reported {
            "no report".dimmed().to_string()
        } else if g.current {
            format!("applied {} fresh", g.applied_revision.unwrap_or(0))
                .green()
                .to_string()
        } else if g.fresh {
            format!("applied {} (behind)", g.applied_revision.unwrap_or(0))
                .yellow()
                .to_string()
        } else {
            format!("applied {} STALE", g.applied_revision.unwrap_or(0))
                .red()
                .to_string()
        }
    };
    match &status.hub {
        Some(hub) => println!("  hub {:<12} {}", hub.name, gateway(hub)),
        None => println!("  hub {}", "none".red()),
    }
    for site in &status.sites {
        println!(
            "  site {:<11} {} routes: {}",
            site.name,
            gateway(site),
            if site.routes.is_empty() {
                "-".to_owned()
            } else {
                site.routes.join(", ")
            }
        );
    }
    for member in &status.members {
        let handshake = status
            .hub
            .as_ref()
            .and_then(|h| h.peers.iter().find(|p| p.public_key == member.public_key))
            .map(|p| {
                if p.last_handshake == 0 {
                    "never".to_owned()
                } else {
                    format!(
                        "handshake {}s ago",
                        chrono::Utc::now()
                            .timestamp()
                            .saturating_sub(i64::try_from(p.last_handshake).unwrap_or(i64::MAX))
                    )
                }
            })
            .unwrap_or_default();
        println!(
            "  {:<7} {:<12} {:<15} {} {} {}",
            member.role,
            member.name,
            member.address,
            member.public_key,
            if member.status == "active" {
                member.status.green()
            } else {
                member.status.red()
            },
            handshake.dimmed()
        );
    }
    for route in &status.routes {
        println!(
            "  route {:<18} via {}",
            route.cidr,
            route.via_name.as_deref().unwrap_or("?")
        );
    }
    for grant in &status.grants {
        println!(
            "  grant {:<12} -> {}",
            grant.client_name.as_deref().unwrap_or("?"),
            grant.cidr.as_deref().unwrap_or("?")
        );
    }
}

pub async fn run(config: &Config, config_path: &Path, command: NetworkCommand) -> Result<()> {
    let api = Api::new(config)?;
    match command {
        NetworkCommand::Create { name, client_cidr } => {
            validate_name(&name)?;
            let pool = parse_client_cidr(&client_cidr)?;
            #[derive(serde::Deserialize)]
            struct Created {
                network: Network,
            }
            let created: Created = api
                .post(
                    "/networks",
                    &serde_json::json!({ "name": name, "client_cidr": pool.to_string() }),
                )
                .await
                .map_err(explain)?;
            println!(
                "created network {} ({}) with client pool {}",
                created.network.name, created.network.id, created.network.client_cidr
            );
        }
        NetworkCommand::Delete { name } => {
            let network = network_by_name(&api, &name).await?;
            api.delete::<serde_json::Value>(&format!("/networks/{}", network.id))
                .await
                .map_err(explain)?;
            println!("deleted network {name}; gateways fail closed and exit on their next poll");
        }
        NetworkCommand::List => {
            #[derive(serde::Deserialize)]
            struct Row {
                name: String,
                client_cidr: String,
                revision: u64,
                members: u64,
                routes: u64,
            }
            #[derive(serde::Deserialize)]
            struct List {
                networks: Vec<Row>,
            }
            let list: List = api.get("/networks").await.map_err(explain)?;
            for n in list.networks {
                println!(
                    "{:<20} {:<18} revision {:<5} members {:<3} routes {}",
                    n.name, n.client_cidr, n.revision, n.members, n.routes
                );
            }
        }
        NetworkCommand::Status { name, json } => {
            let network = network_by_name(&api, &name).await?;
            if json {
                let value: serde_json::Value = api
                    .get(&format!("/networks/{}", network.id))
                    .await
                    .map_err(explain)?;
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else {
                print_status(&status(&api, &network).await?);
            }
        }
        NetworkCommand::Join {
            name,
            member,
            role,
            endpoint,
            listen_port,
            public_key,
        } => {
            let role = role_from_str(&role)?;
            validate_name(&member)?;
            let endpoint = match (role, endpoint) {
                ("hub", Some(endpoint)) => Some(validate_endpoint(&endpoint)?),
                ("hub", None) => bail!("--endpoint host:port is required for the hub"),
                (_, Some(_)) => bail!("only the hub has an endpoint"),
                (_, None) => None,
            };
            ensure!(
                role == "hub" || listen_port.is_none(),
                "only the hub has a listen port"
            );
            if public_key.is_some() && role != "client" {
                bail!("gateways need their private key locally; enroll hubs and sites without --public-key");
            }
            let public_key = public_key.as_deref().map(PublicKey::parse).transpose()?;
            let network = network_by_name(&api, &name).await?;
            let paths = keys::member_paths(config_path, &network.id, &member)?;
            // Local files first: the control plane never learns a member this
            // device could not record. A pending record from an earlier attempt
            // whose answer was lost is resumed with its original key, never
            // replaced; a committed one is refused as before.
            let (state, private, fresh) = match keys::load_existing(&paths)? {
                Some(existing) if !existing.is_pending() => {
                    bail!("{member} is already enrolled locally ({}); run `pike network leave {name} --as {member}` first", paths.dir.display())
                }
                Some(pending) => {
                    let advice = pending_advice(&name, &member);
                    ensure!(
                        pending.role == role,
                        "the pending enrollment of {member} is a {}, not a {role}; {advice}",
                        pending.role
                    );
                    match (&public_key, pending.has_private_key) {
                        (None, true) => {}
                        (Some(given), false) => {
                            ensure!(
                                given.as_str() == pending.public_key,
                                "the pending enrollment of {member} holds public key {}; repeat --public-key with that key, or {advice}",
                                pending.public_key
                            );
                        }
                        (None, false) => bail!("the pending enrollment of {member} was started with --public-key {}; repeat it, or {advice}", pending.public_key),
                        (Some(_), true) => bail!("the pending enrollment of {member} has a locally generated private key; rerun join without --public-key, or {advice}"),
                    }
                    let private = if pending.has_private_key {
                        Some(keys::load_private_key(&paths)?)
                    } else {
                        None
                    };
                    eprintln!(
                        "resuming the pending enrollment of {member} (public key {})",
                        pending.public_key
                    );
                    (pending, private, false)
                }
                None => {
                    let (private, public) = match &public_key {
                        Some(key) => (None, key.clone()),
                        None => {
                            let (private, public) = keys::generate_keypair().await?;
                            (Some(private), public)
                        }
                    };
                    let placeholder = MemberState {
                        network_id: network.id.clone(),
                        network_name: network.name.clone(),
                        member_id: String::new(),
                        member_name: member.clone(),
                        role: role.to_owned(),
                        public_key: public.as_str().to_owned(),
                        has_private_key: private.is_some(),
                    };
                    keys::save_new(&paths, &placeholder, private.as_deref())?;
                    (placeholder, private, true)
                }
            };
            // Reconcile before enrolling again: the earlier attempt may have
            // been committed although this device never saw the answer.
            let mut found: Option<Member> = None;
            if !fresh {
                if let Some(remote) = remote_by_key(&api, &state).await.map_err(explain)? {
                    let advice = pending_advice(&name, &member);
                    ensure!(
                        remote.status == "active",
                        "the key of the pending enrollment of {member} was already revoked in {name} and can never re-enroll; discard it with `pike network leave {name} --as {member} --forget-local` and join again"
                    );
                    ensure!(
                        remote.name == member && remote.role == role,
                        "the key of the pending enrollment of {member} belongs to {} {} in {name}; refusing to adopt another member's identity. {advice}",
                        remote.role,
                        remote.name
                    );
                    eprintln!("the control plane had already recorded {member}; finishing the local record");
                    found = Some(remote);
                }
            }
            #[derive(serde::Deserialize)]
            struct Enrolled {
                member: Member,
                #[serde(default)]
                config: Option<MemberConfig>,
            }
            let (remote, config) = match found {
                Some(remote) => (remote, None),
                None => {
                    let mut body = serde_json::json!({ "name": member, "role": role, "public_key": state.public_key });
                    if let Some(endpoint) = &endpoint {
                        body["endpoint"] = serde_json::Value::String(endpoint.clone());
                    }
                    if let Some(port) = listen_port {
                        body["listen_port"] = serde_json::Value::from(port);
                    }
                    match api
                        .post::<Enrolled>(&format!("/networks/{}/members", network.id), &body)
                        .await
                    {
                        Ok(enrolled) => (enrolled.member, enrolled.config),
                        Err(error) if fresh && refused_definitively(&error) => {
                            // Refused outright: this brand-new key was never recorded, so it can go.
                            let _ = keys::remove(&paths);
                            return Err(explain(error));
                        }
                        Err(error) => {
                            // No answer, an unreadable one or a server failure may hide a
                            // committed enrollment; the only copy of the key stays put.
                            bail!(
                                "{error}; the enrollment of {member} may or may not have been recorded, so the local key and record were kept: {}",
                                pending_advice(&name, &member)
                            );
                        }
                    }
                }
            };
            let state = MemberState {
                member_id: remote.id.clone(),
                ..state
            };
            keys::rewrite_state(&paths, &state)?;
            eprintln!(
                "enrolled {} {} as {} with address {}; public key {}",
                role, member, remote.name, remote.address, remote.public_key
            );
            match role {
                "client" => {
                    let config = match config {
                        Some(config) => Ok(config),
                        None => member_config(&api, &network.id, &remote.id).await,
                    };
                    match config.and_then(|c| render_client(&c, private.as_deref())) {
                        Ok(rendered) => {
                            eprintln!("standard WireGuard configuration follows on stdout; it contains the private key");
                            print!("{rendered}");
                        }
                        Err(error) => eprintln!("configuration not printable yet: {error}; run `pike network config {name} --as {member}` later"),
                    }
                }
                "site" => eprintln!("run on this Linux host: pike network site {name} --as {member} --lan-if <interface>"),
                _ => eprintln!("run on this Linux host: pike network hub {name} --as {member}"),
            }
        }
        NetworkCommand::Config { name, member } => {
            let network = network_by_name(&api, &name).await?;
            let paths = keys::member_paths(config_path, &network.id, &member)?;
            let state = keys::load(&paths)?;
            keys::require_committed(&state)?;
            ensure!(state.role == "client", "only clients import a wg-quick configuration; gateways run `pike network hub|site`");
            let private = if state.has_private_key {
                Some(keys::load_private_key(&paths)?)
            } else {
                None
            };
            let config = member_config(&api, &network.id, &state.member_id).await?;
            print!("{}", render_client(&config, private.as_deref())?);
        }
        NetworkCommand::Leave {
            name,
            member,
            forget_local,
        } => {
            // Resolved from the local record, so a deleted network can still be
            // cleaned up. The local key is removed only when the control plane
            // confirms this device is revoked, or when the user asks for it
            // explicitly: a 404 also answers a key of another account or a
            // deleted network, and destroying the only private key of a
            // still-active member is never the default. For a pending record
            // one lookup that does not find the key proves nothing either:
            // the enrollment whose answer was lost may still be in flight and
            // commit after the lookup, so the key stays until --forget-local.
            let (paths, state) = keys::find_state(config_path, &name, &member)?;
            let target = if state.is_pending() {
                eprintln!("the enrollment of {member} is pending; checking whether the control plane recorded it");
                match remote_by_key(&api, &state).await {
                    Ok(Some(remote)) if remote.status != "active" => {
                        println!("{member} was already revoked");
                        Ok(None)
                    }
                    Ok(Some(remote)) if remote.name == member && remote.role == state.role => Ok(Some(remote.id)),
                    Ok(Some(remote)) => Err(anyhow!("the key of {member} belongs to {} {} in {name}; refusing to revoke another member", remote.role, remote.name)),
                    Ok(None) => Err(anyhow!(
                        "the control plane has no record of the key of {member} yet, but the enrollment whose answer was lost may still be in flight and land after this check, so there is nothing to revoke now. Finish it with `pike network join {name} --as {member}` and leave again, or discard the local key deliberately with --forget-local"
                    )),
                    Err(error) => Err(explain(error)),
                }
            } else {
                Ok(Some(state.member_id.clone()))
            };
            let confirmed = match target {
                Ok(None) => Ok(()),
                Ok(Some(member_id)) => match api
                    .delete::<serde_json::Value>(&format!(
                        "/networks/{}/members/{member_id}",
                        state.network_id
                    ))
                    .await
                {
                    Ok(_) => {
                        println!("revoked {member}");
                        Ok(())
                    }
                    // Only the owner's own member answers 409: it exists and is already revoked.
                    Err(ApiError::Rejected { status: 409, .. }) => {
                        println!("{member} was already revoked");
                        Ok(())
                    }
                    Err(error) => Err(explain(error)),
                },
                Err(error) => Err(error),
            };
            match confirmed {
                Ok(()) => {}
                Err(error) if forget_local => eprintln!("{error}; forgetting the local enrollment as requested. If the member is still active, revoke it with `pike network revoke {name} {member}`"),
                Err(error) => bail!(
                    "{error}; the local key and enrollment record for {member} were kept because the control plane did not confirm that this device is revoked. Retry with the owner's key, or run `pike network leave {name} --as {member} --forget-local` to discard them deliberately"
                ),
            }
            keys::remove(&paths)?;
            println!("removed local key and enrollment record for {member}");
        }
        NetworkCommand::Revoke { name, member } => {
            validate_name(&member)?;
            let network = network_by_name(&api, &name).await?;
            let current = status(&api, &network).await?;
            let target = active_member(&current, &member)?;
            api.delete::<serde_json::Value>(&format!(
                "/networks/{}/members/{}",
                network.id, target.id
            ))
            .await
            .map_err(explain)?;
            println!(
                "revoked {member}; the hub drops its peer, routes and grants within {}s",
                gateway::POLL.as_secs()
            );
        }
        NetworkCommand::Route { command } => match command {
            RouteCommand::Add { name, cidr, via } => {
                let cidr = parse_route_cidr(&cidr)?;
                validate_name(&via)?;
                let network = network_by_name(&api, &name).await?;
                let current = status(&api, &network).await?;
                let site = active_member(&current, &via)?;
                ensure!(site.role == "site", "{via} is not a site");
                api.post::<serde_json::Value>(
                    &format!("/networks/{}/routes", network.id),
                    &serde_json::json!({ "cidr": cidr.to_string(), "via": site.id }),
                )
                .await
                .map_err(explain)?;
                println!("route {cidr} is owned by {via}");
            }
            RouteCommand::Withdraw { name, cidr } => {
                let cidr = parse_route_cidr(&cidr)?;
                let network = network_by_name(&api, &name).await?;
                let current = status(&api, &network).await?;
                let route = current
                    .routes
                    .iter()
                    .find(|r| r.cidr == cidr.to_string())
                    .with_context(|| format!("route {cidr} not found"))?;
                api.delete::<serde_json::Value>(&format!(
                    "/networks/{}/routes/{}",
                    network.id, route.id
                ))
                .await
                .map_err(explain)?;
                println!("withdrew {cidr} and its grants");
            }
        },
        NetworkCommand::Grant { name, client, to } => {
            let cidr = parse_route_cidr(&to)?;
            validate_name(&client)?;
            let network = network_by_name(&api, &name).await?;
            let current = status(&api, &network).await?;
            let member = active_member(&current, &client)?;
            ensure!(member.role == "client", "{client} is not a client");
            api.post::<serde_json::Value>(
                &format!("/networks/{}/grants", network.id),
                &serde_json::json!({ "client": member.id, "cidr": cidr.to_string() }),
            )
            .await
            .map_err(explain)?;
            println!("{client} may reach {cidr}");
        }
        NetworkCommand::Ungrant { name, client, to } => {
            let cidr = parse_route_cidr(&to)?;
            validate_name(&client)?;
            let network = network_by_name(&api, &name).await?;
            let current = status(&api, &network).await?;
            let grant = current
                .grants
                .iter()
                .find(|g| {
                    g.client_name.as_deref() == Some(client.as_str())
                        && g.cidr.as_deref() == Some(cidr.to_string().as_str())
                })
                .with_context(|| format!("no grant from {client} to {cidr}"))?;
            api.delete::<serde_json::Value>(&format!(
                "/networks/{}/grants/{}",
                network.id, grant.id
            ))
            .await
            .map_err(explain)?;
            println!(
                "{client} can no longer reach {cidr}; live flows stop within {}s",
                gateway::LEASE.as_secs()
            );
        }
        NetworkCommand::Hub { name, member } => {
            let (state, private) = gateway_state(config_path, &name, &member, "hub")?;
            gateway::run(api, state, private, None).await?;
        }
        NetworkCommand::Site {
            name,
            member,
            lan_if,
        } => {
            validate_ifname(&lan_if)?;
            let (state, private) = gateway_state(config_path, &name, &member, "site")?;
            gateway::run(api, state, private, Some(lan_if)).await?;
        }
    }
    Ok(())
}

/// Gateways resolve their enrollment locally so a `networks:run`-only key suffices.
fn gateway_state(
    config_path: &Path,
    name: &str,
    member: &str,
    role: &str,
) -> Result<(MemberState, String)> {
    let (paths, state) = keys::find_state(config_path, name, member)?;
    keys::require_committed(&state)?;
    ensure!(
        state.role == role,
        "{member} is enrolled as a {}, not a {role}",
        state.role
    );
    let private = keys::load_private_key(&paths)?;
    Ok((state, private))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path as url_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: NetworkCommand,
    }

    const NET: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
    const MEMBER: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
    const PUBLIC: &str = "CLIENTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const OTHER_PUBLIC: &str = "OTHERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    /// Test constant only; the assertions compare bytes and never print it.
    const PRIVATE: &str = "cPrivateKeyIsNeverLoggedAAAAAAAAAAAAAAAAAAE=";

    fn api_config(server: &MockServer) -> Config {
        let mut config = Config::default();
        config.auth.api_key = Some("pk_live_test".into());
        config.relay.api_url = server.uri();
        config
    }

    fn network_json() -> serde_json::Value {
        json!({ "id": NET, "name": "lab", "client_cidr": "100.96.0.0/24", "revision": 3 })
    }

    fn member_json(name: &str, role: &str, key: &str, status: &str) -> serde_json::Value {
        json!({ "id": MEMBER, "name": name, "role": role, "public_key": key, "address": "100.96.0.4", "status": status })
    }

    fn status_json(members: Vec<serde_json::Value>) -> serde_json::Value {
        json!({ "network": network_json(), "members": members, "routes": [], "grants": [], "hub": null, "sites": [] })
    }

    /// A client configuration without a hub: valid JSON, but not printable,
    /// so no test ever writes a private key to its output.
    fn config_json() -> serde_json::Value {
        json!({ "network": network_json(), "member": { "id": MEMBER, "name": "c1", "address": "100.96.0.4", "public_key": PUBLIC }, "hub": null, "allowed_ips": ["100.96.0.0/24"], "mtu": 1420, "persistent_keepalive": 25 })
    }

    async fn mount_network_list(server: &MockServer) {
        Mock::given(method("GET"))
            .and(url_path("/api/v1/networks"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "networks": [network_json()] })),
            )
            .mount(server)
            .await;
    }

    async fn mount_status(server: &MockServer, members: Vec<serde_json::Value>) {
        Mock::given(method("GET"))
            .and(url_path(format!("/api/v1/networks/{NET}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(status_json(members)))
            .mount(server)
            .await;
    }

    fn join_as(member: &str, role: &str, public_key: Option<&str>) -> NetworkCommand {
        NetworkCommand::Join {
            name: "lab".into(),
            member: member.into(),
            role: role.into(),
            endpoint: None,
            listen_port: None,
            public_key: public_key.map(str::to_owned),
        }
    }

    fn join(member: &str, public_key: Option<&str>) -> NetworkCommand {
        join_as(member, "client", public_key)
    }

    fn leave(member: &str, forget_local: bool) -> NetworkCommand {
        NetworkCommand::Leave {
            name: "lab".into(),
            member: member.into(),
            forget_local,
        }
    }

    /// Write a local record as `join` would: pending when `member_id` is empty.
    fn seed(config_path: &Path, member_id: &str, private: Option<&str>) -> keys::MemberPaths {
        let paths = keys::member_paths(config_path, NET, "c1").unwrap();
        let state = MemberState {
            network_id: NET.into(),
            network_name: "lab".into(),
            member_id: member_id.into(),
            member_name: "c1".into(),
            role: "client".into(),
            public_key: PUBLIC.into(),
            has_private_key: private.is_some(),
        };
        keys::save_new(&paths, &state, private).unwrap();
        paths
    }

    fn key_bytes(paths: &keys::MemberPaths) -> Vec<u8> {
        std::fs::read(&paths.key).unwrap()
    }

    fn message(result: Result<()>) -> String {
        result.err().expect("the command must fail").to_string()
    }

    #[test]
    fn parses_subcommands() {
        let cli = Cli::try_parse_from([
            "pike",
            "join",
            "lab",
            "--as",
            "hub",
            "--role",
            "hub",
            "--endpoint",
            "203.0.113.5:51820",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, NetworkCommand::Join { ref name, ref member, ref role, endpoint: Some(_), listen_port: None, public_key: None } if name == "lab" && member == "hub" && role == "hub")
        );
        assert!(
            Cli::try_parse_from(["pike", "join", "lab", "--as", "c1", "--role", "owner"]).is_err()
        );
        let cli = Cli::try_parse_from(["pike", "leave", "lab", "--as", "c1"]).unwrap();
        assert!(matches!(
            cli.command,
            NetworkCommand::Leave {
                forget_local: false,
                ..
            }
        ));
        let cli =
            Cli::try_parse_from(["pike", "leave", "lab", "--as", "c1", "--forget-local"]).unwrap();
        assert!(matches!(
            cli.command,
            NetworkCommand::Leave {
                forget_local: true,
                ..
            }
        ));
        let cli = Cli::try_parse_from([
            "pike",
            "route",
            "add",
            "lab",
            "10.10.0.0/24",
            "--via",
            "site-a",
        ])
        .unwrap();
        assert!(
            matches!(cli.command, NetworkCommand::Route { command: RouteCommand::Add { ref via, .. } } if via == "site-a")
        );
        let cli =
            Cli::try_parse_from(["pike", "site", "lab", "--as", "site-a", "--lan-if", "eth1"])
                .unwrap();
        assert!(matches!(cli.command, NetworkCommand::Site { ref lan_if, .. } if lan_if == "eth1"));
        let cli = Cli::try_parse_from([
            "pike",
            "ungrant",
            "lab",
            "--client",
            "c1",
            "--to",
            "10.10.0.0/24",
        ])
        .unwrap();
        assert!(matches!(cli.command, NetworkCommand::Ungrant { .. }));
        assert!(Cli::try_parse_from(["pike", "create", "lab"]).is_err());
    }

    #[test]
    fn client_configuration_needs_a_hub() {
        let config = MemberConfig {
            network: Network {
                id: "0f8fad5b-d9cb-469f-a165-70867728950e".into(),
                name: "lab".into(),
                client_cidr: "100.96.0.0/24".into(),
                revision: 3,
            },
            member: api::ConfigMember {
                id: "7c9e6679-7425-40de-944b-e07fc1f90ae7".into(),
                name: "c1".into(),
                address: "100.96.0.4".into(),
                public_key: "CLIENTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            },
            hub: None,
            allowed_ips: vec!["100.96.0.0/24".into()],
            mtu: 1420,
            persistent_keepalive: 25,
        };
        assert!(render_client(&config, None)
            .unwrap_err()
            .to_string()
            .contains("no active hub"));
        let with_hub = MemberConfig {
            hub: Some(api::HubPeer {
                public_key: "HUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                endpoint: Some("hub.example.test:51820".into()),
                address: "100.96.0.1".into(),
            }),
            ..config
        };
        let rendered = render_client(&with_hub, None).unwrap();
        assert!(rendered.contains("Endpoint = hub.example.test:51820\n"));
        assert!(rendered.contains("PrivateKey = <replace-with-the-device-private-key>\n"));
    }

    /// The control plane may commit an enrollment and still fail to deliver
    /// the answer (timeout, truncated or unreadable body, 5xx after commit).
    /// The pending record and key must survive every such outcome.
    #[tokio::test]
    async fn join_keeps_a_new_record_when_the_enrollment_answer_is_lost() {
        for response in [
            ResponseTemplate::new(200).set_body_string("{\"member\": tru"),
            ResponseTemplate::new(500)
                .set_body_json(json!({ "error": "Private network operation failed" })),
            ResponseTemplate::new(503)
                .set_body_json(json!({ "error": "Address allocation raced; retry" })),
        ] {
            let server = MockServer::start().await;
            mount_network_list(&server).await;
            Mock::given(method("POST"))
                .and(url_path(format!("/api/v1/networks/{NET}/members")))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            let temp = tempfile::TempDir::new().unwrap();
            let config_path = temp.path().join("config.toml");
            let error =
                message(run(&api_config(&server), &config_path, join("c1", Some(PUBLIC))).await);
            assert!(
                error.contains("may or may not have been recorded")
                    && error.contains("--forget-local"),
                "{error}"
            );
            let paths = keys::member_paths(&config_path, NET, "c1").unwrap();
            let state = keys::load(&paths).unwrap();
            assert!(
                state.is_pending(),
                "the record stays pending until the control plane confirms it"
            );
            assert_eq!(state.public_key, PUBLIC);
            // The pending record is found by name, so `leave` and a retried `join` can reach it.
            assert!(keys::find_state(&config_path, "lab", "c1")
                .unwrap()
                .1
                .is_pending());
        }
    }

    #[tokio::test]
    async fn join_removes_a_new_record_only_on_a_definitive_refusal() {
        let server = MockServer::start().await;
        mount_network_list(&server).await;
        Mock::given(method("POST"))
            .and(url_path(format!("/api/v1/networks/{NET}/members")))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(json!({ "error": "An active member already uses this name" })),
            )
            .mount(&server)
            .await;
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        let error =
            message(run(&api_config(&server), &config_path, join("c1", Some(PUBLIC))).await);
        assert!(
            error.contains("409") && error.contains("already uses this name"),
            "{error}"
        );
        let paths = keys::member_paths(&config_path, NET, "c1").unwrap();
        assert!(
            !paths.state.exists() && !paths.key.exists(),
            "a refused brand-new key leaves nothing behind"
        );
        // The same refusal for a resumed record keeps it: the user decides.
        seed(&config_path, "", Some(PRIVATE));
        mount_status(&server, vec![]).await;
        let error = message(run(&api_config(&server), &config_path, join("c1", None)).await);
        assert!(
            error.contains("409") && error.contains("were kept"),
            "{error}"
        );
        assert!(paths.state.exists() && paths.key.exists());
    }

    /// Committed but the answer was lost: the retry finds the member by public
    /// key, checks name and role, reuses the original private key and only
    /// completes the local record. No second enrollment is attempted.
    #[tokio::test]
    async fn a_retried_join_finishes_a_committed_enrollment_with_the_original_key() {
        let server = MockServer::start().await;
        mount_network_list(&server).await;
        mount_status(&server, vec![member_json("c1", "client", PUBLIC, "active")]).await;
        Mock::given(method("GET"))
            .and(url_path(format!(
                "/api/v1/networks/{NET}/members/{MEMBER}/config"
            )))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "config": config_json() })),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(url_path(format!("/api/v1/networks/{NET}/members")))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        let paths = seed(&config_path, "", Some(PRIVATE));
        let before = key_bytes(&paths);
        run(&api_config(&server), &config_path, join("c1", None))
            .await
            .unwrap();
        let state = keys::load(&paths).unwrap();
        assert!(!state.is_pending());
        assert_eq!(state.member_id, MEMBER);
        assert_eq!(state.public_key, PUBLIC);
        assert!(
            key_bytes(&paths) == before,
            "the private key is reused byte for byte, never rotated"
        );
        assert!(!paths.state.with_extension("json.tmp").exists());
        // Now committed: a third join is refused instead of resumed.
        let error = message(run(&api_config(&server), &config_path, join("c1", None)).await);
        assert!(error.contains("already enrolled locally"), "{error}");
    }

    /// Never committed (for example the request never arrived): the retry
    /// enrolls the very same public key instead of generating a new one.
    #[tokio::test]
    async fn a_retried_join_enrolls_an_unrecorded_pending_key_without_rotating_it() {
        let server = MockServer::start().await;
        mount_network_list(&server).await;
        mount_status(&server, vec![]).await;
        Mock::given(method("POST"))
            .and(url_path(format!("/api/v1/networks/{NET}/members")))
            .and(body_partial_json(json!({ "name": "c1", "role": "client", "public_key": PUBLIC })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "member": member_json("c1", "client", PUBLIC, "active"), "config": config_json() })))
            .expect(1)
            .mount(&server)
            .await;
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        let paths = seed(&config_path, "", Some(PRIVATE));
        let before = key_bytes(&paths);
        run(&api_config(&server), &config_path, join("c1", None))
            .await
            .unwrap();
        assert_eq!(keys::load(&paths).unwrap().member_id, MEMBER);
        assert!(key_bytes(&paths) == before);
    }

    #[tokio::test]
    async fn a_retried_join_never_adopts_another_identity_or_a_spent_key() {
        let server = MockServer::start().await;
        mount_network_list(&server).await;
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        let paths = seed(&config_path, "", Some(PRIVATE));
        let before = key_bytes(&paths);
        // The key is enrolled under another name.
        mount_status(&server, vec![member_json("c9", "client", PUBLIC, "active")]).await;
        let error = message(run(&api_config(&server), &config_path, join("c1", None)).await);
        assert!(error.contains("refusing to adopt"), "{error}");
        // The key was revoked meanwhile: it can never re-enroll.
        server.reset().await;
        mount_network_list(&server).await;
        mount_status(
            &server,
            vec![member_json("c1", "client", PUBLIC, "revoked")],
        )
        .await;
        let error = message(run(&api_config(&server), &config_path, join("c1", None)).await);
        assert!(
            error.contains("already revoked") && error.contains("--forget-local"),
            "{error}"
        );
        // Arguments that would swap the key are refused before any request.
        let error = message(
            run(
                &api_config(&server),
                &config_path,
                join("c1", Some(OTHER_PUBLIC)),
            )
            .await,
        );
        assert!(error.contains("without --public-key"), "{error}");
        let error = message(
            run(
                &api_config(&server),
                &config_path,
                join_as("c1", "site", None),
            )
            .await,
        );
        assert!(error.contains("not a site"), "{error}");
        assert!(
            paths.state.exists() && key_bytes(&paths) == before,
            "every refusal keeps the pending key"
        );
        // A pending record enrolled with --public-key needs that same key again.
        keys::remove(&paths).unwrap();
        seed(&config_path, "", None);
        let error = message(run(&api_config(&server), &config_path, join("c1", None)).await);
        assert!(error.contains("repeat it"), "{error}");
        let error = message(
            run(
                &api_config(&server),
                &config_path,
                join("c1", Some(OTHER_PUBLIC)),
            )
            .await,
        );
        assert!(error.contains("repeat --public-key"), "{error}");
        assert!(paths.state.exists());
    }

    /// A 404 also answers a deleted network, a key of another account or a
    /// typo in the profile: the only private key is never destroyed on it.
    #[tokio::test]
    async fn leave_keeps_the_key_on_an_unconfirmed_404_and_forgets_only_on_request() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(url_path(format!("/api/v1/networks/{NET}/members/{MEMBER}")))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "error": "Network not found" })),
            )
            .mount(&server)
            .await;
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        let paths = seed(&config_path, MEMBER, Some(PRIVATE));
        let before = key_bytes(&paths);
        let error = message(run(&api_config(&server), &config_path, leave("c1", false)).await);
        assert!(
            error.contains("404")
                && error.contains("were kept")
                && error.contains("--forget-local"),
            "{error}"
        );
        assert!(
            paths.state.exists() && key_bytes(&paths) == before,
            "key bytes are untouched after the wrong-account 404"
        );
        // A server failure is just as ambiguous.
        server.reset().await;
        Mock::given(method("DELETE"))
            .and(url_path(format!("/api/v1/networks/{NET}/members/{MEMBER}")))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_json(json!({ "error": "Private network operation failed" })),
            )
            .mount(&server)
            .await;
        let error = message(run(&api_config(&server), &config_path, leave("c1", false)).await);
        assert!(error.contains("were kept"), "{error}");
        assert!(key_bytes(&paths) == before);
        // Deliberate cleanup of a deleted network or stale enrollment.
        server.reset().await;
        Mock::given(method("DELETE"))
            .and(url_path(format!("/api/v1/networks/{NET}/members/{MEMBER}")))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "error": "Network not found" })),
            )
            .mount(&server)
            .await;
        run(&api_config(&server), &config_path, leave("c1", true))
            .await
            .unwrap();
        assert!(!paths.state.exists() && !paths.key.exists() && !paths.dir.exists());
    }

    #[tokio::test]
    async fn leave_removes_the_key_once_the_owner_confirms_the_revocation() {
        for (status, body) in [
            (
                200u16,
                json!({ "revoked": true, "member_id": MEMBER, "revision": 4 }),
            ),
            (409u16, json!({ "error": "Member is already revoked" })),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("DELETE"))
                .and(url_path(format!("/api/v1/networks/{NET}/members/{MEMBER}")))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
            let temp = tempfile::TempDir::new().unwrap();
            let config_path = temp.path().join("config.toml");
            let paths = seed(&config_path, MEMBER, Some(PRIVATE));
            run(&api_config(&server), &config_path, leave("c1", false))
                .await
                .unwrap();
            assert!(
                !paths.state.exists() && !paths.key.exists(),
                "status {status}"
            );
        }
    }

    /// A pending record has no member id; `leave` reconciles by public key so
    /// a committed-but-unanswered enrollment is revoked rather than orphaned,
    /// and an enrollment the lookup does not find yet is left to land.
    #[tokio::test]
    async fn leave_on_a_pending_record_reconciles_by_key_before_touching_the_file() {
        let server = MockServer::start().await;
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        // Recorded and active: revoke it, then remove the local files.
        mount_status(&server, vec![member_json("c1", "client", PUBLIC, "active")]).await;
        Mock::given(method("DELETE"))
            .and(url_path(format!("/api/v1/networks/{NET}/members/{MEMBER}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "revoked": true })))
            .mount(&server)
            .await;
        let paths = seed(&config_path, "", Some(PRIVATE));
        run(&api_config(&server), &config_path, leave("c1", false))
            .await
            .unwrap();
        assert!(!paths.state.exists() && !paths.key.exists());
        let deletes = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "DELETE")
            .count();
        assert_eq!(
            deletes, 1,
            "the committed member found by key was revoked exactly once"
        );
        // Not recorded at the time of the lookup: the unanswered enrollment may
        // still be in flight and commit after this check, so nothing is
        // revoked and the key stays byte for byte until --forget-local.
        server.reset().await;
        mount_status(&server, vec![]).await;
        seed(&config_path, "", Some(PRIVATE));
        let before = key_bytes(&paths);
        let error = message(run(&api_config(&server), &config_path, leave("c1", false)).await);
        assert!(
            error.contains("still be in flight")
                && error.contains("were kept")
                && error.contains("--forget-local"),
            "{error}"
        );
        assert!(
            paths.state.exists() && key_bytes(&paths) == before,
            "an absent lookup keeps the pending key and record"
        );
        assert!(
            keys::load(&paths).unwrap().is_pending(),
            "the record stays pending"
        );
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.method.as_str() == "DELETE")
                .count(),
            0,
            "nothing was revoked on an absent lookup"
        );
        run(&api_config(&server), &config_path, leave("c1", true))
            .await
            .unwrap();
        assert!(
            !paths.state.exists() && !paths.key.exists(),
            "only the explicit request discards them"
        );
        // Held by another member: refused, kept.
        server.reset().await;
        mount_status(&server, vec![member_json("c9", "client", PUBLIC, "active")]).await;
        seed(&config_path, "", Some(PRIVATE));
        let error = message(run(&api_config(&server), &config_path, leave("c1", false)).await);
        assert!(
            error.contains("refusing to revoke another member") && error.contains("were kept"),
            "{error}"
        );
        assert!(paths.state.exists() && paths.key.exists());
        // The network is gone or belongs to someone else: kept without --forget-local.
        server.reset().await;
        Mock::given(method("GET"))
            .and(url_path(format!("/api/v1/networks/{NET}")))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "error": "Network not found" })),
            )
            .mount(&server)
            .await;
        let error = message(run(&api_config(&server), &config_path, leave("c1", false)).await);
        assert!(
            error.contains("404") && error.contains("were kept"),
            "{error}"
        );
        assert!(paths.key.exists());
        run(&api_config(&server), &config_path, leave("c1", true))
            .await
            .unwrap();
        assert!(!paths.state.exists() && !paths.key.exists());
    }

    #[test]
    fn pending_records_block_gateways_and_config_with_the_recovery_advice() {
        let temp = tempfile::TempDir::new().unwrap();
        let config_path = temp.path().join("config.toml");
        seed(&config_path, "", Some(PRIVATE));
        let error = gateway_state(&config_path, "lab", "c1", "client")
            .err()
            .expect("a pending record cannot run a gateway")
            .to_string();
        assert!(
            error.contains("pending")
                && error.contains("join lab --as c1")
                && error.contains("--forget-local"),
            "{error}"
        );
    }
}
