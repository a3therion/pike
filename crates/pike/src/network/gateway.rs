//! Linux hub and site gateways. The gateway owns exactly one WireGuard
//! interface, one nft table and the rtproto-250 routes on that interface, all
//! named after the network. Every poll re-fetches authenticated state and
//! recreates the kernel authorization elements with a timeout counted from
//! the start of that fetch, so a hung control plane, a revoked key or a
//! SIGKILLed agent lets forwarding expire in the kernel within LEASE.
//!
//! Ordering rules that keep the kernel closed at every instant:
//! - an existing interface is adopted only when `wg show` proves it holds this
//!   member's key, an existing table only when it carries this member's owner
//!   marker; both are probed read-only before either is mutated, and anything
//!   else, or any unreadable probe, is refused with nothing installed;
//! - the owner-marked, default-deny table is then installed (atomically
//!   replaced) before the interface is created or adopted and before its
//!   peers or address are set;
//! - before peers or kernel routes change, authorization is emptied outright;
//!   the full new authorization is installed only after the new identities
//!   are in the kernel. A `(client, route)` or route element is a plain
//!   number pair and cannot tell a revoked key from its successor on the same
//!   /32 or CIDR, so nothing is ever carried across an identity change, at
//!   the price of a short forwarding gap on every peer or route change;
//! - every `nft` transaction, including its stdin, runs inside a fixed budget
//!   that is deducted from the element timeout, so elements never outlive
//!   fetch start + LEASE even if nft stalls; on Linux every child is also
//!   bound to this process with a parent-death SIGKILL armed before exec, so
//!   a stalled or stopped nft cannot commit after the gateway itself is
//!   SIGKILLed;
//! - existence is only ever read from a complete machine-readable inventory;
//!   a failed or unreadable inventory is unknown, never absence, and nothing
//!   unowned is touched while anything is unknown;
//! - teardown flushes authorization, removes the interface and deletes the
//!   table last; unless the interface is confirmed gone the table stays.
//!
//! Nothing global is ever flushed, replaced or forwarded.
use super::api::{Api, ApiError, Desired, PeerReport, StatusReport};
use super::keys::{self, MemberState};
use super::model::{
    owned_names, parse_client_cidr, parse_route_cidr, validate_endpoint, validate_ifname, Cidr,
    PublicKey,
};
use super::render::{self, WgPeer};
use anyhow::{anyhow, bail, ensure, Context, Result};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::{Duration, Instant};

pub const LEASE: Duration = Duration::from_secs(30);
pub const POLL: Duration = Duration::from_secs(10);
/// Bound for wg and ip subprocesses.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound for one `nft -f` transaction including writing its stdin. A stalled
/// nft is killed at this point, so no element can be committed later.
const NFT_BUDGET: Duration = Duration::from_secs(3);
/// Extra margin for signal delivery and second rounding of element timeouts.
const INSTALL_SLACK: Duration = Duration::from_secs(1);
const MAX_PEERS: usize = 64;
const MAX_ROUTES: usize = 32;
const MAX_GRANTS: usize = 256;

fn now() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// Bind a child to the process that spawns it. On Linux the child asks the
/// kernel, between fork and exec, for SIGKILL when its parent dies, so an nft
/// that is still running, stalled or stopped when the gateway is SIGKILLed
/// dies with it instead of committing later; SIGKILL also ends a stopped
/// process. The budget and `kill_on_drop` still cover a live parent. The
/// child arms the signal itself, so a parent that died between the fork and
/// the prctl would leave an orphan armed against nobody; the child therefore
/// compares its parent pid with the pid recorded before the fork and refuses
/// to exec when they differ. The signal is tied to the spawning thread, which
/// here is a runtime worker thread that lives as long as the process. Other
/// platforms run no gateway and get no guard.
pub(super) fn die_with_parent(command: &mut tokio::process::Command) {
    #[cfg(target_os = "linux")]
    {
        bind_child(command, std::process::id());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn bind_child(command: &mut tokio::process::Command, parent: u32) {
    // SAFETY: the closure runs in the forked child before exec and performs
    // only the async-signal-safe calls in `arm_death_signal`; it allocates
    // nothing and touches no lock.
    unsafe {
        command.pre_exec(move || arm_death_signal(parent));
    }
}

/// Runs in the child between fork and exec: arm the parent-death SIGKILL,
/// then prove the recorded parent is still the parent. Non-allocating.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn arm_death_signal(parent: u32) -> std::io::Result<()> {
    // SAFETY: plain system calls with constant arguments and no pointers.
    let armed = unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::c_ulong::from(libc::SIGKILL.unsigned_abs()),
            0,
            0,
            0,
        )
    };
    if armed != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: getppid has no preconditions.
    let current = unsafe { libc::getppid() };
    if current != libc::pid_t::try_from(parent).unwrap_or(-1) {
        // The parent died before the signal was armed: there is nobody left
        // to be bound to, so this child must not run at all.
        return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

/// Run one subprocess with the whole interaction (spawn, stdin, exit) bounded
/// by `budget`; on timeout the child is killed. Arguments are passed as a
/// vector, never through a shell. When `secret` is set, stderr is not reported.
async fn exec_within(
    budget: Duration,
    program: &str,
    args: &[&str],
    stdin: Option<&str>,
    secret: bool,
) -> Result<String> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    die_with_parent(&mut command);
    let mut child = command.spawn().with_context(|| {
        format!("failed to start {program}; install wireguard-tools, nftables and iproute2")
    })?;
    let interaction = async {
        if let Some(input) = stdin {
            if let Some(mut pipe) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                pipe.write_all(input.as_bytes()).await?;
                pipe.shutdown().await?;
            }
        }
        child.wait_with_output().await.map_err(anyhow::Error::from)
    };
    let output = tokio::time::timeout(budget, interaction)
        .await
        .map_err(|_| {
            anyhow!(
                "{program} {} timed out after {}s and was killed",
                args.first().unwrap_or(&""),
                budget.as_secs()
            )
        })??;
    if !output.status.success() {
        if secret {
            bail!(
                "{program} {} failed ({})",
                args.first().unwrap_or(&""),
                output.status
            );
        }
        let stderr: String = String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(400)
            .collect();
        bail!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

async fn exec(program: &str, args: &[&str], stdin: Option<&str>, secret: bool) -> Result<String> {
    exec_within(COMMAND_TIMEOUT, program, args, stdin, secret).await
}

/// Whether `ifname` is present, read from the complete machine-readable link
/// inventory. A failed command or unreadable output is an error, never an
/// absence.
async fn interface_exists(ifname: &str) -> Result<bool> {
    let inventory = exec("ip", &["-j", "link", "show"], None, false).await?;
    link_present(&inventory, ifname)
}

fn link_present(inventory: &str, ifname: &str) -> Result<bool> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(inventory).context("unexpected ip link output")?;
    Ok(rows
        .iter()
        .any(|row| row.get("ifname").and_then(|v| v.as_str()) == Some(ifname)))
}

/// JSON listing of the named table: Some when the complete table inventory
/// names it and it could be listed, None when the inventory proves it absent.
/// A failed command or unreadable output at either step is an error.
async fn table_listing(table: &str) -> Result<Option<String>> {
    let inventory = exec("nft", &["-j", "list", "tables"], None, false).await?;
    if !table_present(&inventory, table)? {
        return Ok(None);
    }
    exec("nft", &["-j", "list", "table", "inet", table], None, false)
        .await
        .map(Some)
}

fn table_present(inventory: &str, table: &str) -> Result<bool> {
    let value: serde_json::Value =
        serde_json::from_str(inventory).context("unexpected nft list tables output")?;
    let items = value
        .get("nftables")
        .and_then(|v| v.as_array())
        .context("unexpected nft list tables output")?;
    Ok(items.iter().any(|item| {
        item.get("table").is_some_and(|t| {
            t.get("family").and_then(|v| v.as_str()) == Some("inet")
                && t.get("name").and_then(|v| v.as_str()) == Some(table)
        })
    }))
}

/// True only when the listed table carries this member's owner marker. A
/// table without the exact marker, however it is named, is never ours.
fn table_owned_by(listing: &str, table: &str, marker: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(listing) else {
        return false;
    };
    value
        .get("nftables")
        .and_then(|v| v.as_array())
        .is_some_and(|items| {
            items.iter().any(|item| {
                let Some(counter) = item.get("counter") else {
                    return false;
                };
                let text = |key: &str| counter.get(key).and_then(|v| v.as_str());
                text("family") == Some("inet")
                    && text("table") == Some(table)
                    && text("name") == Some(marker)
            })
        })
}

/// Element timeout for state fetched `elapsed` ago: what remains of LEASE
/// after the nft budget and slack are deducted, so an element committed at
/// the very end of the budget still expires before fetch start + LEASE.
/// None means the state is too old to apply.
fn element_timeout(elapsed: Duration) -> Option<u64> {
    let remaining = LEASE
        .checked_sub(elapsed)?
        .checked_sub(NFT_BUDGET)?
        .checked_sub(INSTALL_SLACK)?
        .as_secs();
    (remaining >= 1).then_some(remaining)
}

/// One IPv4 route of the main table as reported by `ip -j route`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteEntry {
    dst: Cidr,
    dev: Option<String>,
    proto: Option<String>,
}

fn parse_route_inventory(json: &str) -> Result<Vec<RouteEntry>> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(json).context("unexpected ip route output")?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let dst = row.get("dst")?.as_str()?;
            if dst == "default" {
                return None;
            }
            let text = if dst.contains('/') {
                dst.to_owned()
            } else {
                format!("{dst}/32")
            };
            let text_of = |key: &str| row.get(key).and_then(|v| v.as_str()).map(str::to_owned);
            Some(RouteEntry {
                dst: text.parse().ok()?,
                dev: text_of("dev"),
                proto: text_of("protocol"),
            })
        })
        .collect())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RouteActions {
    add: BTreeSet<Cidr>,
    del: BTreeSet<Cidr>,
}

/// Decide route changes from an inventory. Only routes on our interface with
/// our rtproto are ours: stale ones are deleted, missing desired ones added.
/// A desired prefix already routed by anything else is a conflict; it is
/// refused, never replaced.
fn route_actions(
    inventory: &[RouteEntry],
    desired: &BTreeSet<Cidr>,
    ifname: &str,
) -> Result<RouteActions> {
    let mut owned = BTreeSet::new();
    for entry in inventory {
        if entry.dev.as_deref() == Some(ifname)
            && entry.proto.as_deref() == Some(render::ROUTE_PROTO)
        {
            owned.insert(entry.dst);
        } else if desired.contains(&entry.dst) {
            bail!(
                "route {} already exists in the main table (dev {} proto {}); refusing to replace a route this gateway does not own. Withdraw the Pike route or remove the conflicting one",
                entry.dst,
                entry.dev.as_deref().unwrap_or("?"),
                entry.proto.as_deref().unwrap_or("?")
            );
        }
    }
    Ok(RouteActions {
        add: desired.difference(&owned).copied().collect(),
        del: owned.difference(desired).copied().collect(),
    })
}

/// What the kernel may forward: hub `(client, route)` pairs or site routes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Authorization {
    grants: BTreeSet<(Ipv4Addr, Cidr)>,
    routes: BTreeSet<Cidr>,
}

impl Authorization {
    fn len(&self) -> usize {
        self.grants.len() + self.routes.len()
    }
}

/// The ordered kernel operations one apply performs. Computed without side
/// effects so the ordering rule is testable: whenever the peer set or the
/// kernel routes differ from what is applied, every authorization element is
/// removed first, the identities are changed, and only then is the new
/// authorization installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// Remove every live authorization element.
    FlushAuthorization,
    /// `wg syncconf` with the new peer set.
    SyncPeers,
    /// Reconcile the rtproto-250 routes on the interface.
    ReconcileRoutes,
    /// Install the full, validated authorization of the new state.
    InstallAuthorization,
}

/// The ordered teardown operations, decided from what the inventory could
/// confirm about the interface: Some(true) present, Some(false) absent, None
/// unknown. The table is the last line of defence and is deleted only once
/// the interface is confirmed gone; while that is unknown, or while an
/// interface this run does not own is present, it stays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cleanup {
    RemoveInterface,
    DeleteTable,
    KeepTable,
}

fn cleanup_steps(owns_interface: bool, owns_table: bool, interface: Option<bool>) -> Vec<Cleanup> {
    let mut steps = Vec::with_capacity(2);
    match (owns_interface, interface) {
        (_, Some(false)) => {}
        (true, Some(true)) => steps.push(Cleanup::RemoveInterface),
        // Unknown, or present but never verified as ours (a setup that failed
        // before adoption): neither touched nor exposed.
        (_, None) | (false, Some(true)) => {
            if owns_table {
                steps.push(Cleanup::KeepTable);
            }
            return steps;
        }
    }
    if owns_table {
        steps.push(Cleanup::DeleteTable);
    }
    steps
}

fn change_steps(
    applied_wg: Option<&str>,
    applied_routes: &BTreeSet<Cidr>,
    plan: &Plan,
) -> Vec<Step> {
    let peers_changed = applied_wg != Some(plan.wg_conf.as_str());
    let routes_changed = *applied_routes != plan.kernel_routes;
    let mut steps = Vec::with_capacity(4);
    if peers_changed || routes_changed {
        steps.push(Step::FlushAuthorization);
    }
    if peers_changed {
        steps.push(Step::SyncPeers);
    }
    if routes_changed {
        steps.push(Step::ReconcileRoutes);
    }
    steps.push(Step::InstallAuthorization);
    steps
}

struct Plan {
    revision: u64,
    address: Ipv4Addr,
    pool: Cidr,
    wg_conf: String,
    /// Hub: every site route, installed on the interface with rtproto 250.
    kernel_routes: BTreeSet<Cidr>,
    authorization: Authorization,
    peers: usize,
}

pub struct Gateway {
    api: Api,
    state: MemberState,
    private_key: String,
    ifname: String,
    table: String,
    /// Counter object name proving the table was created by this member.
    owner: String,
    lan_if: Option<String>,
    /// Set only when this run created the resource or positively verified
    /// that it belongs to this member. Teardown touches nothing else.
    owns_interface: bool,
    owns_table: bool,
    /// Peer configuration known to be in the kernel; None while unknown or
    /// mid-change, which forces the next apply to treat peers as changed.
    applied_wg: Option<String>,
    applied_routes: BTreeSet<Cidr>,
    applied_revision: Option<u64>,
    reported_failure: bool,
}

pub async fn run(
    api: Api,
    state: MemberState,
    private_key: String,
    lan_if: Option<String>,
) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "hub and site gateways run on Linux only; other systems import the printed WireGuard client configuration"
    );
    match (state.role.as_str(), &lan_if) {
        ("hub", None) | ("site", Some(_)) => {}
        ("hub", Some(_)) => bail!("the hub has no LAN interface"),
        ("site", None) => bail!("a site needs --lan-if"),
        _ => bail!("only hub and site members run a gateway"),
    }
    let (ifname, table) = owned_names(&state.network_id)?;
    let derived = keys::public_key_of(&private_key).await?;
    ensure!(
        derived.as_str() == state.public_key,
        "local private key does not match the enrolled public key"
    );
    if let Some(lan) = &lan_if {
        validate_ifname(lan)?;
        ensure!(
            lan != &ifname,
            "the LAN interface cannot be the Pike interface"
        );
        ensure!(
            interface_exists(lan).await?,
            "LAN interface {lan} does not exist"
        );
    }
    exec("wg", &["--version"], None, false).await?;
    exec("nft", &["--version"], None, false).await?;
    exec("ip", &["-V"], None, false).await?;
    let forwarding = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default();
    ensure!(
        forwarding.trim() == "1",
        "IPv4 forwarding is disabled; the operator must enable it (sysctl -w net.ipv4.ip_forward=1)"
    );
    let owner = render::owner_marker(&state.member_id);
    let mut gateway = Gateway {
        api,
        state,
        private_key,
        ifname,
        table,
        owner,
        lan_if,
        owns_interface: false,
        owns_table: false,
        applied_wg: None,
        applied_routes: BTreeSet::new(),
        applied_revision: None,
        reported_failure: false,
    };
    // Authenticated fresh state comes first: a refused credential or a deleted
    // network never creates kernel resources.
    let started = Instant::now();
    let desired = gateway.fetch().await.map_err(anyhow::Error::from)?;
    let plan = gateway.plan(&desired)?;
    let result = match gateway.setup(&plan).await {
        Ok(()) => match gateway.apply(&plan, started).await {
            Ok(()) => gateway.serve().await,
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    // Only resources this run created or proved to own are removed; a refusal
    // during setup leaves the foreign interface, key and table exactly as found.
    gateway.teardown().await;
    result
}

impl Gateway {
    async fn fetch(&self) -> Result<Desired, ApiError> {
        self.api
            .get(&format!(
                "/networks/{}/members/{}/desired",
                self.state.network_id, self.state.member_id
            ))
            .await
    }

    /// Validate every value the control plane sent before rendering anything.
    fn plan(&self, desired: &Desired) -> Result<Plan> {
        ensure!(
            desired.protocol == 1,
            "unsupported desired-state protocol {}",
            desired.protocol
        );
        ensure!(
            desired.this.id == self.state.member_id && desired.this.role == self.state.role,
            "desired state is for another member"
        );
        ensure!(
            desired.this.public_key == self.state.public_key,
            "desired state carries a different public key"
        );
        ensure!(
            desired.network.id == self.state.network_id,
            "desired state is for another network"
        );
        ensure!(
            desired.lease_seconds <= LEASE.as_secs(),
            "control plane lease exceeds the local bound"
        );
        let pool = parse_client_cidr(&desired.network.client_cidr)?;
        let address: Ipv4Addr = desired
            .this
            .address
            .parse()
            .context("invalid own address")?;
        ensure!(
            pool.contains(address),
            "own address is outside the client pool"
        );
        if self.state.role == "hub" {
            let listen_port = desired
                .this
                .listen_port
                .filter(|p| *p > 0)
                .context("hub listen port missing")?;
            ensure!(
                desired.peers.len() <= MAX_PEERS && desired.grants.len() <= MAX_GRANTS,
                "desired state exceeds bounds"
            );
            let mut peers = Vec::with_capacity(desired.peers.len());
            let mut clients = BTreeSet::new();
            let mut routes = BTreeSet::new();
            let mut seen_keys = BTreeSet::new();
            for peer in &desired.peers {
                let key = PublicKey::parse(&peer.public_key)?;
                ensure!(
                    key.as_str() != self.state.public_key
                        && seen_keys.insert(key.as_str().to_owned()),
                    "duplicate or own key among peers"
                );
                let peer_address: Ipv4Addr =
                    peer.address.parse().context("invalid peer address")?;
                ensure!(
                    pool.contains(peer_address) && peer_address != address,
                    "peer address outside the pool"
                );
                let allowed: Vec<Cidr> = peer
                    .allowed_ips
                    .iter()
                    .map(|c| c.parse())
                    .collect::<Result<_>>()?;
                ensure!(
                    allowed.first() == Some(&Cidr::new(peer_address, 32)?),
                    "peer allowed IPs must start with its own /32"
                );
                match peer.role.as_str() {
                    "client" => {
                        ensure!(allowed.len() == 1, "client peers are bound to one /32");
                        clients.insert(peer_address);
                    }
                    "site" => {
                        ensure!(
                            allowed.len() <= 1 + MAX_ROUTES,
                            "site route count exceeds bounds"
                        );
                        for route in &allowed[1..] {
                            let route = parse_route_cidr(&route.to_string())?;
                            ensure!(
                                !(route.contains(pool.address) || pool.contains(route.address)),
                                "site route overlaps the client pool"
                            );
                            ensure!(routes.insert(route), "duplicate route among sites");
                        }
                    }
                    _ => bail!("unexpected peer role {}", peer.role),
                }
                peers.push(WgPeer {
                    public_key: key.as_str().to_owned(),
                    allowed_ips: allowed,
                    endpoint: None,
                    keepalive: None,
                });
            }
            let mut grants = BTreeSet::new();
            for grant in &desired.grants {
                let client: Ipv4Addr = grant
                    .client_address
                    .parse()
                    .context("invalid grant client")?;
                let route = parse_route_cidr(&grant.cidr)?;
                ensure!(clients.contains(&client), "grant for an unknown client");
                ensure!(routes.contains(&route), "grant for a route no site owns");
                grants.insert((client, route));
            }
            return Ok(Plan {
                revision: desired.network.revision,
                address,
                pool,
                wg_conf: render::wg_conf(&self.private_key, Some(listen_port), &peers),
                kernel_routes: routes,
                authorization: Authorization {
                    grants,
                    routes: BTreeSet::new(),
                },
                peers: peers.len(),
            });
        }
        ensure!(
            desired.routes.len() <= MAX_ROUTES,
            "desired state exceeds bounds"
        );
        let mut site_routes = BTreeSet::new();
        for text in &desired.routes {
            let route = parse_route_cidr(text)?;
            ensure!(
                !(route.contains(pool.address) || pool.contains(route.address)),
                "owned route overlaps the client pool"
            );
            site_routes.insert(route);
        }
        let peers = match &desired.hub {
            Some(hub) => {
                let key = PublicKey::parse(&hub.public_key)?;
                ensure!(
                    key.as_str() != self.state.public_key,
                    "hub key equals own key"
                );
                let endpoint =
                    validate_endpoint(hub.endpoint.as_deref().context("hub endpoint missing")?)?;
                vec![WgPeer {
                    public_key: key.as_str().to_owned(),
                    allowed_ips: vec![pool],
                    endpoint: Some(endpoint),
                    keepalive: Some(render::KEEPALIVE),
                }]
            }
            // No active hub: no peer and no live routes; the site forwards nothing.
            None => Vec::new(),
        };
        Ok(Plan {
            revision: desired.network.revision,
            address,
            pool,
            wg_conf: render::wg_conf(&self.private_key, None, &peers),
            kernel_routes: BTreeSet::new(),
            authorization: Authorization {
                grants: BTreeSet::new(),
                routes: if peers.is_empty() {
                    BTreeSet::new()
                } else {
                    site_routes
                },
            },
            peers: peers.len(),
        })
    }

    fn table_definition(&self, pool: Cidr) -> String {
        match &self.lan_if {
            Some(lan) => render::site_table(&self.table, &self.ifname, lan, pool, &self.owner),
            None => render::hub_table(&self.table, &self.ifname, &self.owner),
        }
    }

    fn authorization_script(&self, authorization: &Authorization, timeout_secs: u64) -> String {
        if self.lan_if.is_some() {
            let routes: Vec<Cidr> = authorization.routes.iter().copied().collect();
            render::site_routes(&self.table, &routes, timeout_secs)
        } else {
            let grants: Vec<(Ipv4Addr, Cidr)> = authorization.grants.iter().copied().collect();
            render::hub_grants(&self.table, &grants, timeout_secs)
        }
    }

    /// Read-only probes first, then protection, then the interface, then
    /// peers and activation. Anything with our name that we cannot prove is
    /// ours, or cannot read, is refused before either resource is mutated;
    /// ownership flags are set only for what we created or positively verified.
    async fn setup(&mut self, plan: &Plan) -> Result<()> {
        // 1. Probe both resources without touching either. An inventory that
        //    cannot be read proves nothing, so nothing is installed on it.
        let listing = table_listing(&self.table).await.with_context(|| {
            format!(
                "cannot tell whether nft table inet {} exists; refusing to install one",
                self.table
            )
        })?;
        if let Some(listing) = &listing {
            ensure!(
                table_owned_by(listing, &self.table, &self.owner),
                "nft table inet {} exists without this member's owner marker; refusing to replace or delete a table this member did not create",
                self.table
            );
        }
        let present = interface_exists(&self.ifname).await.with_context(|| {
            format!(
                "cannot tell whether {} exists; refusing to create or adopt it",
                self.ifname
            )
        })?;
        if present {
            let existing = exec("wg", &["show", &self.ifname, "public-key"], None, false)
                .await
                .with_context(|| {
                    format!(
                        "{} exists but is not a WireGuard interface owned by this member",
                        self.ifname
                    )
                })?;
            ensure!(
                existing.trim() == self.state.public_key,
                "{} exists with another key; refusing to take over an interface this member does not own",
                self.ifname
            );
        }
        // 2. Default-deny table with this member's owner marker, replaced in
        //    one transaction. Its sets start empty, so nothing is forwarded on
        //    the interface even if this process dies right after this step.
        if listing.is_some() {
            println!(
                "[{}] replacing table {} left by a previous run of this member",
                now(),
                self.table
            );
        }
        let definition = self.table_definition(plan.pool);
        exec_within(
            NFT_BUDGET,
            "nft",
            &["-f", "-"],
            Some(&render::replace_table(&self.table, &definition)),
            false,
        )
        .await?;
        self.owns_table = true;
        // 3. Interface: adopt the one verified above, or create it.
        if present {
            self.owns_interface = true;
            println!(
                "[{}] adopting existing interface {} from a previous run",
                now(),
                self.ifname
            );
        } else {
            exec(
                "ip",
                &["link", "add", "dev", &self.ifname, "type", "wireguard"],
                None,
                false,
            )
            .await?;
            self.owns_interface = true;
        }
        // 4. Peers, address and activation happen under the closed table.
        exec(
            "wg",
            &["syncconf", &self.ifname, "/dev/stdin"],
            Some(&plan.wg_conf),
            true,
        )
        .await?;
        self.applied_wg = Some(plan.wg_conf.clone());
        let address = format!("{}/{}", plan.address, plan.pool.prefix);
        exec(
            "ip",
            &["-4", "address", "replace", &address, "dev", &self.ifname],
            None,
            false,
        )
        .await?;
        let mtu = render::MTU.to_string();
        exec(
            "ip",
            &["link", "set", "dev", &self.ifname, "mtu", &mtu, "up"],
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Bring the main table in line with `desired` touching only routes on
    /// our interface with our rtproto. A desired prefix routed by anything
    /// else is refused so unrelated host routes are never replaced.
    async fn reconcile_routes(&mut self, desired: &BTreeSet<Cidr>) -> Result<()> {
        let listed = exec(
            "ip",
            &["-j", "-4", "route", "show", "table", "main"],
            None,
            false,
        )
        .await?;
        let actions = route_actions(&parse_route_inventory(&listed)?, desired, &self.ifname)?;
        for stale in &actions.del {
            exec(
                "ip",
                &[
                    "-4",
                    "route",
                    "del",
                    &stale.to_string(),
                    "dev",
                    &self.ifname,
                    "proto",
                    render::ROUTE_PROTO,
                ],
                None,
                false,
            )
            .await?;
        }
        for missing in &actions.add {
            // `add`, never `replace`: an unexpected same-prefix route fails loudly.
            exec(
                "ip",
                &[
                    "-4",
                    "route",
                    "add",
                    &missing.to_string(),
                    "dev",
                    &self.ifname,
                    "proto",
                    render::ROUTE_PROTO,
                ],
                None,
                false,
            )
            .await?;
        }
        self.applied_routes.clone_from(desired);
        Ok(())
    }

    /// Recreate the authorization elements in one bounded transaction with a
    /// timeout that ends before fetch start + LEASE. Returns the timeout used.
    async fn install(&self, authorization: &Authorization, started: Instant) -> Result<u64> {
        let timeout = element_timeout(started.elapsed())
            .context("state is older than the lease minus the install budget; not applying")?;
        exec_within(
            NFT_BUDGET,
            "nft",
            &["-f", "-"],
            Some(&self.authorization_script(authorization, timeout)),
            false,
        )
        .await?;
        Ok(timeout)
    }

    /// Apply one fetched state in the order given by `change_steps`: when
    /// peers or kernel routes differ from what is applied, authorization is
    /// emptied first, the identities are changed, and the full validated new
    /// authorization is installed last. An unchanged identity set (the normal
    /// poll) only refreshes the element timeouts.
    async fn apply(&mut self, plan: &Plan, started: Instant) -> Result<()> {
        let mut lease = 0;
        for step in change_steps(self.applied_wg.as_deref(), &self.applied_routes, plan) {
            match step {
                Step::FlushAuthorization => self.flush_authorization().await?,
                Step::SyncPeers => {
                    self.applied_wg = None;
                    exec(
                        "wg",
                        &["syncconf", &self.ifname, "/dev/stdin"],
                        Some(&plan.wg_conf),
                        true,
                    )
                    .await?;
                    self.applied_wg = Some(plan.wg_conf.clone());
                }
                Step::ReconcileRoutes => self.reconcile_routes(&plan.kernel_routes).await?,
                Step::InstallAuthorization => {
                    lease = self.install(&plan.authorization, started).await?;
                }
            }
        }
        if self.applied_revision != Some(plan.revision) {
            println!(
                "[{}] applied revision {} on {}: {} peer(s), {} live {}",
                now(),
                plan.revision,
                self.ifname,
                plan.peers,
                plan.authorization.len(),
                if self.lan_if.is_some() {
                    "route(s)"
                } else {
                    "grant(s)"
                }
            );
            self.applied_revision = Some(plan.revision);
        }
        self.report(plan.revision, lease).await;
        Ok(())
    }

    /// Remove every live authorization element in one bounded transaction.
    /// Peers stay configured; nothing is forwarded until the next install.
    async fn flush_authorization(&self) -> Result<()> {
        let script = self.authorization_script(&Authorization::default(), 1);
        exec_within(NFT_BUDGET, "nft", &["-f", "-"], Some(&script), false).await?;
        Ok(())
    }

    /// Best-effort flush for rejected state and teardown.
    async fn fail_closed(&self) {
        if let Err(error) = self.flush_authorization().await {
            eprintln!(
                "[{}] could not flush authorization ({error:#}); elements expire on their own",
                now()
            );
        }
    }

    /// Public peer identity and counters only. Best effort.
    async fn report(&mut self, revision: u64, lease_seconds: u64) {
        let peers = match self.peer_counters().await {
            Ok(peers) => peers,
            Err(error) => {
                eprintln!("[{}] could not read peer counters: {error:#}", now());
                Vec::new()
            }
        };
        let body = StatusReport {
            applied_revision: revision,
            lease_seconds,
            peers,
        };
        let path = format!(
            "/networks/{}/members/{}/status",
            self.state.network_id, self.state.member_id
        );
        match self.api.post::<serde_json::Value>(&path, &body).await {
            Ok(_) => self.reported_failure = false,
            Err(error) if !self.reported_failure => {
                eprintln!("[{}] status report failed: {error}", now());
                self.reported_failure = true;
            }
            Err(_) => {}
        }
    }

    async fn peer_counters(&self) -> Result<Vec<PeerReport>> {
        let handshakes = exec(
            "wg",
            &["show", &self.ifname, "latest-handshakes"],
            None,
            false,
        )
        .await?;
        let transfer = exec("wg", &["show", &self.ifname, "transfer"], None, false).await?;
        let mut peers = Vec::new();
        for line in handshakes.lines().take(MAX_PEERS) {
            let mut fields = line.split_whitespace();
            let (Some(key), Some(at)) = (fields.next(), fields.next()) else {
                continue;
            };
            let key = PublicKey::parse(key)?;
            let (mut rx, mut tx) = (0, 0);
            for row in transfer.lines() {
                let mut fields = row.split_whitespace();
                if fields.next() == Some(key.as_str()) {
                    rx = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                    tx = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                }
            }
            peers.push(PeerReport {
                public_key: key.as_str().to_owned(),
                last_handshake: at.parse().unwrap_or(0),
                rx,
                tx,
            });
        }
        Ok(peers)
    }

    async fn serve(&mut self) -> Result<()> {
        println!(
            "[{}] {} {} running on {} (table {}); authorization lease {}s, poll {}s; Ctrl+C or SIGTERM tears down",
            now(),
            self.state.role,
            self.state.member_name,
            self.ifname,
            self.table,
            LEASE.as_secs(),
            POLL.as_secs()
        );
        let mut shutdown = Box::pin(shutdown_signal());
        loop {
            tokio::select! {
                () = &mut shutdown => {
                    println!("[{}] shutdown requested", now());
                    return Ok(());
                }
                () = tokio::time::sleep(POLL) => {}
            }
            let started = Instant::now();
            match self.fetch().await {
                Ok(desired) => match self.plan(&desired) {
                    Ok(plan) => {
                        if let Err(error) = self.apply(&plan, started).await {
                            eprintln!("[{}] apply failed: {error:#}; last authorization expires within {}s", now(), LEASE.as_secs());
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "[{}] desired state rejected ({error:#}); failing closed",
                            now()
                        );
                        self.fail_closed().await;
                    }
                },
                Err(error) if error.is_definitive() => {
                    eprintln!("[{}] {error}; failing closed and exiting", now());
                    return Err(error.into());
                }
                Err(error) => {
                    eprintln!("[{}] {error}; forwarding expires at most {}s after the last successful fetch", now(), LEASE.as_secs());
                }
            }
        }
    }

    /// Remove only what this run created or proved to own, interface before
    /// table, in the order given by `cleanup_steps`. Authorization is flushed
    /// first; unless the interface is confirmed gone (removed here, or absent
    /// in a readable inventory) the table stays so the interface remains
    /// filtered. Ownership flags are cleared only by a confirmed removal or a
    /// confirmed absence. Errors are reported, never hidden.
    async fn teardown(&mut self) {
        if !self.owns_interface && !self.owns_table {
            return;
        }
        if self.owns_table {
            self.fail_closed().await;
        }
        // Probed whenever anything is owned: an owned table may be the only
        // filter in front of an interface setup never got to verify.
        let interface = match interface_exists(&self.ifname).await {
            Ok(present) => Some(present),
            Err(error) => {
                eprintln!(
                    "[{}] cannot tell whether {} still exists: {error:#}",
                    now(),
                    self.ifname
                );
                None
            }
        };
        if interface == Some(false) {
            self.owns_interface = false;
        }
        for step in cleanup_steps(self.owns_interface, self.owns_table, interface) {
            match step {
                Cleanup::RemoveInterface => {
                    let removed = match exec(
                        "ip",
                        &["link", "set", "dev", &self.ifname, "down"],
                        None,
                        false,
                    )
                    .await
                    {
                        Ok(_) => {
                            exec("ip", &["link", "del", "dev", &self.ifname], None, false).await
                        }
                        Err(error) => Err(error),
                    };
                    match removed {
                        Ok(_) => {
                            self.owns_interface = false;
                            println!("[{}] removed {}", now(), self.ifname);
                        }
                        Err(error) => {
                            eprintln!("[{}] cleanup failed: {error:#}; keeping table {} so {} stays filtered", now(), self.table, self.ifname);
                            return;
                        }
                    }
                }
                Cleanup::KeepTable => eprintln!(
                    "[{}] keeping table {} so {} stays filtered if it is still there",
                    now(),
                    self.table,
                    self.ifname
                ),
                Cleanup::DeleteTable => match table_listing(&self.table).await {
                    Ok(Some(_)) => match exec(
                        "nft",
                        &["delete", "table", "inet", &self.table],
                        None,
                        false,
                    )
                    .await
                    {
                        Ok(_) => {
                            self.owns_table = false;
                            println!("[{}] removed {}", now(), self.table);
                        }
                        Err(error) => eprintln!("[{}] cleanup failed: {error:#}", now()),
                    },
                    Ok(None) => self.owns_table = false,
                    Err(error) => eprintln!(
                        "[{}] cannot tell whether table {} still exists: {error:#}; leaving it",
                        now(),
                        self.table
                    ),
                },
            }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            () = async {
                match term.as_mut() {
                    Some(term) => { term.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::super::api::{DesiredGrant, DesiredNetwork, DesiredPeer, DesiredSelf, HubPeer};
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    /// A syntactically valid 44-character key with a readable tag.
    fn key(tag: &str) -> String {
        format!("{tag}{}=", "A".repeat(43 - tag.len()))
    }

    fn gateway(role: &str) -> Gateway {
        let mut config = crate::config::Config::default();
        config.auth.api_key = Some("pk_live_test".into());
        Gateway {
            api: Api::new(&config).unwrap(),
            state: MemberState {
                network_id: "0f8fad5b-d9cb-469f-a165-70867728950e".into(),
                network_name: "lab".into(),
                member_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7".into(),
                member_name: role.into(),
                role: role.into(),
                public_key: "SELFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                has_private_key: true,
            },
            private_key: "cPrivateKeyIsNeverLoggedAAAAAAAAAAAAAAAAAAE=".into(),
            ifname: "pike0f8fad5b".into(),
            table: "pike_0f8fad5b".into(),
            owner: render::owner_marker("7c9e6679-7425-40de-944b-e07fc1f90ae7"),
            lan_if: if role == "site" {
                Some("eth1".into())
            } else {
                None
            },
            owns_interface: false,
            owns_table: false,
            applied_wg: None,
            applied_routes: BTreeSet::new(),
            applied_revision: None,
            reported_failure: false,
        }
    }

    fn desired(role: &str) -> Desired {
        Desired {
            protocol: 1,
            network: DesiredNetwork {
                id: "0f8fad5b-d9cb-469f-a165-70867728950e".into(),
                client_cidr: "100.96.0.0/24".into(),
                revision: 7,
            },
            this: DesiredSelf {
                id: "7c9e6679-7425-40de-944b-e07fc1f90ae7".into(),
                role: role.into(),
                public_key: "SELFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                address: if role == "hub" {
                    "100.96.0.1".into()
                } else {
                    "100.96.0.2".into()
                },
                listen_port: Some(51820),
            },
            lease_seconds: 30,
            peers: vec![
                DesiredPeer {
                    name: "site-a".into(),
                    role: "site".into(),
                    public_key: "SITEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    address: "100.96.0.2".into(),
                    allowed_ips: vec!["100.96.0.2/32".into(), "10.10.0.0/24".into()],
                },
                DesiredPeer {
                    name: "c1".into(),
                    role: "client".into(),
                    public_key: "CLIENTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    address: "100.96.0.4".into(),
                    allowed_ips: vec!["100.96.0.4/32".into()],
                },
            ],
            grants: vec![DesiredGrant {
                client_address: "100.96.0.4".into(),
                cidr: "10.10.0.0/24".into(),
            }],
            hub: Some(HubPeer {
                public_key: "HUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                endpoint: Some("203.0.113.5:51820".into()),
                address: "100.96.0.1".into(),
            }),
            routes: vec!["10.10.0.0/24".into()],
        }
    }

    #[test]
    fn hub_plan_binds_peers_grants_and_kernel_routes() {
        let plan = gateway("hub").plan(&desired("hub")).unwrap();
        assert_eq!(plan.revision, 7);
        assert_eq!(
            plan.authorization
                .grants
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![("100.96.0.4".parse().unwrap(), cidr("10.10.0.0/24"))]
        );
        assert!(plan.authorization.routes.is_empty());
        assert_eq!(
            plan.kernel_routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["10.10.0.0/24"]
        );
        assert!(plan.wg_conf.contains("ListenPort = 51820\n"));
        assert!(plan
            .wg_conf
            .contains("AllowedIPs = 100.96.0.2/32, 10.10.0.0/24\n"));
        assert!(plan.wg_conf.contains("AllowedIPs = 100.96.0.4/32\n"));
        assert!(!plan.wg_conf.contains("Endpoint"));
    }

    #[test]
    fn hub_plan_rejects_tampered_state() {
        let gw = gateway("hub");
        let mut d = desired("hub");
        d.grants[0].client_address = "100.96.0.9".into();
        assert!(gw
            .plan(&d)
            .err()
            .expect("invalid plan must be rejected")
            .to_string()
            .contains("unknown client"));
        let mut d = desired("hub");
        d.grants[0].cidr = "10.20.0.0/24".into();
        assert!(gw
            .plan(&d)
            .err()
            .expect("invalid plan must be rejected")
            .to_string()
            .contains("no site owns"));
        let mut d = desired("hub");
        d.peers[1].allowed_ips.push("10.10.0.0/24".into());
        assert!(gw
            .plan(&d)
            .err()
            .expect("invalid plan must be rejected")
            .to_string()
            .contains("one /32"));
        let mut d = desired("hub");
        d.peers[0].allowed_ips = vec!["10.10.0.0/24".into(), "100.96.0.2/32".into()];
        assert!(gw
            .plan(&d)
            .err()
            .expect("invalid plan must be rejected")
            .to_string()
            .contains("own /32"));
        let mut d = desired("hub");
        d.peers[0].allowed_ips[1] = "100.96.0.0/25".into();
        assert!(gw
            .plan(&d)
            .err()
            .expect("invalid plan must be rejected")
            .to_string()
            .contains("overlaps the client pool"));
        let mut d = desired("hub");
        d.peers[0].allowed_ips[1] = "0.0.0.0/0".into();
        assert!(gw.plan(&d).is_err());
        let mut d = desired("hub");
        d.this.public_key = "OTHERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        assert!(gw
            .plan(&d)
            .err()
            .expect("invalid plan must be rejected")
            .to_string()
            .contains("different public key"));
        let mut d = desired("hub");
        d.lease_seconds = 31;
        assert!(gw
            .plan(&d)
            .err()
            .expect("invalid plan must be rejected")
            .to_string()
            .contains("lease"));
        let mut d = desired("hub");
        d.peers[1].public_key = "SITEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        assert!(gw
            .plan(&d)
            .err()
            .expect("invalid plan must be rejected")
            .to_string()
            .contains("duplicate"));
        let mut d = desired("hub");
        d.protocol = 2;
        assert!(gw.plan(&d).is_err());
    }

    #[test]
    fn site_plan_has_one_hub_peer_and_no_routes_without_a_hub() {
        let plan = gateway("site").plan(&desired("site")).unwrap();
        assert_eq!(plan.peers, 1);
        assert!(plan.wg_conf.contains(
            "AllowedIPs = 100.96.0.0/24\nEndpoint = 203.0.113.5:51820\nPersistentKeepalive = 25\n"
        ));
        assert_eq!(plan.authorization.routes.len(), 1);
        assert!(plan.authorization.grants.is_empty());
        assert!(plan.kernel_routes.is_empty());
        let mut d = desired("site");
        d.hub = None;
        let plan = gateway("site").plan(&d).unwrap();
        assert_eq!(plan.peers, 0);
        assert!(plan.authorization.routes.is_empty());
        assert!(!plan.wg_conf.contains("[Peer]"));
        let mut d = desired("site");
        d.routes = vec!["100.96.0.0/25".into()];
        assert!(gateway("site").plan(&d).is_err());
        let mut d = desired("site");
        d.hub.as_mut().unwrap().endpoint = Some("bad host:1".into());
        assert!(gateway("site").plan(&d).is_err());
    }

    #[test]
    fn a_fresh_gateway_owns_nothing_so_a_refusal_tears_nothing_down() {
        let gw = gateway("hub");
        assert!(!gw.owns_interface && !gw.owns_table);
        assert!(gw.applied_wg.is_none() && gw.applied_routes.is_empty());
    }

    #[test]
    fn table_ownership_requires_this_members_marker() {
        let marker = render::owner_marker("7c9e6679-7425-40de-944b-e07fc1f90ae7");
        let listing = |name: &str, table: &str| {
            format!(
                r#"{{"nftables":[{{"metainfo":{{"version":"1.1.1","release_name":"x","json_schema_version":1}}}},{{"table":{{"family":"inet","name":"{table}","handle":7}}}},{{"counter":{{"family":"inet","name":"{name}","table":"{table}","handle":8,"packets":0,"bytes":0}}}},{{"counter":{{"family":"inet","name":"fwd_accept","table":"{table}","handle":9,"packets":0,"bytes":0}}}}]}}"#
            )
        };
        assert!(table_owned_by(
            &listing(&marker, "pike_0f8fad5b"),
            "pike_0f8fad5b",
            &marker
        ));
        // Another member of the same network, a foreign table of the same name, or no marker at all.
        assert!(!table_owned_by(
            &listing(
                &render::owner_marker("11111111-2222-3333-4444-555555555555"),
                "pike_0f8fad5b"
            ),
            "pike_0f8fad5b",
            &marker
        ));
        assert!(!table_owned_by(
            &listing("fwd_drop", "pike_0f8fad5b"),
            "pike_0f8fad5b",
            &marker
        ));
        assert!(!table_owned_by(
            &listing(&marker, "other_table"),
            "pike_0f8fad5b",
            &marker
        ));
        assert!(!table_owned_by(
            r#"{"nftables":[{"table":{"family":"inet","name":"pike_0f8fad5b","handle":7}}]}"#,
            "pike_0f8fad5b",
            &marker
        ));
        assert!(!table_owned_by("not json", "pike_0f8fad5b", &marker));
        assert!(!table_owned_by("", "pike_0f8fad5b", &marker));
    }

    /// A failed or unreadable inventory is unknown, never absence: setup must
    /// not replace a table it could not list, teardown must not delete a
    /// table while it cannot tell whether the interface is gone.
    #[test]
    fn inventories_distinguish_confirmed_absence_from_unreadable_output() {
        let links = r#"[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"link_type":"loopback"},{"ifindex":9,"ifname":"pike0f8fad5b","flags":["POINTOPOINT","NOARP","UP"],"link_type":"none"}]"#;
        assert!(link_present(links, "pike0f8fad5b").unwrap());
        assert!(!link_present(links, "pike00000000").unwrap());
        assert!(!link_present("[]", "pike0f8fad5b").unwrap());
        assert!(link_present("", "pike0f8fad5b").is_err());
        assert!(link_present("Device \"pike0f8fad5b\" does not exist.", "pike0f8fad5b").is_err());
        let tables = |family: &str| {
            format!(
                r#"{{"nftables":[{{"metainfo":{{"version":"1.1.1","release_name":"x","json_schema_version":1}}}},{{"table":{{"family":"{family}","name":"pike_0f8fad5b","handle":3}}}},{{"table":{{"family":"inet","name":"filter","handle":4}}}}]}}"#
            )
        };
        assert!(table_present(&tables("inet"), "pike_0f8fad5b").unwrap());
        // Same name in another family, or only other tables: confirmed absent.
        assert!(!table_present(&tables("ip"), "pike_0f8fad5b").unwrap());
        assert!(!table_present(&tables("inet"), "pike_00000000").unwrap());
        assert!(!table_present(r#"{"nftables":[]}"#, "pike_0f8fad5b").unwrap());
        // Anything that is not a complete inventory is unknown.
        assert!(table_present("", "pike_0f8fad5b").is_err());
        assert!(table_present("{}", "pike_0f8fad5b").is_err());
        assert!(table_present("Error: could not open netlink socket", "pike_0f8fad5b").is_err());
    }

    #[test]
    fn cleanup_deletes_the_table_only_after_the_interface_is_confirmed_gone() {
        assert_eq!(
            cleanup_steps(true, true, Some(true)),
            vec![Cleanup::RemoveInterface, Cleanup::DeleteTable]
        );
        assert_eq!(
            cleanup_steps(true, true, Some(false)),
            vec![Cleanup::DeleteTable]
        );
        // Unknown interface: the table stays whatever else happens.
        assert_eq!(cleanup_steps(true, true, None), vec![Cleanup::KeepTable]);
        assert!(cleanup_steps(true, false, None).is_empty());
        assert_eq!(
            cleanup_steps(true, false, Some(true)),
            vec![Cleanup::RemoveInterface]
        );
        // Restart regression: setup installed the table, then creating the
        // interface failed, so the interface is unverified. Present or unknown
        // keeps the table and leaves the interface alone; only a confirmed
        // absence lets the table go.
        assert_eq!(cleanup_steps(false, true, None), vec![Cleanup::KeepTable]);
        assert_eq!(
            cleanup_steps(false, true, Some(true)),
            vec![Cleanup::KeepTable]
        );
        assert_eq!(
            cleanup_steps(false, true, Some(false)),
            vec![Cleanup::DeleteTable]
        );
        assert!(cleanup_steps(false, false, None).is_empty());
        assert!(cleanup_steps(false, false, Some(true)).is_empty());
        for interface in [Some(true), Some(false), None] {
            let steps = cleanup_steps(true, true, interface);
            let delete = steps.iter().position(|s| *s == Cleanup::DeleteTable);
            let remove = steps.iter().position(|s| *s == Cleanup::RemoveInterface);
            assert!(
                delete.is_none() || interface == Some(false) || remove < delete,
                "{interface:?}: the interface goes before the table"
            );
        }
    }

    /// The parent-death guard is armed by the child and verified against the
    /// pid recorded before the fork: a child whose parent is not that pid
    /// never execs, so the guard cannot be installed after the parent is gone.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_child_execs_only_when_bound_to_the_process_that_spawned_it() {
        exec_within(COMMAND_TIMEOUT, "true", &[], None, false)
            .await
            .unwrap();
        let mut command = tokio::process::Command::new("true");
        bind_child(&mut command, std::process::id().wrapping_add(1));
        assert!(
            command.spawn().is_err(),
            "a child whose parent is not the recorded pid must refuse to exec"
        );
    }

    #[test]
    fn element_timeout_deducts_the_bounded_install_budget_from_the_lease() {
        // fetch start + 30 s is the deadline: 30 - 3 (nft budget) - 1 (slack).
        assert_eq!(element_timeout(Duration::ZERO), Some(26));
        assert_eq!(element_timeout(Duration::from_secs(10)), Some(16));
        assert_eq!(element_timeout(Duration::from_secs(25)), Some(1));
        assert_eq!(element_timeout(Duration::from_millis(25_500)), None);
        assert_eq!(element_timeout(Duration::from_secs(26)), None);
        assert_eq!(element_timeout(Duration::from_secs(300)), None);
        // A committed element expires no later than fetch start + LEASE even if
        // nft commits at the very end of its budget.
        for elapsed in [0u64, 5, 12, 25] {
            if let Some(timeout) = element_timeout(Duration::from_secs(elapsed)) {
                assert!(
                    elapsed + NFT_BUDGET.as_secs() + timeout <= LEASE.as_secs(),
                    "elapsed {elapsed}"
                );
            }
        }
        // Ten second polling stays usable: a fresh apply leaves well over one poll.
        assert!(element_timeout(Duration::from_secs(2)).unwrap() > POLL.as_secs());
    }

    #[test]
    fn route_actions_touch_only_owned_routes_and_refuse_foreign_same_prefix_routes() {
        let inventory = parse_route_inventory(
            r#"[{"dst":"default","gateway":"172.18.0.1","dev":"eth0","flags":[]},
                {"dst":"172.18.0.0/16","dev":"eth0","protocol":"kernel","scope":"link","prefsrc":"172.18.0.2","flags":[]},
                {"dst":"100.96.0.0/24","dev":"pike0f8fad5b","protocol":"kernel","scope":"link","prefsrc":"100.96.0.1","flags":[]},
                {"dst":"10.10.0.0/24","dev":"pike0f8fad5b","protocol":"250","scope":"link","flags":[]},
                {"dst":"10.99.0.7","dev":"pike0f8fad5b","protocol":"250","scope":"link","flags":[]}]"#,
        )
        .unwrap();
        assert_eq!(inventory.len(), 4);
        assert_eq!(inventory[3].dst, cidr("10.99.0.7/32"));
        let desired: BTreeSet<Cidr> = [cidr("10.10.0.0/24"), cidr("10.20.0.0/24")]
            .into_iter()
            .collect();
        let actions = route_actions(&inventory, &desired, "pike0f8fad5b").unwrap();
        assert_eq!(
            actions.add.iter().copied().collect::<Vec<_>>(),
            vec![cidr("10.20.0.0/24")]
        );
        assert_eq!(
            actions.del.iter().copied().collect::<Vec<_>>(),
            vec![cidr("10.99.0.7/32")]
        );
        // The connected pool route on our interface has another rtproto: neither owned nor deleted.
        assert!(!actions.del.contains(&cidr("100.96.0.0/24")));
        // A foreign route for a desired prefix is a conflict, whatever its device or protocol.
        let mut foreign = inventory.clone();
        foreign.push(RouteEntry {
            dst: cidr("10.20.0.0/24"),
            dev: Some("eth0".into()),
            proto: Some("static".into()),
        });
        let error = route_actions(&foreign, &desired, "pike0f8fad5b")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("10.20.0.0/24") && error.contains("refusing"),
            "{error}"
        );
        let mut same_dev = inventory.clone();
        same_dev.push(RouteEntry {
            dst: cidr("10.20.0.0/24"),
            dev: Some("pike0f8fad5b".into()),
            proto: Some("boot".into()),
        });
        assert!(route_actions(&same_dev, &desired, "pike0f8fad5b").is_err());
        // Foreign routes for other prefixes are simply ignored.
        let mut unrelated = inventory.clone();
        unrelated.push(RouteEntry {
            dst: cidr("10.30.0.0/24"),
            dev: Some("eth0".into()),
            proto: Some("static".into()),
        });
        assert_eq!(
            route_actions(&unrelated, &desired, "pike0f8fad5b").unwrap(),
            actions
        );
        assert!(parse_route_inventory("nonsense").is_err());
    }

    #[test]
    fn an_unchanged_identity_set_only_refreshes_authorization() {
        let gw = gateway("hub");
        let plan = gw.plan(&desired("hub")).unwrap();
        assert_eq!(
            change_steps(Some(&plan.wg_conf), &plan.kernel_routes, &plan),
            vec![Step::InstallAuthorization]
        );
        // A fresh gateway knows nothing about the kernel: it flushes before it trusts anything.
        let steps = change_steps(None, &BTreeSet::new(), &plan);
        assert_eq!(steps[0], Step::FlushAuthorization);
        assert_eq!(steps.last(), Some(&Step::InstallAuthorization));
    }

    /// Regression: revoked client A (100.96.0.4, granted 10.10.0.0/24) is
    /// replaced by B, who reuses the /32 and receives the same grant. The
    /// `(client, route)` tuple is identical, only the peer key differs. After
    /// a control-plane outage longer than the lease, A's element has expired
    /// in the kernel; refreshing the "retained" tuple before the key change
    /// would have re-authorized A's old key for one more lease. The tuple
    /// must never be installed before the peers are synchronized.
    #[test]
    fn a_reused_address_with_the_same_grant_but_a_new_key_is_never_authorized_before_the_key_change(
    ) {
        let gw = gateway("hub");
        let before = gw.plan(&desired("hub")).unwrap();
        let mut successor = desired("hub");
        successor.peers[1].name = "c1-successor".into();
        successor.peers[1].public_key = key("SUCCESSOR");
        successor.network.revision = 9;
        let after = gw.plan(&successor).unwrap();
        // Same authorization tuple, different peer identity. (Compared without
        // assert_ne so a failure never prints the interface private key.)
        assert_eq!(before.authorization, after.authorization);
        assert_eq!(before.kernel_routes, after.kernel_routes);
        assert!(
            before.wg_conf != after.wg_conf,
            "the successor must change the peer configuration"
        );
        let steps = change_steps(Some(&before.wg_conf), &before.kernel_routes, &after);
        assert_eq!(
            steps,
            vec![
                Step::FlushAuthorization,
                Step::SyncPeers,
                Step::InstallAuthorization
            ]
        );
        let sync = steps.iter().position(|s| *s == Step::SyncPeers).unwrap();
        assert!(
            steps[..sync].iter().all(|s| *s == Step::FlushAuthorization),
            "nothing but a flush may precede the peer change"
        );
        assert!(
            !steps[..sync].contains(&Step::InstallAuthorization),
            "the shared tuple is installed only after the new key is in the kernel"
        );
    }

    /// The same rule for a site CIDR: a route transferred from site A to
    /// site B keeps its kernel route and its grants; only the peer binding
    /// changes, so the grants are flushed before the peers are synchronized.
    #[test]
    fn a_route_transferred_to_another_site_flushes_grants_before_rebinding_peers() {
        let gw = gateway("hub");
        let before = gw.plan(&desired("hub")).unwrap();
        let mut transferred = desired("hub");
        transferred.peers[0].allowed_ips = vec!["100.96.0.2/32".into()];
        transferred.peers.push(DesiredPeer {
            name: "site-b".into(),
            role: "site".into(),
            public_key: key("SITEB"),
            address: "100.96.0.3".into(),
            allowed_ips: vec!["100.96.0.3/32".into(), "10.10.0.0/24".into()],
        });
        let after = gw.plan(&transferred).unwrap();
        assert_eq!(before.authorization, after.authorization);
        assert_eq!(before.kernel_routes, after.kernel_routes);
        assert_eq!(
            change_steps(Some(&before.wg_conf), &before.kernel_routes, &after),
            vec![
                Step::FlushAuthorization,
                Step::SyncPeers,
                Step::InstallAuthorization
            ]
        );
        // A site gateway whose hub key changes likewise loses its live routes first.
        let site = gateway("site");
        let site_before = site.plan(&desired("site")).unwrap();
        let mut rekeyed = desired("site");
        rekeyed.hub.as_mut().unwrap().public_key = key("HUB2");
        let site_after = site.plan(&rekeyed).unwrap();
        assert_eq!(site_before.authorization, site_after.authorization);
        assert_eq!(
            change_steps(
                Some(&site_before.wg_conf),
                &site_before.kernel_routes,
                &site_after
            ),
            vec![
                Step::FlushAuthorization,
                Step::SyncPeers,
                Step::InstallAuthorization
            ]
        );
        // A route change alone: flush, reconcile, install.
        let mut withdrawn = desired("hub");
        withdrawn.peers[0].allowed_ips = vec!["100.96.0.2/32".into()];
        withdrawn.grants.clear();
        let after_withdraw = gw.plan(&withdrawn).unwrap();
        assert_eq!(
            change_steps(
                Some(&after_withdraw.wg_conf),
                &before.kernel_routes,
                &after_withdraw
            ),
            vec![
                Step::FlushAuthorization,
                Step::ReconcileRoutes,
                Step::InstallAuthorization
            ]
        );
    }
}
