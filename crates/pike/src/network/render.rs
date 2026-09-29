//! Pure renderers for wg(8) configuration, wg-quick(8) client files and nft(8)
//! scripts. Inputs are already validated types; outputs are covered by exact
//! snapshot tests so the enforcement model is reviewable as text.
use super::model::Cidr;
use std::fmt::Write as _;
use std::net::Ipv4Addr;

pub const MTU: u16 = 1420;
pub const KEEPALIVE: u16 = 25;
/// Routes the gateway installs carry this rtproto so only they are reconciled.
pub const ROUTE_PROTO: &str = "250";

pub struct WgPeer {
    pub public_key: String,
    pub allowed_ips: Vec<Cidr>,
    pub endpoint: Option<String>,
    pub keepalive: Option<u16>,
}

/// wg(8) `setconf`/`syncconf` format: interface key and peers only.
pub fn wg_conf(private_key: &str, listen_port: Option<u16>, peers: &[WgPeer]) -> String {
    let mut out = String::from("[Interface]\n");
    let _ = writeln!(out, "PrivateKey = {private_key}");
    if let Some(port) = listen_port {
        let _ = writeln!(out, "ListenPort = {port}");
    }
    for peer in peers {
        out.push_str("\n[Peer]\n");
        let _ = writeln!(out, "PublicKey = {}", peer.public_key);
        let ips: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();
        let _ = writeln!(out, "AllowedIPs = {}", ips.join(", "));
        if let Some(endpoint) = &peer.endpoint {
            let _ = writeln!(out, "Endpoint = {endpoint}");
        }
        if let Some(keepalive) = peer.keepalive {
            let _ = writeln!(out, "PersistentKeepalive = {keepalive}");
        }
    }
    out
}

/// wg-quick(8) file for a standard client on any OS. `private_key` is None
/// when the device generated its own key elsewhere.
pub fn client_conf(
    private_key: Option<&str>,
    address: Ipv4Addr,
    hub_key: &str,
    endpoint: &str,
    allowed: &[Cidr],
) -> String {
    let ips: Vec<String> = allowed.iter().map(ToString::to_string).collect();
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {address}/32\nMTU = {MTU}\n\n[Peer]\nPublicKey = {hub_key}\nEndpoint = {endpoint}\nAllowedIPs = {}\nPersistentKeepalive = {KEEPALIVE}\n",
        private_key.unwrap_or("<replace-with-the-device-private-key>"),
        ips.join(", ")
    )
}

/// Name of the counter object that marks a table as created by one member.
/// A table without this exact marker is never adopted, replaced or deleted.
pub fn owner_marker(member_id: &str) -> String {
    format!(
        "owner_{}",
        member_id
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
    )
}

/// One `nft -f` transaction that installs `definition` whether or not a table
/// of that name exists: the add is a no-op on an existing table, the delete
/// removes it, and the declaration recreates it, all committed together so
/// there is never a moment without the table or with duplicated rules.
pub fn replace_table(table: &str, definition: &str) -> String {
    format!("table inet {table} {{}}\ndelete table inet {table}\n{definition}")
}

/// Hub table. Forwarding between peers is allowed only while the exact
/// (client, route) pair is a live element of `grants`; replies additionally
/// need conntrack state so a site cannot open connections toward clients.
/// Elements expire in the kernel, so a dead agent stops forwarding by itself.
/// Only traffic entering or leaving the Pike interface is ever dropped.
/// The table is installed before the interface exists, so it starts closed.
pub fn hub_table(table: &str, ifname: &str, owner: &str) -> String {
    format!(
        "table inet {table} {{
\tcounter {owner} {{}}
\tcounter fwd_accept {{}}
\tcounter fwd_drop {{}}
\tset grants {{
\t\ttype ipv4_addr . ipv4_addr
\t\tflags interval,timeout
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname \"{ifname}\" oifname \"{ifname}\" ip saddr . ip daddr @grants ct state new,established,related counter name \"fwd_accept\" accept
\t\tiifname \"{ifname}\" oifname \"{ifname}\" ip daddr . ip saddr @grants ct state established,related counter name \"fwd_accept\" accept
\t\tiifname \"{ifname}\" counter name \"fwd_drop\" drop
\t\toifname \"{ifname}\" counter name \"fwd_drop\" drop
\t}}
\tchain input {{
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname \"{ifname}\" icmp type echo-request accept
\t\tiifname \"{ifname}\" drop
\t}}
}}
"
    )
}

/// One atomic transaction: every element is recreated with a fresh timeout
/// measured by the caller from the start of the successful fetch.
pub fn hub_grants(table: &str, grants: &[(Ipv4Addr, Cidr)], timeout_secs: u64) -> String {
    let mut out = format!("flush set inet {table} grants\n");
    if !grants.is_empty() {
        let elements: Vec<String> = grants
            .iter()
            .map(|(client, route)| format!("{client} . {} timeout {timeout_secs}s", route.nft()))
            .collect();
        let _ = writeln!(
            out,
            "add element inet {table} grants {{ {} }}",
            elements.join(", ")
        );
    }
    out
}

/// Site table. Client traffic may enter the LAN only toward this site's live
/// owned routes and is masqueraded there; LAN replies flow back only for
/// established flows. Nothing else crosses the Pike interface.
pub fn site_table(
    table: &str,
    ifname: &str,
    lan_if: &str,
    client_cidr: &Cidr,
    owner: &str,
) -> String {
    format!(
        "table inet {table} {{
\tcounter {owner} {{}}
\tcounter fwd_accept {{}}
\tcounter fwd_drop {{}}
\tset routes {{
\t\ttype ipv4_addr
\t\tflags interval,timeout
\t}}
\tchain forward {{
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname \"{ifname}\" oifname \"{lan_if}\" ip saddr {client_cidr} ip daddr @routes ct state new,established,related counter name \"fwd_accept\" accept
\t\tiifname \"{lan_if}\" oifname \"{ifname}\" ip daddr {client_cidr} ip saddr @routes ct state established,related counter name \"fwd_accept\" accept
\t\tiifname \"{ifname}\" counter name \"fwd_drop\" drop
\t\toifname \"{ifname}\" counter name \"fwd_drop\" drop
\t}}
\tchain postrouting {{
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname \"{lan_if}\" ip saddr {client_cidr} ip daddr @routes masquerade
\t}}
\tchain input {{
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname \"{ifname}\" icmp type echo-request accept
\t\tiifname \"{ifname}\" drop
\t}}
}}
"
    )
}

pub fn site_routes(table: &str, routes: &[Cidr], timeout_secs: u64) -> String {
    let mut out = format!("flush set inet {table} routes\n");
    if !routes.is_empty() {
        let elements: Vec<String> = routes
            .iter()
            .map(|r| format!("{} timeout {timeout_secs}s", r.nft()))
            .collect();
        let _ = writeln!(
            out,
            "add element inet {table} routes {{ {} }}",
            elements.join(", ")
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    #[test]
    fn hub_wg_conf_binds_each_peer_to_its_own_sources() {
        let conf = wg_conf(
            "cPrivateKeyIsNeverLoggedAAAAAAAAAAAAAAAAAAE=",
            Some(51820),
            &[
                WgPeer {
                    public_key: "SITEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    allowed_ips: vec![cidr("100.96.0.2/32"), cidr("10.10.0.0/24")],
                    endpoint: None,
                    keepalive: None,
                },
                WgPeer {
                    public_key: "CLIENTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                    allowed_ips: vec![cidr("100.96.0.4/32")],
                    endpoint: None,
                    keepalive: None,
                },
            ],
        );
        assert_eq!(
            conf,
            "[Interface]\nPrivateKey = cPrivateKeyIsNeverLoggedAAAAAAAAAAAAAAAAAAE=\nListenPort = 51820\n\n[Peer]\nPublicKey = SITEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 100.96.0.2/32, 10.10.0.0/24\n\n[Peer]\nPublicKey = CLIENTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 100.96.0.4/32\n"
        );
    }

    #[test]
    fn site_wg_conf_routes_only_the_client_pool_to_the_hub() {
        let conf = wg_conf(
            "cPrivateKeyIsNeverLoggedAAAAAAAAAAAAAAAAAAE=",
            None,
            &[WgPeer {
                public_key: "HUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                allowed_ips: vec![cidr("100.96.0.0/24")],
                endpoint: Some("203.0.113.5:51820".into()),
                keepalive: Some(KEEPALIVE),
            }],
        );
        assert_eq!(
            conf,
            "[Interface]\nPrivateKey = cPrivateKeyIsNeverLoggedAAAAAAAAAAAAAAAAAAE=\n\n[Peer]\nPublicKey = HUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 100.96.0.0/24\nEndpoint = 203.0.113.5:51820\nPersistentKeepalive = 25\n"
        );
    }

    #[test]
    fn client_conf_is_a_standard_wg_quick_file() {
        let conf = client_conf(
            None,
            "100.96.0.4".parse().unwrap(),
            "HUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "hub.example.test:51820",
            &[cidr("100.96.0.0/24"), cidr("10.10.0.0/24")],
        );
        assert_eq!(
            conf,
            "[Interface]\nPrivateKey = <replace-with-the-device-private-key>\nAddress = 100.96.0.4/32\nMTU = 1420\n\n[Peer]\nPublicKey = HUBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = hub.example.test:51820\nAllowedIPs = 100.96.0.0/24, 10.10.0.0/24\nPersistentKeepalive = 25\n"
        );
        assert!(
            client_conf(Some("k"), "100.96.0.4".parse().unwrap(), "H", "e:1", &[])
                .starts_with("[Interface]\nPrivateKey = k\n")
        );
    }

    #[test]
    fn owner_marker_is_a_plain_identifier_and_replacement_is_one_transaction() {
        assert_eq!(
            owner_marker("7c9e6679-7425-40de-944b-e07fc1f90ae7"),
            "owner_7c9e6679742540de944be07fc1f90ae7"
        );
        assert_eq!(replace_table("pike_0f8fad5b", "table inet pike_0f8fad5b {\n}\n"), "table inet pike_0f8fad5b {}\ndelete table inet pike_0f8fad5b\ntable inet pike_0f8fad5b {\n}\n");
        // Only the named table is ever deleted; no flush, no other table.
        let script = replace_table(
            "pike_0f8fad5b",
            &hub_table("pike_0f8fad5b", "pike0f8fad5b", "owner_x"),
        );
        assert_eq!(script.matches("delete").count(), 1);
        assert!(!script.contains("flush"));
    }

    #[test]
    fn hub_table_drops_only_pike_traffic_and_requires_a_live_grant_in_both_directions() {
        let table = hub_table(
            "pike_0f8fad5b",
            "pike0f8fad5b",
            "owner_7c9e6679742540de944be07fc1f90ae7",
        );
        assert_eq!(
            table,
            "table inet pike_0f8fad5b {
\tcounter owner_7c9e6679742540de944be07fc1f90ae7 {}
\tcounter fwd_accept {}
\tcounter fwd_drop {}
\tset grants {
\t\ttype ipv4_addr . ipv4_addr
\t\tflags interval,timeout
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname \"pike0f8fad5b\" oifname \"pike0f8fad5b\" ip saddr . ip daddr @grants ct state new,established,related counter name \"fwd_accept\" accept
\t\tiifname \"pike0f8fad5b\" oifname \"pike0f8fad5b\" ip daddr . ip saddr @grants ct state established,related counter name \"fwd_accept\" accept
\t\tiifname \"pike0f8fad5b\" counter name \"fwd_drop\" drop
\t\toifname \"pike0f8fad5b\" counter name \"fwd_drop\" drop
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname \"pike0f8fad5b\" icmp type echo-request accept
\t\tiifname \"pike0f8fad5b\" drop
\t}
}
"
        );
        // No unconditional established/related accept and no flush of anything but the named set.
        assert!(!table.contains("ct state established,related accept\n"));
        assert!(!table.contains("flush"));
    }

    #[test]
    fn grant_elements_are_recreated_atomically_with_the_caller_timeout() {
        let script = hub_grants(
            "pike_0f8fad5b",
            &[
                ("100.96.0.4".parse().unwrap(), cidr("10.10.0.0/24")),
                ("100.96.0.5".parse().unwrap(), cidr("10.20.0.7/32")),
            ],
            27,
        );
        assert_eq!(
            script,
            "flush set inet pike_0f8fad5b grants\nadd element inet pike_0f8fad5b grants { 100.96.0.4 . 10.10.0.0/24 timeout 27s, 100.96.0.5 . 10.20.0.7 timeout 27s }\n"
        );
        assert_eq!(
            hub_grants("pike_0f8fad5b", &[], 30),
            "flush set inet pike_0f8fad5b grants\n"
        );
    }

    #[test]
    fn site_table_forwards_only_client_pool_to_live_owned_routes() {
        let table = site_table(
            "pike_0f8fad5b",
            "pike0f8fad5b",
            "eth1",
            &cidr("100.96.0.0/24"),
            "owner_7c9e6679742540de944be07fc1f90ae7",
        );
        assert_eq!(
            table,
            "table inet pike_0f8fad5b {
\tcounter owner_7c9e6679742540de944be07fc1f90ae7 {}
\tcounter fwd_accept {}
\tcounter fwd_drop {}
\tset routes {
\t\ttype ipv4_addr
\t\tflags interval,timeout
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname \"pike0f8fad5b\" oifname \"eth1\" ip saddr 100.96.0.0/24 ip daddr @routes ct state new,established,related counter name \"fwd_accept\" accept
\t\tiifname \"eth1\" oifname \"pike0f8fad5b\" ip daddr 100.96.0.0/24 ip saddr @routes ct state established,related counter name \"fwd_accept\" accept
\t\tiifname \"pike0f8fad5b\" counter name \"fwd_drop\" drop
\t\toifname \"pike0f8fad5b\" counter name \"fwd_drop\" drop
\t}
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname \"eth1\" ip saddr 100.96.0.0/24 ip daddr @routes masquerade
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname \"pike0f8fad5b\" icmp type echo-request accept
\t\tiifname \"pike0f8fad5b\" drop
\t}
}
"
        );
        assert_eq!(site_routes("pike_0f8fad5b", &[cidr("10.10.0.0/24")], 29), "flush set inet pike_0f8fad5b routes\nadd element inet pike_0f8fad5b routes { 10.10.0.0/24 timeout 29s }\n");
    }
}
