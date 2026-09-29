//! Validated value types. Everything rendered into a WireGuard, nft or ip
//! command passes through one of these constructors first, so no untrusted
//! string ever reaches a subprocess or configuration file unchecked.
use anyhow::{bail, ensure, Result};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Canonical IPv4 subnet: host bits are zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    pub address: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub fn new(address: Ipv4Addr, prefix: u8) -> Result<Self> {
        ensure!(prefix <= 32, "prefix must be at most /32");
        let bits = u32::from(address);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix))
        };
        ensure!(
            bits & !mask == 0,
            "{address}/{prefix} is not canonical; use {}/{prefix}",
            Ipv4Addr::from(bits & mask)
        );
        Ok(Self { address, prefix })
    }

    /// RFC 1918 or 100.64.0.0/10, never the default route.
    pub fn is_private(self) -> bool {
        let first = u32::from(self.address);
        let last = first
            | if self.prefix >= 32 {
                0
            } else {
                u32::MAX >> self.prefix
            };
        [
            (0x0A00_0000, 0x0AFF_FFFF),
            (0x6440_0000, 0x647F_FFFF),
            (0xAC10_0000, 0xAC1F_FFFF),
            (0xC0A8_0000, 0xC0A8_FFFF),
        ]
        .iter()
        .any(|(lo, hi)| first >= *lo && last <= *hi)
    }

    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix))
        };
        u32::from(ip) & mask == u32::from(self.address)
    }

    /// nft element text: a host is written bare, anything else as a prefix.
    pub fn nft(self) -> String {
        if self.prefix == 32 {
            self.address.to_string()
        } else {
            self.to_string()
        }
    }
}

impl FromStr for Cidr {
    type Err = anyhow::Error;
    fn from_str(text: &str) -> Result<Self> {
        let (address, prefix) = text
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("CIDR must look like 10.10.0.0/24"))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IPv4 address in {text}"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid prefix length in {text}"))?;
        Self::new(address, prefix)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// A client pool must be private and between /20 and /29; a route between /8 and /32.
pub fn parse_client_cidr(text: &str) -> Result<Cidr> {
    let cidr: Cidr = text.parse()?;
    ensure!(
        cidr.is_private(),
        "client pool must be a private IPv4 subnet (RFC 1918 or 100.64.0.0/10)"
    );
    ensure!(
        (20..=29).contains(&cidr.prefix),
        "client pool prefix must be between /20 and /29"
    );
    Ok(cidr)
}

pub fn parse_route_cidr(text: &str) -> Result<Cidr> {
    let cidr: Cidr = text.parse()?;
    ensure!(
        cidr.is_private(),
        "route must be a private IPv4 subnet, never the default route"
    );
    ensure!(
        (8..=32).contains(&cidr.prefix),
        "route prefix must be between /8 and /32"
    );
    Ok(cidr)
}

/// Base64 Curve25519 key: 44 characters with a canonical final sextet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(String);

impl PublicKey {
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let bytes = text.as_bytes();
        ensure!(
            bytes.len() == 44
                && bytes[43] == b'='
                && b"AEIMQUYcgkosw048".contains(&bytes[42])
                && bytes[..42]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/'),
            "invalid WireGuard key format"
        );
        Ok(Self(text.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Member and network names: 1-32 lowercase letters, digits and hyphens.
pub fn validate_name(text: &str) -> Result<&str> {
    let bytes = text.as_bytes();
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= 32
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            && !text.starts_with('-')
            && !text.ends_with('-'),
        "name must be 1-32 lowercase letters, digits or hyphens"
    );
    Ok(text)
}

pub fn validate_uuid(text: &str) -> Result<String> {
    Ok(uuid::Uuid::parse_str(text)
        .map_err(|_| anyhow::anyhow!("invalid identifier"))?
        .hyphenated()
        .to_string())
}

/// `host:port` for the hub endpoint. Hosts are DNS labels or IPv4 literals.
pub fn validate_endpoint(text: &str) -> Result<String> {
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("endpoint must be host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid endpoint port"))?;
    ensure!(port > 0, "invalid endpoint port");
    ensure!(
        !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')),
        "endpoint host must be a DNS name or IPv4 address"
    );
    Ok(format!("{host}:{port}"))
}

/// Kernel interface names: at most 15 bytes, no whitespace, quotes or slashes.
pub fn validate_ifname(text: &str) -> Result<&str> {
    ensure!(
        !text.is_empty()
            && text.len() <= 15
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            && text != "."
            && text != "..",
        "interface name must be 1-15 letters, digits, '-', '_' or '.'"
    );
    Ok(text)
}

/// Pike-owned names derived from the network id: `pike` + 8 hex characters.
pub fn owned_names(network_id: &str) -> Result<(String, String)> {
    let id =
        uuid::Uuid::parse_str(network_id).map_err(|_| anyhow::anyhow!("invalid network id"))?;
    let short = &id.simple().to_string()[..8];
    Ok((format!("pike{short}"), format!("pike_{short}")))
}

pub fn role_from_str(text: &str) -> Result<&'static str> {
    match text {
        "hub" => Ok("hub"),
        "site" => Ok("site"),
        "client" => Ok("client"),
        _ => bail!("role must be hub, site or client"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_rules() {
        assert_eq!(
            parse_route_cidr("10.10.0.0/24").unwrap().to_string(),
            "10.10.0.0/24"
        );
        assert!(parse_route_cidr("10.10.0.1/24")
            .unwrap_err()
            .to_string()
            .contains("not canonical"));
        assert!(parse_route_cidr("0.0.0.0/0")
            .unwrap_err()
            .to_string()
            .contains("private"));
        assert!(parse_route_cidr("8.8.8.0/24").is_err());
        assert!(parse_route_cidr("10.0.0.0/7").is_err());
        assert!(parse_client_cidr("100.96.0.0/24").is_ok());
        assert!(parse_client_cidr("100.96.0.0/30").is_err());
        assert!(parse_client_cidr("100.96.0.0/16").is_err());
        assert_eq!(parse_route_cidr("10.10.0.7/32").unwrap().nft(), "10.10.0.7");
        assert_eq!(
            parse_route_cidr("10.10.0.0/24").unwrap().nft(),
            "10.10.0.0/24"
        );
        assert!(parse_route_cidr("10.10.0.0/24")
            .unwrap()
            .contains("10.10.0.200".parse().unwrap()));
        assert!(!parse_route_cidr("10.10.0.0/24")
            .unwrap()
            .contains("10.10.1.1".parse().unwrap()));
    }

    #[test]
    fn keys_names_endpoints_and_interfaces() {
        let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(PublicKey::parse(key).is_ok());
        assert!(PublicKey::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=").is_err());
        assert!(PublicKey::parse("short=").is_err());
        assert!(
            PublicKey::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nPrivateKey").is_err()
        );
        assert!(validate_name("site-a").is_ok());
        assert!(validate_name("Site").is_err());
        assert!(validate_name("-a").is_err());
        assert!(validate_name("../x").is_err());
        assert_eq!(
            validate_endpoint("hub.example.test:51820").unwrap(),
            "hub.example.test:51820"
        );
        assert_eq!(
            validate_endpoint("203.0.113.5:51820").unwrap(),
            "203.0.113.5:51820"
        );
        assert!(validate_endpoint("hub:0").is_err());
        assert!(validate_endpoint("hub example:1").is_err());
        assert!(validate_endpoint("[::1]:51820").is_err());
        assert!(validate_ifname("eth1").is_ok());
        assert!(validate_ifname("eth1\" drop").is_err());
        assert!(validate_ifname("averyveryverylongname").is_err());
        let (ifname, table) = owned_names("0f8fad5b-d9cb-469f-a165-70867728950e").unwrap();
        assert_eq!(ifname, "pike0f8fad5b");
        assert_eq!(table, "pike_0f8fad5b");
        assert!(owned_names("nope").is_err());
    }
}
