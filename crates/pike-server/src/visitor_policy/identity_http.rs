//! Outbound identity-provider HTTP is bounded and validated at the actual DNS connector.
use anyhow::{ensure, Context, Result};
use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    Url,
};
use serde::Deserialize;
use std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConfig {
    pub url: String,
    pub ca_path: Option<PathBuf>,
    #[serde(default)]
    pub allow_private_network: bool,
}

pub struct IdentityHttp {
    default_client: reqwest::Client,
    overrides: HashMap<String, (reqwest::Client, bool)>,
    slots: Semaphore,
}
pub struct Document {
    pub body: Vec<u8>,
    pub headers: reqwest::header::HeaderMap,
}
impl IdentityHttp {
    pub fn new(config: &[SourceConfig]) -> Result<Arc<Self>> {
        ensure!(config.len() <= 64, "too many identity HTTP overrides");
        let mut overrides = HashMap::new();
        for source in config {
            let url = validate_url(&source.url)?;
            ensure!(
                overrides
                    .insert(
                        url.to_string(),
                        (
                            client(source.allow_private_network, source.ca_path.as_ref())?,
                            source.allow_private_network
                        )
                    )
                    .is_none(),
                "duplicate identity HTTP override"
            );
        }
        Ok(Arc::new(Self {
            default_client: client(false, None)?,
            overrides,
            slots: Semaphore::new(8),
        }))
    }
    pub fn validate(&self, value: &str) -> Result<Url> {
        let url = validate_url(value)?;
        if !self
            .overrides
            .get(url.as_str())
            .is_some_and(|(_, private)| *private)
        {
            check_host(&url)?;
        }
        Ok(url)
    }
    fn configured(&self, value: &str) -> Result<(Url, &reqwest::Client)> {
        let url = self.validate(value)?;
        let client = self
            .overrides
            .get(url.as_str())
            .map_or(&self.default_client, |(client, _)| client);
        Ok((url, client))
    }
    pub async fn get(&self, value: &str) -> Result<Document> {
        let (url, client) = self.configured(value)?;
        self.execute(client.get(url).header("accept", "application/json"))
            .await
    }
    pub async fn post_form(
        &self,
        value: &str,
        fields: &[(String, String)],
        basic: Option<(&str, &str)>,
    ) -> Result<Document> {
        let (url, client) = self.configured(value)?;
        let mut request = client
            .post(url)
            .form(fields)
            .header("accept", "application/json")
            .timeout(Duration::from_secs(10));
        if let Some((username, password)) = basic {
            request = request.basic_auth(username, Some(password));
        }
        self.execute(request).await
    }
    async fn execute(&self, request: reqwest::RequestBuilder) -> Result<Document> {
        let _permit = self
            .slots
            .try_acquire()
            .context("identity HTTP capacity exceeded")?;
        let mut response = request
            .send()
            .await
            .context("identity provider unavailable")?;
        ensure!(
            response.status().is_success(),
            "identity provider unavailable"
        );
        const MAX_BODY: usize = 64 * 1024;
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_BODY as u64),
            "identity document too large"
        );
        let headers = response.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= MAX_BODY,
                "identity document too large"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(Document { body, headers })
    }
}
fn client(allow_private: bool, ca_path: Option<&PathBuf>) -> Result<reqwest::Client> {
    let mut client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .dns_resolver(Arc::new(PublicResolver { allow_private }));
    if let Some(path) = ca_path {
        client = client.add_root_certificate(reqwest::Certificate::from_pem(
            &std::fs::read(path).context("read identity CA")?,
        )?);
    }
    Ok(client.build()?)
}
fn check_host(url: &Url) -> Result<()> {
    let host = url
        .host_str()
        .context("missing identity host")?
        .trim_matches(['[', ']']);
    if let Ok(ip) = host.parse() {
        ensure!(
            public_ip(ip),
            "private identity address requires an operator override"
        );
    }
    ensure!(
        host != "localhost"
            && !host.ends_with(".localhost")
            && host.rsplit('.').next() != Some("local"),
        "local identity name requires an operator override"
    );
    Ok(())
}
pub fn validate_url(value: &str) -> Result<Url> {
    ensure!(
        value.len() <= 2048 && !value.bytes().any(|c| c <= 32 || c == 127),
        "invalid identity URL"
    );
    let url = Url::parse(value)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "identity requires HTTPS without credentials or fragments"
    );
    Ok(url)
}
struct PublicResolver {
    allow_private: bool,
}
impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let allow_private = self.allow_private;
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if addresses.is_empty()
                || (!allow_private && addresses.iter().any(|addr| !public_ip(addr.ip())))
            {
                return Err(std::io::Error::other("non-public identity DNS answer").into());
            }
            // The connector receives exactly the addresses we validated.
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}
pub(super) fn public_ip(ip: IpAddr) -> bool {
    let ip = super::canonical_ip(ip);
    let excluded: &[&str] = match ip {
        IpAddr::V4(_) => &[
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/3",
        ],
        IpAddr::V6(_) => {
            if !"2000::/3".parse::<ipnet::IpNet>().unwrap().contains(&ip) {
                return false;
            }
            &["2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"]
        }
    };
    !excluded
        .iter()
        .any(|cidr| cidr.parse::<ipnet::IpNet>().unwrap().contains(&ip))
}
