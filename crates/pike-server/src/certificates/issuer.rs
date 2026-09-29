use super::{
    shared::{Lease, Shared},
    storage::Storage,
    AcmeConfig, Authority, Challenge, Challenges,
};
use anyhow::{ensure, Context, Result};
use axum::{body::Bytes, http};
use http_body_util::{BodyExt, Full};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, Key, NewOrder,
    OrderStatus, RetryPolicy,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

#[derive(Clone)]
struct Http {
    client: reqwest::Client,
    origin: String,
}
impl instant_acme::HttpClient for Http {
    fn request(
        &self,
        request: http::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        let this = self.clone();
        Box::pin(async move {
            let result: Result<_> = async {
                let (parts, body) = request.into_parts();
                let url = reqwest::Url::parse(&parts.uri.to_string())?;
                ensure!(
                    url.scheme() == "https"
                        && url.origin().ascii_serialization() == this.origin
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none(),
                    "ACME URL left the configured CA origin"
                );
                let body = body.collect().await?.to_bytes();
                let mut response = this
                    .client
                    .request(parts.method, url)
                    .headers(parts.headers)
                    .body(body)
                    .send()
                    .await?;
                ensure!(
                    !response.status().is_redirection(),
                    "ACME redirects are refused"
                );
                ensure!(
                    response
                        .content_length()
                        .is_none_or(|size| size <= 1024 * 1024),
                    "ACME response exceeds limit"
                );
                let mut output = http::Response::builder()
                    .status(response.status())
                    .version(response.version());
                *output.headers_mut().expect("valid response builder") = response.headers().clone();
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    ensure!(
                        bytes.len() + chunk.len() <= 1024 * 1024,
                        "ACME response exceeds limit"
                    );
                    bytes.extend_from_slice(&chunk);
                }
                Ok(instant_acme::BytesResponse::from(
                    output.body(Full::new(Bytes::from(bytes)))?,
                ))
            }
            .await;
            result.map_err(|error| instant_acme::Error::Other(error.into_boxed_dyn_error()))
        })
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "state")]
enum AccountState {
    Pending {
        directory: String,
        key_pkcs8: Vec<u8>,
    },
    Ready {
        directory: String,
        credentials: Box<AccountCredentials>,
    },
}
pub(super) struct Issuer {
    config: AcmeConfig,
    storage: Arc<Storage>,
    shared: Option<Arc<Shared>>,
    http: Http,
    account: tokio::sync::Mutex<Option<Account>>,
}
impl Issuer {
    pub async fn new(
        config: AcmeConfig,
        storage: Arc<Storage>,
        shared: Option<Arc<Shared>>,
    ) -> Result<Self> {
        let url = config.validate()?;
        let mut client = reqwest::Client::builder()
            .user_agent(concat!("pike-server/", env!("CARGO_PKG_VERSION"), " ACME"))
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5));
        if let Some(path) = &config.directory_ca_path {
            let bytes = tokio::fs::read(path).await?;
            ensure!(bytes.len() <= 65536, "ACME directory CA exceeds limit");
            let mut count = 0;
            for certificate in CertificateDer::pem_slice_iter(&bytes) {
                count += 1;
                client = client
                    .add_root_certificate(reqwest::Certificate::from_der(certificate?.as_ref())?);
            }
            ensure!(
                count > 0 && count <= 16,
                "ACME directory CA bundle must contain 1 to 16 certificates"
            );
        }
        Ok(Self {
            http: Http {
                client: client.build()?,
                origin: url.origin().ascii_serialization(),
            },
            config,
            storage,
            shared,
            account: tokio::sync::Mutex::new(None),
        })
    }
    async fn account(&self) -> Result<Account> {
        let mut cached = self.account.lock().await;
        if self.shared.is_none() {
            if let Some(account) = &*cached {
                return Ok(account.clone());
            }
        }
        let stored = match &self.shared {
            Some(shared) => shared.account::<AccountState>().await?,
            None => self.storage.read::<AccountState>("account.json")?,
        };
        let state = if let Some(state) = stored {
            state
        } else {
            let (_, key) = Key::generate_pkcs8()?;
            let state = AccountState::Pending {
                directory: self.config.directory_url.clone(),
                key_pkcs8: key.secret_pkcs8_der().to_vec(),
            };
            // Persist before contacting the CA. Ambiguous creation/restart
            // then recovers the same account key instead of creating another.
            if let Some(shared) = &self.shared {
                shared.initialize_account(&state).await?
            } else {
                self.storage.write("account.json", &state)?;
                state
            }
        };
        let builder = Account::builder_with_http(Box::new(self.http.clone()));
        let account = match state {
            AccountState::Ready {
                directory,
                credentials,
            } => {
                ensure!(
                    directory == self.config.directory_url,
                    "ACME state belongs to a different directory"
                );
                builder.from_credentials(*credentials).await?
            }
            AccountState::Pending {
                directory,
                key_pkcs8,
            } => {
                ensure!(
                    directory == self.config.directory_url,
                    "ACME state belongs to a different directory"
                );
                let pending = AccountState::Pending {
                    directory: directory.clone(),
                    key_pkcs8: key_pkcs8.clone(),
                };
                let der = PrivatePkcs8KeyDer::from(key_pkcs8);
                let key = Key::from_pkcs8_der(der.clone_key())?;
                let (account, credentials) = builder
                    .create_from_key((key, PrivateKeyDer::Pkcs8(der)), directory.clone())
                    .await?;
                let ready = AccountState::Ready {
                    directory,
                    credentials: Box::new(credentials),
                };
                match &self.shared {
                    Some(shared) => shared.finish_account(&pending, &ready).await?,
                    None => self.storage.write("account.json", &ready)?,
                }
                account
            }
        };
        let contact = format!("mailto:{}", self.config.contact_email);
        account.update_contacts(&[contact.as_str()]).await?;
        if self.shared.is_none() {
            *cached = Some(account.clone());
        }
        Ok(account)
    }
    pub async fn issue(
        &self,
        authority: Arc<Authority>,
        challenges: &Challenges,
        shared: Option<&Lease>,
    ) -> Result<(String, String)> {
        ensure!(authority.active(), "hostname authorization ended");
        let account = self.account().await?;
        let identifiers = [Identifier::Dns(authority.hostname.clone())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
        let mut guards = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authorization = result?;
            ensure!(
                authorization.identifier().to_string() == authority.hostname,
                "ACME authorization identifier changed"
            );
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => anyhow::bail!("ACME authorization is not usable"),
            }
            let mut challenge = authorization
                .challenge(ChallengeType::Http01)
                .context("CA did not offer HTTP-01")?;
            let token = challenge.token.clone();
            ensure!(
                token.len() <= 256
                    && !token.is_empty()
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "invalid ACME challenge token"
            );
            let value = challenge.key_authorization().as_str().to_owned();
            ensure!(value.len() <= 512, "ACME challenge response exceeds limit");
            if let Some(lease) = shared {
                lease.publish(&token, &value).await?;
            } else {
                guards.push(challenges.publish(Challenge {
                    authority: authority.clone(),
                    token,
                    value,
                })?);
            }
            challenge.set_ready().await?;
        }
        let retry = RetryPolicy::new().timeout(Duration::from_secs(60));
        ensure!(
            order.poll_ready(&retry).await? == OrderStatus::Ready,
            "ACME order did not become ready"
        );
        ensure!(authority.active(), "hostname authorization ended");
        let key = order.finalize().await?;
        let chain = order.poll_certificate(&retry).await?;
        drop(guards);
        Ok((chain, key))
    }
}
