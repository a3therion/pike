//! Origin selection, verified TLS and HTTP protocol negotiation.
use anyhow::{bail, ensure, Context, Result};
use axum::http::{header::HOST, request::Parts, HeaderValue, Uri, Version};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::timeout,
};

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, PartialEq, Eq)]
pub enum OriginProtocol {
    #[default]
    Auto,
    Http1,
    Http2,
}

#[derive(Clone, Debug, Default, clap::Args)]
pub struct OriginOptions {
    /// Origin URL. Repeat for a pool; URLs cannot contain paths or credentials.
    #[arg(long, conflicts_with_all = ["port", "unix_socket"])]
    pub upstream: Vec<String>,
    /// Connect to an HTTP server through this Unix domain socket.
    #[arg(long, conflicts_with_all = ["port", "upstream"])]
    pub unix_socket: Option<PathBuf>,
    /// Auto negotiates TLS ALPN; cleartext defaults to HTTP/1.1. Use http2 for h2c.
    #[arg(long, value_enum, default_value = "auto")]
    pub upstream_protocol: OriginProtocol,
    /// Additional trusted CA certificates for an HTTPS origin (PEM).
    #[arg(long)]
    pub origin_ca: Option<PathBuf>,
    /// Certificate DNS name for an HTTPS origin; defaults to the URL hostname.
    #[arg(long)]
    pub origin_server_name: Option<String>,
}

#[derive(Clone)]
enum Address {
    Tcp { host: String, port: u16 },
    Unix(PathBuf),
}

#[derive(Clone)]
pub struct Origin {
    address: Address,
    authority: String,
    protocol: OriginProtocol,
    tls: Option<Arc<rustls::ClientConfig>>,
    server_name: Option<ServerName<'static>>,
}

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
pub type OriginIo = Box<dyn AsyncIo>;

impl Origin {
    pub fn from_options(port: Option<u16>, host: &str, options: OriginOptions) -> Result<Self> {
        let (address, authority, tls_host) = if let Some(path) = options.unix_socket {
            ensure!(
                port.is_none() && options.upstream.is_empty(),
                "Unix socket cannot be combined with a port or URL"
            );
            ensure!(path.is_absolute(), "Unix socket path must be absolute");
            (Address::Unix(path), "localhost".to_string(), None)
        } else if let Some(url) = options.upstream.first() {
            ensure!(
                options.upstream.len() == 1,
                "single origin requires exactly one URL"
            );
            ensure!(port.is_none(), "origin URL cannot be combined with a port");
            let url = reqwest::Url::parse(url).context("invalid origin URL")?;
            ensure!(
                matches!(url.scheme(), "http" | "https"),
                "origin URL must use http or https"
            );
            ensure!(
                url.username().is_empty() && url.password().is_none(),
                "origin URL must not contain credentials"
            );
            ensure!(
                url.path() == "/" && url.query().is_none() && url.fragment().is_none(),
                "origin URL must not contain a path, query or fragment"
            );
            let host = url
                .host_str()
                .context("origin hostname required")?
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
            let port = url
                .port_or_known_default()
                .context("origin port required")?;
            ensure!(port > 0, "origin port must be positive");
            let authority = socket_authority(&host, port);
            let tls_host = (url.scheme() == "https").then(|| host.clone());
            (Address::Tcp { host, port }, authority, tls_host)
        } else {
            let port = port.context("provide a port, --upstream URL or --unix-socket path")?;
            ensure!(port > 0, "origin port must be positive");
            ensure!(!host.is_empty(), "origin host required");
            (
                Address::Tcp {
                    host: host.to_owned(),
                    port,
                },
                socket_authority(host, port),
                None,
            )
        };
        let (tls, server_name) = if let Some(host) = tls_host {
            let name = ServerName::try_from(options.origin_server_name.unwrap_or(host))
                .context("invalid origin certificate name")?;
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(path) = options.origin_ca {
                let pem = std::fs::read(&path)
                    .with_context(|| format!("cannot read origin CA {}", path.display()))?;
                let certs = CertificateDer::pem_slice_iter(&pem)
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                ensure!(!certs.is_empty(), "origin CA file contains no certificates");
                for cert in certs {
                    roots.add(cert).context("invalid origin CA certificate")?;
                }
            }
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.alpn_protocols = match options.upstream_protocol {
                OriginProtocol::Auto => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                OriginProtocol::Http1 => vec![b"http/1.1".to_vec()],
                OriginProtocol::Http2 => vec![b"h2".to_vec()],
            };
            (Some(Arc::new(config)), Some(name))
        } else {
            ensure!(
                options.origin_ca.is_none() && options.origin_server_name.is_none(),
                "origin CA and certificate name require an HTTPS URL"
            );
            (None, None)
        };
        Ok(Self {
            address,
            authority,
            protocol: options.upstream_protocol,
            tls,
            server_name,
        })
    }

    pub fn display(&self) -> String {
        match &self.address {
            Address::Unix(path) => format!("unix:{}", path.display()),
            Address::Tcp { .. } => format!("{}://{}", self.scheme(), self.authority),
        }
    }

    /// The original wire fields are informational SocketAddr hints. DNS names
    /// and Unix paths are resolved only by this local connector, never the relay.
    pub fn registration_address(&self) -> SocketAddr {
        match &self.address {
            Address::Tcp { host, port } => SocketAddr::new(
                host.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                *port,
            ),
            Address::Unix(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }

    fn scheme(&self) -> &'static str {
        if self.tls.is_some() {
            "https"
        } else {
            "http"
        }
    }

    pub async fn connect(&self, websocket: bool) -> Result<(OriginIo, OriginProtocol)> {
        timeout(Duration::from_secs(5), self.connect_inner(websocket))
            .await
            .context("origin connection or TLS handshake timed out")?
    }

    async fn connect_inner(&self, websocket: bool) -> Result<(OriginIo, OriginProtocol)> {
        let io: OriginIo = match &self.address {
            Address::Tcp { host, port } => {
                let socket = TcpStream::connect((host.as_str(), *port))
                    .await
                    .context("origin TCP connect failed")?;
                socket.set_nodelay(true)?;
                Box::new(socket)
            }
            Address::Unix(path) => {
                #[cfg(unix)]
                {
                    Box::new(
                        tokio::net::UnixStream::connect(path)
                            .await
                            .context("origin Unix socket connect failed")?,
                    )
                }
                #[cfg(not(unix))]
                {
                    let _ = path;
                    bail!("Unix socket origins are unavailable on this platform");
                }
            }
        };
        if let Some(config) = &self.tls {
            let config = if websocket {
                let mut config = (**config).clone();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                Arc::new(config)
            } else {
                config.clone()
            };
            let stream = tokio_rustls::TlsConnector::from(config)
                .connect(
                    self.server_name
                        .clone()
                        .context("HTTPS certificate name missing")?,
                    io,
                )
                .await
                .context("origin TLS verification or handshake failed")?;
            let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            if !websocket && self.protocol == OriginProtocol::Http2 {
                ensure!(h2, "origin did not negotiate HTTP/2");
            }
            Ok((
                Box::new(stream),
                if h2 {
                    OriginProtocol::Http2
                } else {
                    OriginProtocol::Http1
                },
            ))
        } else {
            Ok((
                io,
                if !websocket && self.protocol == OriginProtocol::Http2 {
                    OriginProtocol::Http2
                } else {
                    OriginProtocol::Http1
                },
            ))
        }
    }

    pub fn prepare_request(&self, parts: &mut Parts, protocol: OriginProtocol) -> Result<()> {
        let authority = parts
            .headers
            .get(HOST)
            .map_or(Ok(self.authority.as_str()), |value| value.to_str())?;
        if protocol == OriginProtocol::Http2 {
            parts.uri = Uri::builder()
                .scheme(self.scheme())
                .authority(authority)
                .path_and_query(
                    parts
                        .uri
                        .path_and_query()
                        .map_or("/", |value| value.as_str()),
                )
                .build()?;
            parts.version = Version::HTTP_2;
            parts.headers.remove(HOST);
            parts
                .headers
                .insert("te", HeaderValue::from_static("trailers"));
        } else {
            parts.version = Version::HTTP_11;
            if !parts.headers.contains_key(HOST) {
                parts.headers.insert(HOST, self.authority.parse()?);
            }
        }
        Ok(())
    }
}

fn socket_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambiguous_or_unsafe_origin_options() {
        for upstream in [
            "ftp://localhost:21",
            "http://user:pass@localhost:80",
            "http://localhost/path",
            "https://localhost/?token=x",
            "http://localhost/#fragment",
        ] {
            assert!(
                Origin::from_options(
                    None,
                    "127.0.0.1",
                    OriginOptions {
                        upstream: vec![upstream.into()],
                        ..Default::default()
                    }
                )
                .is_err(),
                "{upstream}"
            );
        }
        assert!(Origin::from_options(None, "127.0.0.1", OriginOptions::default()).is_err());
        assert!(Origin::from_options(
            Some(80),
            "127.0.0.1",
            OriginOptions {
                origin_server_name: Some("localhost".into()),
                ..Default::default()
            }
        )
        .is_err());
        assert!(Origin::from_options(
            None,
            "127.0.0.1",
            OriginOptions {
                unix_socket: Some("relative.sock".into()),
                ..Default::default()
            }
        )
        .is_err());
    }

    #[test]
    fn ipv6_and_http2_origin_authority_preserve_public_host_and_path() {
        let origin = Origin::from_options(
            None,
            "127.0.0.1",
            OriginOptions {
                upstream: vec!["http://[::1]:8080".into()],
                upstream_protocol: OriginProtocol::Http2,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(origin.display(), "http://[::1]:8080");
        assert_eq!(origin.registration_address(), "[::1]:8080".parse().unwrap());
        let (mut parts, ()) = hyper::Request::builder()
            .uri("/foo?q=a%2Fb")
            .header("host", "public.pike.test")
            .body(())
            .unwrap()
            .into_parts();
        origin
            .prepare_request(&mut parts, OriginProtocol::Http2)
            .unwrap();
        assert_eq!(parts.uri.to_string(), "http://public.pike.test/foo?q=a%2Fb");
        assert!(!parts.headers.contains_key("host"));
        assert_eq!(parts.headers["te"], "trailers");
    }
}
