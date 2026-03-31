use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderValue, Request, Response, StatusCode};
use tower::{Layer, Service};

use crate::connection::validate_api_key;
use crate::registry::ClientRegistry;

const API_KEY_HEADER: &str = "x-api-key";
const WEBSOCKET_TUNNEL_PATH: &str = "/ws/tunnel";

#[derive(Clone)]
pub struct AuthLayer {
    registry: Arc<ClientRegistry>,
}

impl AuthLayer {
    #[must_use]
    pub fn new(registry: Arc<ClientRegistry>) -> Self {
        Self { registry }
    }
}

#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    registry: Arc<ClientRegistry>,
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            registry: self.registry.clone(),
        }
    }
}

impl<S> Service<Request<Body>> for AuthService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        if req.uri().path() != WEBSOCKET_TUNNEL_PATH {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(req).await });
        }

        let api_key = extract_api_key(&req);
        let invalid = api_key
            .as_ref()
            .is_none_or(|key| validate_api_key(key, false).is_err());

        if invalid
            || !self
                .registry
                .is_api_key_allowed(api_key.unwrap_or_default())
        {
            return Box::pin(async { Ok(unauthorized_response()) });
        }

        let mut inner = self.inner.clone();
        Box::pin(async move { inner.call(req).await })
    }
}

fn unauthorized_response() -> Response<Body> {
    let mut response = Response::new(Body::from("unauthorized: invalid API key"));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    let _ = response.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("ApiKey realm=\"pike\""),
    );
    response
}

fn extract_api_key(request: &Request<Body>) -> Option<&str> {
    if let Some(raw) = request
        .headers()
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        return Some(raw);
    }

    let auth = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let (_, key) = auth.split_once(' ')?;
    if auth.to_ascii_lowercase().starts_with("bearer ") {
        return Some(key);
    }

    None
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::{Layer, Service, ServiceExt};

    use super::AuthLayer;
    use crate::registry::ClientRegistry;

    #[tokio::test]
    async fn rejects_missing_api_key_for_websocket_tunnel() {
        let registry = std::sync::Arc::new(ClientRegistry::new());
        let layer = AuthLayer::new(registry);
        let service = tower::service_fn(|_req: Request<Body>| async {
            Ok::<_, std::convert::Infallible>(axum::response::Response::new(Body::empty()))
        });
        let mut service = layer.layer(service);

        let request = Request::builder()
            .uri("/ws/tunnel")
            .body(Body::empty())
            .expect("request");
        let response = service
            .ready()
            .await
            .expect("ready")
            .call(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn allows_non_ws_routes_without_api_key() {
        let registry = std::sync::Arc::new(ClientRegistry::new());
        let layer = AuthLayer::new(registry);
        let service = tower::service_fn(|_req: Request<Body>| async {
            Ok::<_, std::convert::Infallible>(axum::response::Response::new(Body::empty()))
        });
        let mut service = layer.layer(service);

        let request = Request::builder()
            .uri("/demo")
            .body(Body::empty())
            .expect("request");
        let response = service
            .ready()
            .await
            .expect("ready")
            .call(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
