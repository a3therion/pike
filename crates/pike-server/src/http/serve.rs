//! Bounded HTTP serving for every downstream listener: the plain listener, the
//! native HTTPS listener and the owner's injected hop connections.
//!
//! `axum::serve` detaches each connection onto its own task, so once its
//! graceful shutdown starts nothing can end a connection whose peer never
//! finishes reading its response, and dropping the serve future does not close
//! those sockets either. Here every connection is a task owned by one
//! `JoinSet`: on shutdown the accept loop stops, each open connection is asked
//! to finish gracefully, and whatever is still open when the bound expires is
//! aborted, which drops and therefore closes its socket. The application, its
//! layers and the exact per-listener `ConnectInfo` are unchanged.
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response},
    serve::Listener,
    Router,
};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use std::{convert::Infallible, future::Future, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::watch,
    task::JoinSet,
};

/// Time an open connection has to finish on its own after shutdown begins
/// before it is aborted. `main` has already spent its configured drain on the
/// connector registry by the time the HTTP servers observe shutdown, so this
/// only has to cover requests that are about to complete anyway.
pub const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

/// The application with one connection's verified peer attached as
/// `ConnectInfo`, exactly what `into_make_service_with_connect_info` produces.
#[derive(Clone)]
struct PeerService<C> {
    app: Router,
    peer: C,
}

impl<C> hyper::service::Service<Request<Incoming>> for PeerService<C>
where
    C: Clone + Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let mut request = request.map(Body::new);
        request
            .extensions_mut()
            .insert(ConnectInfo(self.peer.clone()));
        let mut app = self.app.clone();
        Box::pin(async move { tower::Service::call(&mut app, request).await })
    }
}

/// Serve `app` on `listener` until `shutdown` fires, then finish within
/// `drain`. `peer` derives the connection's `ConnectInfo` from the accepted
/// stream, so each listener keeps its exact identity type.
pub(super) async fn serve_bounded<L, C>(
    mut listener: L,
    app: Router,
    peer: fn(&L::Io, &L::Addr) -> C,
    mut shutdown: watch::Receiver<bool>,
    drain: Duration,
) where
    L: Listener,
    C: Clone + Send + Sync + 'static,
{
    let mut connections: JoinSet<()> = JoinSet::new();
    let connection_shutdown = shutdown.clone();
    loop {
        tokio::select! {
            _ = shutdown.wait_for(|stop| *stop) => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            (io, addr) = listener.accept() => {
                let service = PeerService { app: app.clone(), peer: peer(&io, &addr) };
                connections.spawn(serve_connection(io, service, connection_shutdown.clone()));
            }
        }
    }
    // A TCP listener releases its port here; channel-backed listeners simply
    // stop taking connections.
    drop(listener);
    let graceful = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(drain, graceful).await.is_err() {
        tracing::warn!(
            open = connections.len(),
            "HTTP connections still open after the shutdown bound; closing them"
        );
    }
    connections.shutdown().await;
}

/// One connection: HTTP/1.1 or HTTP/2 by inspection, with upgrades. When
/// shutdown fires hyper stops accepting requests and finishes the ones in
/// flight; the caller's bound ends anything that never does.
async fn serve_connection<I, C>(io: I, service: PeerService<C>, mut shutdown: watch::Receiver<bool>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    C: Clone + Send + Sync + 'static,
{
    let mut builder = Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new());
    builder.http2().timer(TokioTimer::new());
    let mut connection =
        std::pin::pin!(builder.serve_connection_with_upgrades(TokioIo::new(io), service));
    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%error, "HTTP connection ended with an error");
            }
            return;
        }
        _ = shutdown.wait_for(|stop| *stop) => {}
    }
    connection.as_mut().graceful_shutdown();
    let _ = connection.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Bytes, routing::get};
    use http_body_util::BodyExt;
    use std::{net::SocketAddr, time::Instant};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    fn endless() -> Body {
        Body::from_stream(futures_util::stream::repeat_with(|| {
            Ok::<_, Infallible>(Bytes::from_static(&[7_u8; 16_384]))
        }))
    }

    async fn peer_echo(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
        tokio::time::sleep(Duration::from_millis(300)).await;
        addr.to_string()
    }

    fn app() -> Router {
        Router::new()
            .route("/peer", get(peer_echo))
            .route("/endless", get(|| async { endless() }))
    }

    async fn start(
        drain: Duration,
    ) -> (SocketAddr, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, shutdown) = watch::channel(false);
        let server = tokio::spawn(serve_bounded(
            listener,
            app(),
            |_: &TcpStream, addr: &SocketAddr| *addr,
            shutdown,
            drain,
        ));
        (addr, stop, server)
    }

    /// Reads until the peer closes or errors; returns how many bytes arrived.
    async fn drain_until_closed(mut socket: TcpStream) -> usize {
        let mut total = 0;
        let mut buffer = vec![0_u8; 65_536];
        loop {
            match socket.read(&mut buffer).await {
                Ok(0) | Err(_) => return total,
                Ok(count) => total += count,
            }
        }
    }

    #[tokio::test]
    async fn in_flight_requests_finish_with_their_exact_connect_info_and_new_connections_are_refused(
    ) {
        let (addr, stop, server) = start(Duration::from_secs(5)).await;
        let mut socket = TcpStream::connect(addr).await.unwrap();
        let local = socket.local_addr().unwrap();
        socket
            .write_all(b"GET /peer HTTP/1.1\r\nhost: pike.test\r\n\r\n")
            .await
            .unwrap();
        // Shutdown arrives while the handler is still running.
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.send_replace(true);
        let started = Instant::now();
        let response = String::from_utf8(
            timeout(Duration::from_secs(5), async {
                let mut bytes = Vec::new();
                socket.read_to_end(&mut bytes).await.unwrap();
                bytes
            })
            .await
            .unwrap(),
        )
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with(&local.to_string()), "{response}");
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        // The in-flight request completed on its own, well inside the bound, and
        // the listener socket is gone.
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(TcpStream::connect(addr).await.is_err());
    }

    #[tokio::test]
    async fn an_endless_response_over_http1_is_cut_at_the_bound_even_when_the_peer_stops_reading() {
        let (addr, stop, server) = start(Duration::from_millis(500)).await;
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /endless HTTP/1.1\r\nhost: pike.test\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0_u8; 12];
        socket.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 200");
        // The peer stops reading here; nothing is polled until after shutdown.
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.send_replace(true);
        let started = Instant::now();
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        // The socket was closed under the peer; whatever was buffered is finite.
        timeout(Duration::from_secs(5), drain_until_closed(socket))
            .await
            .expect("connection closed by the server");
    }

    #[tokio::test]
    async fn an_http2_response_whose_peer_never_polls_the_body_is_cut_at_the_bound() {
        let (addr, stop, server) = start(Duration::from_millis(500)).await;
        let socket = TcpStream::connect(addr).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .initial_stream_window_size(16_384)
                .initial_connection_window_size(16_384)
                .handshake(TokioIo::new(socket))
                .await
                .unwrap();
        let driver = tokio::spawn(async move { connection.await });
        let request = Request::builder()
            .uri("http://pike.test/endless")
            .body(Body::empty())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), 200);
        // The body is never polled, so the server side cannot make progress on
        // this stream by itself.
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.send_replace(true);
        let started = Instant::now();
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
        // The connection under the unread response is gone, and the response can
        // never be mistaken for complete.
        let _ = timeout(Duration::from_secs(5), driver)
            .await
            .expect("client connection ended once the server closed it");
        let mut body = response.into_body();
        let outcome = timeout(Duration::from_secs(5), async {
            loop {
                match body.frame().await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error),
                    None => return Ok(()),
                }
            }
        })
        .await
        .unwrap();
        assert!(outcome.is_err(), "a cut response must not end cleanly");
    }
}
