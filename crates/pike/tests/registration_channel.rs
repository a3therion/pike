use pike_core::quic::client::RegistrationResult;
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn oneshot_channel_resolves_on_tunnel_registered() {
    let (tx, rx) = oneshot::channel::<RegistrationResult>();

    tx.send(RegistrationResult {
        public_url: "https://test.pike.life".to_string(),
        remote_port: None,
    })
    .unwrap();

    let result = rx.await.unwrap();
    assert_eq!(result.public_url, "https://test.pike.life");
    assert!(result.remote_port.is_none());
}

#[tokio::test]
async fn oneshot_channel_timeout_when_no_response() {
    let (_tx, rx) = oneshot::channel::<RegistrationResult>();

    let result = timeout(Duration::from_millis(100), rx).await;
    assert!(result.is_err(), "should timeout when server never responds");
}

#[tokio::test]
async fn public_url_passthrough_preserves_server_value() {
    let (tx, rx) = oneshot::channel::<RegistrationResult>();

    let server_url = "https://my-custom-subdomain.pike.life".to_string();
    tx.send(RegistrationResult {
        public_url: server_url.clone(),
        remote_port: Some(9999),
    })
    .unwrap();

    let result = rx.await.unwrap();
    assert_eq!(result.public_url, server_url);
    assert_eq!(result.remote_port, Some(9999));
}

#[tokio::test]
async fn channel_closed_when_sender_dropped() {
    let (tx, rx) = oneshot::channel::<RegistrationResult>();
    drop(tx);

    let result = rx.await;
    assert!(
        result.is_err(),
        "should error when sender is dropped (connection lost)"
    );
}

#[tokio::test]
async fn timeout_fires_before_late_response() {
    let (tx, rx) = oneshot::channel::<RegistrationResult>();

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = tx.send(RegistrationResult {
            public_url: "https://late.pike.life".to_string(),
            remote_port: None,
        });
    });

    let result = timeout(Duration::from_millis(50), rx).await;
    assert!(
        result.is_err(),
        "should timeout before late response arrives"
    );

    handle.await.unwrap();
}
