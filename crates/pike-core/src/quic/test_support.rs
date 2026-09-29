//! Real QUIC packet exchange in memory: no public network or test server needed.
use tokio_quiche::{quic::QuicheConnection, quiche};

pub(super) struct Pair {
    pub client: QuicheConnection,
    pub server: QuicheConnection,
}

impl Pair {
    pub fn new() -> Self {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config.set_application_protos(&[b"pike/1"]).unwrap();
        config.verify_peer(false);
        config.set_initial_max_data(64 * 1024);
        config.set_initial_max_stream_data_bidi_local(16 * 1024);
        config.set_initial_max_stream_data_bidi_remote(16 * 1024);
        config.set_initial_max_streams_bidi(100);
        config
            .load_cert_chain_from_pem_file(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/quic-test-cert.pem"
            ))
            .unwrap();
        config
            .load_priv_key_from_pem_file(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/quic-test-key.pem"
            ))
            .unwrap();
        let client_addr = "127.0.0.1:10000".parse().unwrap();
        let server_addr = "127.0.0.1:10001".parse().unwrap();
        let scid = quiche::ConnectionId::from_ref(&[1; 16]);
        let mut client = quiche::connect(
            Some("localhost"),
            &scid,
            client_addr,
            server_addr,
            &mut config,
        )
        .unwrap();
        let mut buf = vec![0; 65535];
        let (written, _) = client.send(&mut buf).unwrap();
        let header = quiche::Header::from_slice(&mut buf[..written], 16).unwrap();
        let mut server =
            quiche::accept(&header.dcid, None, server_addr, client_addr, &mut config).unwrap();
        server
            .recv(
                &mut buf[..written],
                quiche::RecvInfo {
                    from: client_addr,
                    to: server_addr,
                },
            )
            .unwrap();
        let mut pair = Self { client, server };
        for _ in 0..20 {
            pair.exchange();
            if pair.client.is_established() && pair.server.is_established() {
                return pair;
            }
        }
        panic!("QUIC handshake did not complete");
    }

    pub fn exchange(&mut self) {
        Self::transfer(&mut self.client, &mut self.server);
        Self::transfer(&mut self.server, &mut self.client);
    }

    fn transfer(from: &mut QuicheConnection, to: &mut QuicheConnection) {
        let mut packet = vec![0; 65535];
        loop {
            match from.send(&mut packet) {
                Ok((written, info)) => {
                    to.recv(
                        &mut packet[..written],
                        quiche::RecvInfo {
                            from: info.from,
                            to: info.to,
                        },
                    )
                    .unwrap();
                }
                Err(quiche::Error::Done) => break,
                Err(error) => panic!("QUIC send failed: {error}"),
            }
        }
    }
}
