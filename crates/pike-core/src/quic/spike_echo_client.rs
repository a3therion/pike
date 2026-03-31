use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::{HandshakeInfo, QuicheConnection};
use tokio_quiche::{quiche, ApplicationOverQuic, QuicResult};

pub const CLIENT_BIDI_STREAM_ID: u64 = 4;
pub const SERVER_BIDI_STREAM_ID: u64 = 1;

#[derive(Debug)]
pub enum ClientCommand {
    Close,
}

#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connected,
    EchoReceived(Vec<u8>),
    ServerInitiatedReceived(Vec<u8>),
    Closed,
}

#[derive(Debug)]
struct PendingWrite {
    stream_id: u64,
    payload: Vec<u8>,
    offset: usize,
    fin: bool,
}

pub struct SpikeEchoClient {
    scratch: Vec<u8>,
    stream_buffers: HashMap<u64, Vec<u8>>,
    pending_writes: VecDeque<PendingWrite>,
    command_rx: mpsc::Receiver<ClientCommand>,
    event_tx: mpsc::Sender<ClientEvent>,
    hello_payload: Vec<u8>,
    close_requested: bool,
}

impl SpikeEchoClient {
    #[must_use]
    pub fn new(
        event_tx: mpsc::Sender<ClientEvent>,
        command_rx: mpsc::Receiver<ClientCommand>,
        hello_payload: Vec<u8>,
    ) -> Self {
        Self {
            scratch: vec![0; 64 * 1024],
            stream_buffers: HashMap::new(),
            pending_writes: VecDeque::new(),
            command_rx,
            event_tx,
            hello_payload,
            close_requested: false,
        }
    }

    fn emit(&self, event: ClientEvent) {
        let _ = self.event_tx.try_send(event);
    }
}

impl ApplicationOverQuic for SpikeEchoClient {
    fn on_conn_established(
        &mut self,
        _qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.pending_writes.push_back(PendingWrite {
            stream_id: CLIENT_BIDI_STREAM_ID,
            payload: self.hello_payload.clone(),
            offset: 0,
            fin: true,
        });

        self.emit(ClientEvent::Connected);
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.scratch
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        tokio::select! {
            _cmd = self.command_rx.recv() => self.close_requested = true,
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        for stream_id in qconn.readable() {
            loop {
                match qconn.stream_recv(stream_id, &mut self.scratch) {
                    Ok((n, fin)) => {
                        let stream_buf = self.stream_buffers.entry(stream_id).or_default();
                        stream_buf.extend_from_slice(&self.scratch[..n]);

                        if fin {
                            let payload =
                                self.stream_buffers.remove(&stream_id).unwrap_or_default();
                            if stream_id == CLIENT_BIDI_STREAM_ID {
                                self.emit(ClientEvent::EchoReceived(payload));
                            } else if stream_id == SERVER_BIDI_STREAM_ID {
                                self.emit(ClientEvent::ServerInitiatedReceived(payload));
                            }

                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        while let Some(mut write) = self.pending_writes.pop_front() {
            match qconn.stream_send(write.stream_id, &write.payload[write.offset..], write.fin) {
                Ok(written) => {
                    write.offset += written;

                    if write.offset < write.payload.len() {
                        self.pending_writes.push_front(write);
                        break;
                    }
                }
                Err(quiche::Error::Done) => {
                    self.pending_writes.push_front(write);
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        if self.close_requested {
            let _ = qconn.close(true, 0, b"spike complete");
        }

        Ok(())
    }

    fn on_conn_close<M: Metrics>(
        &mut self,
        _qconn: &mut QuicheConnection,
        _metrics: &M,
        _result: &QuicResult<()>,
    ) {
        self.emit(ClientEvent::Closed);
    }
}
