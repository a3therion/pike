use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_quiche::metrics::Metrics;
use tokio_quiche::quic::{HandshakeInfo, QuicheConnection};
use tokio_quiche::{quiche, ApplicationOverQuic, QuicResult};

pub const CLIENT_BIDI_STREAM_ID: u64 = 4;
pub const SERVER_BIDI_STREAM_ID: u64 = 1;

#[derive(Debug)]
pub enum ServerCommand {
    SendServerInitiated(Vec<u8>),
    Close,
}

#[derive(Debug, Clone)]
pub enum ServerEvent {
    Connected,
    Echoed(Vec<u8>),
    ServerInitiatedSent(Vec<u8>),
    Closed,
}

#[derive(Debug, Clone)]
enum WriteTag {
    Echo(Vec<u8>),
    ServerInitiated(Vec<u8>),
}

#[derive(Debug)]
struct PendingWrite {
    stream_id: u64,
    payload: Vec<u8>,
    offset: usize,
    fin: bool,
    tag: WriteTag,
}

pub struct SpikeEchoServer {
    scratch: Vec<u8>,
    stream_buffers: HashMap<u64, Vec<u8>>,
    pending_writes: VecDeque<PendingWrite>,
    command_rx: mpsc::Receiver<ServerCommand>,
    event_tx: mpsc::Sender<ServerEvent>,
    close_requested: bool,
}

impl SpikeEchoServer {
    #[must_use]
    pub fn new(
        event_tx: mpsc::Sender<ServerEvent>,
        command_rx: mpsc::Receiver<ServerCommand>,
    ) -> Self {
        Self {
            scratch: vec![0; 64 * 1024],
            stream_buffers: HashMap::new(),
            pending_writes: VecDeque::new(),
            command_rx,
            event_tx,
            close_requested: false,
        }
    }

    fn emit(&self, event: ServerEvent) {
        let _ = self.event_tx.try_send(event);
    }
}

impl ApplicationOverQuic for SpikeEchoServer {
    fn on_conn_established(
        &mut self,
        _qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.emit(ServerEvent::Connected);
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
            cmd = self.command_rx.recv() => {
                if let Some(command) = cmd {
                    match command {
                        ServerCommand::SendServerInitiated(payload) => {
                            self.pending_writes.push_back(PendingWrite {
                                stream_id: SERVER_BIDI_STREAM_ID,
                                payload: payload.clone(),
                                offset: 0,
                                fin: true,
                                tag: WriteTag::ServerInitiated(payload),
                            });
                        }
                        ServerCommand::Close => {
                            self.close_requested = true;
                        }
                    }
                } else {
                    self.close_requested = true;
                }
            }
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
                                self.pending_writes.push_back(PendingWrite {
                                    stream_id,
                                    payload: payload.clone(),
                                    offset: 0,
                                    fin: true,
                                    tag: WriteTag::Echo(payload),
                                });
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

                    match write.tag {
                        WriteTag::Echo(payload) => self.emit(ServerEvent::Echoed(payload)),
                        WriteTag::ServerInitiated(payload) => {
                            self.emit(ServerEvent::ServerInitiatedSent(payload));
                        }
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
        self.emit(ServerEvent::Closed);
    }
}
