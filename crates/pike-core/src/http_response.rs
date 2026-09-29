//! Incremental HTTP/1 response framing shared by the CLI and public relay.
//! Keeps headers/trailers bounded and emits body chunks without retaining a body.
use anyhow::{anyhow, bail, Result};

pub const MAX_HEADERS: usize = 32 * 1024;
#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}
impl ResponseHead {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
    pub fn end_to_end_headers(&self) -> impl Iterator<Item = &(String, String)> {
        self.headers.iter().filter(|(name, _)| {
            !is_hop_by_hop(name)
                && !self.header("connection").is_some_and(|tokens| {
                    tokens
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case(name))
                })
        })
    }
}
#[derive(Debug)]
pub enum Event {
    Head(ResponseHead),
    Body(Vec<u8>),
    End,
}
#[derive(Debug, Clone, Copy)]
enum State {
    Headers,
    Fixed(u64),
    UntilEof,
    ChunkSize,
    Chunk(u64),
    ChunkEnd,
    Trailers,
    Done,
}
pub struct ResponseDecoder {
    buffer: Vec<u8>,
    state: State,
    no_body: bool,
    interim: usize,
    trailer_bytes: usize,
}
impl ResponseDecoder {
    pub fn new(no_body: bool) -> Self {
        Self {
            buffer: Vec::new(),
            state: State::Headers,
            no_body,
            interim: 0,
            trailer_bytes: 0,
        }
    }
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }
    fn read_head(&mut self, events: &mut Vec<Event>) -> Result<bool> {
        let Some(end) = self.buffer.windows(4).position(|part| part == b"\r\n\r\n") else {
            if self.buffer.len() > MAX_HEADERS {
                bail!("response headers too large");
            }
            return Ok(false);
        };
        if end + 4 > MAX_HEADERS {
            bail!("response headers too large");
        }
        let head = parse_head(&self.buffer[..end])?;
        self.buffer.drain(..end + 4);
        if (100..200).contains(&head.status) && head.status != 101 {
            self.interim += 1;
            if self.interim > 8 {
                bail!("too many interim responses");
            }
            return Ok(true);
        }
        let content_lengths: Vec<_> = head
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.parse::<u64>())
            .collect::<std::result::Result<_, _>>()?;
        if content_lengths.windows(2).any(|pair| pair[0] != pair[1]) {
            bail!("conflicting content lengths");
        }
        let transfer: Vec<_> = head
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
            .map(|(_, value)| value.to_lowercase())
            .collect();
        if !transfer.is_empty() && (!content_lengths.is_empty() || transfer != ["chunked"]) {
            bail!("ambiguous or unsupported transfer encoding");
        }
        self.state = if self.no_body || matches!(head.status, 101 | 204 | 304) {
            State::Done
        } else if !transfer.is_empty() {
            State::ChunkSize
        } else if let Some(length) = content_lengths.first() {
            State::Fixed(*length)
        } else {
            State::UntilEof
        };
        events.push(Event::Head(head));
        if self.is_done() {
            events.push(Event::End);
        }

        Ok(true)
    }
    pub fn feed(&mut self, bytes: &[u8], eof: bool) -> Result<Vec<Event>> {
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            match self.state {
                State::Headers => {
                    if !self.read_head(&mut events)? {
                        break;
                    }
                }
                State::Fixed(0) => {
                    self.state = State::Done;
                    events.push(Event::End);
                }
                State::Fixed(remaining) | State::Chunk(remaining) => {
                    if self.buffer.is_empty() {
                        break;
                    }
                    let take = remaining.min(self.buffer.len() as u64) as usize;
                    events.push(Event::Body(self.buffer.drain(..take).collect()));
                    self.state = if matches!(self.state, State::Fixed(_)) {
                        State::Fixed(remaining - take as u64)
                    } else if remaining == take as u64 {
                        State::ChunkEnd
                    } else {
                        State::Chunk(remaining - take as u64)
                    };
                }
                State::UntilEof => {
                    if !self.buffer.is_empty() {
                        events.push(Event::Body(std::mem::take(&mut self.buffer)));
                    }
                    if eof {
                        self.state = State::Done;
                        events.push(Event::End);
                    }
                    break;
                }
                State::ChunkSize | State::Trailers => {
                    let Some(end) = self.buffer.windows(2).position(|part| part == b"\r\n") else {
                        if self.buffer.len() + self.trailer_bytes > MAX_HEADERS {
                            bail!("chunk metadata too large");
                        }
                        break;
                    };
                    if end + self.trailer_bytes > MAX_HEADERS {
                        bail!("chunk metadata too large");
                    }
                    if matches!(self.state, State::Trailers) {
                        self.trailer_bytes += end + 2;
                        if end == 0 {
                            self.state = State::Done;
                            events.push(Event::End);
                        } else if !self.buffer[..end].contains(&b':') {
                            bail!("invalid trailer");
                        }
                    } else {
                        let line = std::str::from_utf8(&self.buffer[..end])?;
                        let size =
                            u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)?;
                        self.state = if size == 0 {
                            State::Trailers
                        } else {
                            State::Chunk(size)
                        };
                    }
                    self.buffer.drain(..end + 2);
                }
                State::ChunkEnd => {
                    if self.buffer.len() < 2 {
                        break;
                    }
                    if &self.buffer[..2] != b"\r\n" {
                        bail!("invalid chunk terminator");
                    }
                    self.buffer.drain(..2);
                    self.state = State::ChunkSize;
                }
                State::Done => {
                    self.buffer.clear();
                    break;
                }
            }
        }
        if eof && !self.is_done() {
            bail!("truncated upstream response");
        }
        Ok(events)
    }
}

pub fn parse_head(bytes: &[u8]) -> Result<ResponseHead> {
    if bytes.len() > MAX_HEADERS {
        bail!("response headers too large");
    }
    let text = std::str::from_utf8(bytes)?;
    let mut lines = text.split("\r\n");
    let mut status = lines
        .next()
        .ok_or_else(|| anyhow!("missing status"))?
        .split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        bail!("invalid response version");
    }
    let status: u16 = status
        .next()
        .ok_or_else(|| anyhow!("missing status code"))?
        .parse()?;
    if !(100..600).contains(&status) {
        bail!("invalid response status");
    }
    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed response header"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || value.bytes().any(|byte| byte < 32 && byte != b'\t')
        {
            bail!("invalid response header");
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    Ok(ResponseHead { status, headers })
}
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "expect"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_fragment_boundary_preserves_interim_chunked_and_repeated_headers() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n3\r\nabc\r\n2;ext=x\r\nde\r\n0\r\nX-Trailer: yes\r\n\r\n";
        for width in 1..raw.len() {
            let mut parser = ResponseDecoder::new(false);
            let mut body = vec![];
            let mut heads = 0;
            let mut ends = 0;
            for part in raw.chunks(width) {
                for event in parser.feed(part, false).unwrap() {
                    match event {
                        Event::Head(head) => {
                            heads += 1;
                            assert_eq!(head.headers.len(), 3);
                        }
                        Event::Body(bytes) => body.extend(bytes),
                        Event::End => ends += 1,
                    }
                }
            }
            parser.feed(&[], true).unwrap();
            assert_eq!(body, b"abcde");
            assert_eq!((heads, ends), (1, 1));
        }
    }
    #[test]
    fn sse_delivers_before_eof_and_large_chunk_does_not_accumulate() {
        let mut parser = ResponseDecoder::new(false);
        parser
            .feed(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2000000\r\n",
                false,
            )
            .unwrap();
        for _ in 0..512 {
            let events = parser.feed(&vec![b'x'; 65536], false).unwrap();
            assert!(matches!(&events[0],Event::Body(body) if body.len()==65536));
            assert!(parser.buffer.is_empty());
        }
        assert!(parser.feed(b"\r\n0\r\n\r\n", true).is_ok());
    }
    #[test]
    fn rejects_smuggling_truncation_and_unbounded_metadata() {
        for raw in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nx",
        ] {
            assert!(ResponseDecoder::new(false).feed(raw, true).is_err());
        }
        assert!(ResponseDecoder::new(false)
            .feed(&vec![b'x'; MAX_HEADERS + 1], false)
            .is_err());
        assert!(ResponseDecoder::new(true)
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n", true)
            .is_ok());
    }
}
