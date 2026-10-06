//! Native-messaging framing (02 section 3.3): a 4-byte length prefix in **native byte order**, then
//! that many bytes of UTF-8 JSON (an object).
//!
//! ```text
//! +----------------------+---------------------------------+
//! | length: uint32       | payload: UTF-8 JSON object      |
//! | native byte order    | exactly `length` bytes          |
//! +----------------------+---------------------------------+
//! ```
//!
//! `length` counts payload bytes only. Limits per direction (browser limit "1 MB" daemon to extension,
//! Zeus uses 4 MiB extension to daemon) are checked on the **prefix**, before any payload is allocated.
//! A zero length or an oversize prefix cannot be skipped safely (the stream would desynchronise), so
//! the reader reports an error and the caller closes the connection; invalid JSON inside a well-framed
//! payload is recoverable ([`FrameError::is_recoverable`]).
//!
//! Everything here is protocol logic over bytes; it does no logging of payloads (00 section 8).

use std::io::{self, Read, Write};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeus_types::limits::{MAX_FRAME_TO_DAEMON_BYTES, MAX_FRAME_TO_EXTENSION_BYTES};

use crate::error::FrameError;
use crate::protocol::Limits;

/// Which way a frame travels; the limit differs per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Daemon (through the host) to the extension: at most 1,000,000 bytes.
    ToExtension,
    /// Extension to the daemon: at most 4 MiB.
    ToDaemon,
}

/// Maximum payload sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    /// Daemon to extension.
    pub to_extension: usize,
    /// Extension to daemon.
    pub to_daemon: usize,
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            to_extension: MAX_FRAME_TO_EXTENSION_BYTES,
            to_daemon: MAX_FRAME_TO_DAEMON_BYTES,
        }
    }
}

impl FrameLimits {
    /// The limits a connection announced in `hello.ack`, never above the normative maxima.
    #[must_use]
    pub fn from_negotiated(limits: &Limits) -> Self {
        let clamp =
            |announced: u64, max: usize| usize::try_from(announced).map_or(max, |n| n.min(max));
        Self {
            to_extension: clamp(
                limits.max_frame_to_extension_bytes,
                MAX_FRAME_TO_EXTENSION_BYTES,
            ),
            to_daemon: clamp(limits.max_frame_to_daemon_bytes, MAX_FRAME_TO_DAEMON_BYTES),
        }
    }

    /// The limit for `direction`.
    #[must_use]
    pub const fn for_direction(&self, direction: Direction) -> usize {
        match direction {
            Direction::ToExtension => self.to_extension,
            Direction::ToDaemon => self.to_daemon,
        }
    }
}

/// Validates a length prefix (already converted from native byte order) and returns the payload length.
pub fn check_length(
    length: u32,
    direction: Direction,
    limits: &FrameLimits,
) -> Result<usize, FrameError> {
    if length == 0 {
        return Err(FrameError::ZeroLength);
    }
    let limit = limits.for_direction(direction);
    let length = length as usize;
    if length > limit {
        return Err(FrameError::TooLarge {
            announced: length as u64,
            limit,
        });
    }
    Ok(length)
}

/// Prefix plus payload for one frame. Fails when the payload is empty or above the limit.
pub fn encode_frame(
    payload: &[u8],
    direction: Direction,
    limits: &FrameLimits,
) -> Result<Vec<u8>, FrameError> {
    let limit = limits.for_direction(direction);
    if payload.is_empty() {
        return Err(FrameError::ZeroLength);
    }
    if payload.len() > limit {
        return Err(FrameError::TooLarge {
            announced: payload.len() as u64,
            limit,
        });
    }
    // `payload.len() <= limit <= 4 MiB`, so the cast cannot truncate.
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Checks that a payload is UTF-8 JSON that is an object (02 section 3.3 rule 4) nesting at most 32
/// levels deep (00 section 10), without keeping the parsed value.
pub fn check_payload(payload: &[u8]) -> Result<(), FrameError> {
    match serde_json::from_slice::<serde_json::Value>(payload) {
        Ok(value @ serde_json::Value::Object(_)) => {
            if json_depth(&value) > zeus_types::limits::MAX_JSON_DEPTH {
                Err(FrameError::TooDeep)
            } else {
                Ok(())
            }
        }
        _ => Err(FrameError::InvalidJson),
    }
}

/// Nesting depth of a JSON value: a scalar is 0, an object or array is 1 plus its deepest child.
#[must_use]
pub fn json_depth(value: &serde_json::Value) -> usize {
    let mut deepest = 0;
    let mut stack = vec![(value, 0usize)];
    while let Some((v, depth)) = stack.pop() {
        match v {
            serde_json::Value::Array(items) => {
                deepest = deepest.max(depth + 1);
                stack.extend(items.iter().map(|i| (i, depth + 1)));
            }
            serde_json::Value::Object(map) => {
                deepest = deepest.max(depth + 1);
                stack.extend(map.values().map(|i| (i, depth + 1)));
            }
            _ => {}
        }
    }
    deepest
}

/// Reads one frame from a blocking stream. `Ok(None)` is a clean end of stream at a frame boundary
/// (the peer closed the port); an end inside a frame is [`FrameError::Truncated`].
pub fn read_frame<R: Read>(
    reader: &mut R,
    direction: Direction,
    limits: &FrameLimits,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut prefix = [0u8; 4];
    match read_exact_or_eof(reader, &mut prefix)? {
        ReadOutcome::Eof => return Ok(None),
        ReadOutcome::Partial => return Err(FrameError::Truncated),
        ReadOutcome::Full => {}
    }
    let length = check_length(u32::from_ne_bytes(prefix), direction, limits)?;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            e.into()
        }
    })?;
    Ok(Some(payload))
}

/// Writes one frame to a blocking stream and flushes it (the host writes to stdout, which must carry
/// frames only).
pub fn write_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    direction: Direction,
    limits: &FrameLimits,
) -> Result<(), FrameError> {
    let frame = encode_frame(payload, direction, limits)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

/// Asynchronous [`read_frame`] over a tokio stream.
pub async fn read_frame_async<R: AsyncRead + Unpin>(
    reader: &mut R,
    direction: Direction,
    limits: &FrameLimits,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut prefix = [0u8; 4];
    let mut filled = 0;
    while filled < prefix.len() {
        let n = reader.read(&mut prefix[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated)
            };
        }
        filled += n;
    }
    let length = check_length(u32::from_ne_bytes(prefix), direction, limits)?;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            e.into()
        }
    })?;
    Ok(Some(payload))
}

/// Asynchronous [`write_frame`] over a tokio stream.
pub async fn write_frame_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
    direction: Direction,
    limits: &FrameLimits,
) -> Result<(), FrameError> {
    let frame = encode_frame(payload, direction, limits)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

enum ReadOutcome {
    Full,
    Partial,
    Eof,
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<ReadOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Ok(if filled == 0 {
                    ReadOutcome::Eof
                } else {
                    ReadOutcome::Partial
                });
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ReadOutcome::Full)
}

/// An incremental decoder for callers that receive bytes in arbitrary pieces (a pipe read, a fuzzer).
///
/// Push bytes with [`FrameDecoder::push`] and pull complete payloads with [`FrameDecoder::next_frame`].
/// After an error that is not recoverable the decoder refuses further input.
#[derive(Debug)]
pub struct FrameDecoder {
    direction: Direction,
    limits: FrameLimits,
    buffer: Vec<u8>,
    poisoned: bool,
}

impl FrameDecoder {
    /// A decoder for frames travelling in `direction`.
    #[must_use]
    pub fn new(direction: Direction, limits: FrameLimits) -> Self {
        Self {
            direction,
            limits,
            buffer: Vec::new(),
            poisoned: false,
        }
    }

    /// Appends received bytes. The buffer never grows beyond one frame plus the bytes of the next
    /// prefix, because [`FrameDecoder::next_frame`] checks the prefix as soon as it is complete.
    pub fn push(&mut self, bytes: &[u8]) {
        if !self.poisoned {
            self.buffer.extend_from_slice(bytes);
        }
    }

    /// Bytes buffered and not yet returned.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// The next complete payload, or `None` when more bytes are needed. A bad prefix is an error and
    /// poisons the decoder: the stream is desynchronised and the connection must close.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.poisoned {
            return Err(FrameError::Truncated);
        }
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let prefix: [u8; 4] = [
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ];
        let length = match check_length(u32::from_ne_bytes(prefix), self.direction, &self.limits) {
            Ok(n) => n,
            Err(e) => {
                self.poisoned = true;
                self.buffer.clear();
                return Err(e);
            }
        };
        if self.buffer.len() < 4 + length {
            return Ok(None);
        }
        let payload = self.buffer[4..4 + length].to_vec();
        self.buffer.drain(..4 + length);
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const PING: &[u8] = br#"{"v":1,"id":"e1","type":"ping","body":{}}"#;

    #[test]
    fn the_specification_example_prefix() {
        // 02 section 3.3: the 41-byte message is preceded by 29 00 00 00 (little-endian hosts).
        assert_eq!(PING.len(), 41);
        let frame = encode_frame(PING, Direction::ToDaemon, &FrameLimits::default()).unwrap();
        assert_eq!(&frame[..4], &41u32.to_ne_bytes());
        #[cfg(target_endian = "little")]
        assert_eq!(&frame[..4], &[0x29, 0, 0, 0]);
        assert_eq!(&frame[4..], PING);
    }

    #[test]
    fn limits_apply_per_direction_and_to_the_prefix() {
        let limits = FrameLimits::default();
        assert_eq!(
            check_length(1_000_000, Direction::ToExtension, &limits).unwrap(),
            1_000_000
        );
        assert!(matches!(
            check_length(1_000_001, Direction::ToExtension, &limits),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(check_length(1_000_001, Direction::ToDaemon, &limits).is_ok());
        assert!(matches!(
            check_length(4_194_305, Direction::ToDaemon, &limits),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(matches!(
            check_length(0, Direction::ToDaemon, &limits),
            Err(FrameError::ZeroLength)
        ));
        assert!(matches!(
            encode_frame(b"", Direction::ToDaemon, &limits),
            Err(FrameError::ZeroLength)
        ));
        assert!(matches!(
            encode_frame(&vec![b'x'; 1_000_001], Direction::ToExtension, &limits),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn negotiated_limits_never_exceed_the_maxima() {
        let mut l = Limits {
            max_frame_to_extension_bytes: 5_000_000,
            max_frame_to_daemon_bytes: 1 << 40,
            ..Limits::default()
        };
        let f = FrameLimits::from_negotiated(&l);
        assert_eq!((f.to_extension, f.to_daemon), (1_000_000, 4_194_304));
        l.max_frame_to_extension_bytes = 4096;
        assert_eq!(FrameLimits::from_negotiated(&l).to_extension, 4096);
    }

    #[test]
    fn sync_round_trip_clean_eof_and_truncation() {
        let limits = FrameLimits::default();
        let mut wire = Vec::new();
        write_frame(&mut wire, PING, Direction::ToDaemon, &limits).unwrap();
        write_frame(&mut wire, b"{}", Direction::ToDaemon, &limits).unwrap();
        let mut r = io::Cursor::new(wire.clone());
        assert_eq!(
            read_frame(&mut r, Direction::ToDaemon, &limits)
                .unwrap()
                .unwrap(),
            PING
        );
        assert_eq!(
            read_frame(&mut r, Direction::ToDaemon, &limits)
                .unwrap()
                .unwrap(),
            b"{}"
        );
        assert!(
            read_frame(&mut r, Direction::ToDaemon, &limits)
                .unwrap()
                .is_none(),
            "clean end at a frame boundary"
        );
        for cut in [2, 4, 10, wire.len() - 3] {
            let mut r = io::Cursor::new(wire[..cut].to_vec());
            let first = read_frame(&mut r, Direction::ToDaemon, &limits);
            let second = first
                .as_ref()
                .ok()
                .and_then(|_| read_frame(&mut r, Direction::ToDaemon, &limits).err());
            assert!(
                matches!(first, Err(FrameError::Truncated))
                    || matches!(second, Some(FrameError::Truncated)),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn an_oversize_prefix_is_rejected_before_any_payload_is_read() {
        let limits = FrameLimits::default();
        let mut wire = 2_000_000u32.to_ne_bytes().to_vec();
        wire.extend_from_slice(b"{}"); // far fewer bytes than announced: must fail on the prefix, not wait for them
        let err =
            read_frame(&mut io::Cursor::new(wire), Direction::ToExtension, &limits).unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge {
                announced: 2_000_000,
                limit: 1_000_000
            }
        ));
    }

    #[test]
    fn nesting_deeper_than_32_is_a_schema_violation_not_a_crash() {
        let nested = |levels: usize| format!("{}1{}", "{\"a\":".repeat(levels), "}".repeat(levels));
        assert!(check_payload(nested(32).as_bytes()).is_ok());
        let err = check_payload(nested(33).as_bytes()).unwrap_err();
        assert!(matches!(err, FrameError::TooDeep) && err.is_recoverable());
        assert_eq!(err.code(), "nm.schema_violation");
        assert_eq!(json_depth(&serde_json::json!({"a": [1, {"b": []}]})), 4);
        assert_eq!(json_depth(&serde_json::json!(5)), 0);
    }

    #[test]
    fn payload_must_be_a_json_object() {
        assert!(check_payload(PING).is_ok());
        for bad in [
            &b"[1]"[..],
            b"\"s\"",
            b"123",
            b"not json",
            b"\xff\xfe",
            b"{\"a\":",
        ] {
            assert!(
                matches!(check_payload(bad), Err(FrameError::InvalidJson)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn decoder_handles_arbitrary_splits() {
        let limits = FrameLimits::default();
        let mut wire = Vec::new();
        for p in [PING, &b"{}"[..], &b"{\"a\":[1,2,3]}"[..]] {
            wire.extend(encode_frame(p, Direction::ToDaemon, &limits).unwrap());
        }
        for chunk in [1usize, 2, 3, 5, 7, 64] {
            let mut d = FrameDecoder::new(Direction::ToDaemon, limits);
            let mut got = Vec::new();
            for piece in wire.chunks(chunk) {
                d.push(piece);
                while let Some(f) = d.next_frame().unwrap() {
                    got.push(f);
                }
            }
            assert_eq!(got.len(), 3, "chunk size {chunk}");
            assert_eq!(got[0], PING);
            assert_eq!(d.buffered(), 0);
        }
    }

    #[test]
    fn decoder_poisons_on_a_bad_prefix() {
        let mut d = FrameDecoder::new(Direction::ToExtension, FrameLimits::default());
        d.push(&u32::MAX.to_ne_bytes());
        assert!(matches!(d.next_frame(), Err(FrameError::TooLarge { .. })));
        d.push(b"{}");
        assert!(
            d.next_frame().is_err(),
            "a desynchronised stream is never trusted again"
        );
        let mut d = FrameDecoder::new(Direction::ToExtension, FrameLimits::default());
        d.push(&0u32.to_ne_bytes());
        assert!(matches!(d.next_frame(), Err(FrameError::ZeroLength)));
    }

    #[tokio::test]
    async fn async_round_trip_over_a_duplex_pipe() {
        let limits = FrameLimits::default();
        let (mut a, mut b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            for _ in 0..3 {
                write_frame_async(&mut a, PING, Direction::ToDaemon, &limits)
                    .await
                    .unwrap();
            }
        });
        for _ in 0..3 {
            assert_eq!(
                read_frame_async(&mut b, Direction::ToDaemon, &limits)
                    .await
                    .unwrap()
                    .unwrap(),
                PING
            );
        }
        writer.await.unwrap();
        assert!(
            read_frame_async(&mut b, Direction::ToDaemon, &limits)
                .await
                .unwrap()
                .is_none()
        );
    }

    proptest! {
        /// Whatever bytes arrive, the decoder never panics, never allocates beyond one frame, and every
        /// frame it yields equals what was encoded.
        #[test]
        fn decoder_never_panics_and_round_trips(
            payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..200), 0..8),
            noise in proptest::collection::vec(any::<u8>(), 0..64),
            split in 1usize..32,
        ) {
            let limits = FrameLimits { to_extension: 1_000_000, to_daemon: 4096 };
            let mut wire = Vec::new();
            for p in &payloads {
                wire.extend(encode_frame(p, Direction::ToDaemon, &limits).unwrap());
            }
            let mut d = FrameDecoder::new(Direction::ToDaemon, limits);
            let mut got = Vec::new();
            for piece in wire.chunks(split) {
                d.push(piece);
                while let Some(f) = d.next_frame().unwrap() { got.push(f); }
            }
            prop_assert_eq!(&got, &payloads);
            // Garbage afterwards must not panic (it may produce an error or frames).
            d.push(&noise);
            let _ = d.next_frame();
            prop_assert!(d.buffered() <= noise.len() + 4 + 4096);
        }
    }
}
