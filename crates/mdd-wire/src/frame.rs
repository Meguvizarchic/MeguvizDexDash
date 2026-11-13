//! `mdd-wire/1` framing: a fixed 32-byte little-endian header and a body.
//!
//! | offset | type    | field                                   |
//! | ------ | ------- | --------------------------------------- |
//! | 0      | byte[4] | magic `MDDW`                            |
//! | 4 / 6  | u16/u16 | major / minor                           |
//! | 8 / 10 | u16/u16 | frame kind / flags                      |
//! | 12     | u32     | header_bytes, 32 in v1                  |
//! | 16     | u64     | stream_id                               |
//! | 24     | u64     | body_bytes                              |
//!
//! The body length is checked against the negotiated maximum *before* a single
//! body byte is read or allocated, a header cut short is not the same thing as a
//! clean end of input, and a body cut short is never returned as a frame.
use crate::channel::ChannelKind;
use crate::error::{WireError, WireErrorKind, WireResult, malformed};
use serde_json::{Value, json};
use std::io::{Read, Write};

pub const MAGIC: [u8; 4] = *b"MDDW";
pub const MAJOR: u16 = 1;
pub const MINOR: u16 = 0;
pub const HEADER_BYTES: usize = 32;
/// Flag bits that a v1 reader must understand. v1 defines none, so any of them
/// being set is a protocol failure; the high byte is optional and ignored.
pub const REQUIRED_FLAGS_MASK: u16 = 0x00ff;
/// Smallest frame size two peers may agree on.
pub const MIN_FRAME_BYTES: u64 = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum FrameKind {
    Hello = 1,
    Request = 2,
    Schema = 3,
    Batch = 4,
    Progress = 5,
    End = 6,
    Error = 7,
    Cancel = 8,
    Credit = 9,
}

impl FrameKind {
    pub fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::Hello,
            2 => Self::Request,
            3 => Self::Schema,
            4 => Self::Batch,
            5 => Self::Progress,
            6 => Self::End,
            7 => Self::Error,
            8 => Self::Cancel,
            9 => Self::Credit,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::Request => "request",
            Self::Schema => "schema",
            Self::Batch => "batch",
            Self::Progress => "progress",
            Self::End => "end",
            Self::Error => "error",
            Self::Cancel => "cancel",
            Self::Credit => "credit",
        }
    }

    /// A frame after which its stream carries nothing more.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::End | Self::Error | Self::Cancel)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub minor: u16,
    pub kind: FrameKind,
    pub flags: u16,
    pub stream_id: u64,
    pub body_bytes: u64,
}

impl Header {
    pub fn new(kind: FrameKind, stream_id: u64, body_bytes: u64) -> Self {
        Self {
            minor: MINOR,
            kind,
            flags: 0,
            stream_id,
            body_bytes,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&MAJOR.to_le_bytes());
        out[6..8].copy_from_slice(&self.minor.to_le_bytes());
        out[8..10].copy_from_slice(&(self.kind as u16).to_le_bytes());
        out[10..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..16].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        out[16..24].copy_from_slice(&self.stream_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.body_bytes.to_le_bytes());
        out
    }

    /// Validate a header against the largest body the connection allows.
    pub fn decode(bytes: &[u8; HEADER_BYTES], max_body_bytes: u64) -> WireResult<Self> {
        if bytes[0..4] != MAGIC {
            return Err(WireError::new(
                WireErrorKind::BadMagic,
                "frame does not start with MDDW",
            ));
        }
        let u16_at = |at: usize| u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let major = u16_at(4);
        if major != MAJOR {
            return Err(WireError::new(
                WireErrorKind::UnsupportedVersion,
                format!("major version {major} is not {MAJOR}"),
            ));
        }
        let header_bytes = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if header_bytes as usize != HEADER_BYTES {
            return Err(WireError::new(
                WireErrorKind::BadHeaderLength,
                format!("header_bytes {header_bytes} is not {HEADER_BYTES}"),
            ));
        }
        let kind_value = u16_at(8);
        let kind = FrameKind::from_u16(kind_value).ok_or_else(|| {
            WireError::new(
                WireErrorKind::UnknownFrameKind,
                format!("frame kind {kind_value} is not defined"),
            )
        })?;
        let flags = u16_at(10);
        if flags & REQUIRED_FLAGS_MASK != 0 {
            return Err(WireError::new(
                WireErrorKind::UnknownRequiredFlag,
                format!(
                    "required flag bits {:#06x} are not defined",
                    flags & REQUIRED_FLAGS_MASK
                ),
            ));
        }
        let mut stream = [0u8; 8];
        stream.copy_from_slice(&bytes[16..24]);
        // Connection frames (Hello) live on stream 0, every stream frame on a
        // non-zero id.
        if (kind == FrameKind::Hello) != (u64::from_le_bytes(stream) == 0) {
            return Err(WireError::new(
                WireErrorKind::BadStreamId,
                format!(
                    "a {} frame cannot be on stream {}",
                    kind.name(),
                    u64::from_le_bytes(stream)
                ),
            ));
        }
        let mut body = [0u8; 8];
        body.copy_from_slice(&bytes[24..32]);
        let body_bytes = u64::from_le_bytes(body);
        if body_bytes > max_body_bytes {
            return Err(WireError::new(
                WireErrorKind::FrameTooLarge,
                format!("body of {body_bytes} bytes exceeds the {max_body_bytes} byte limit"),
            ));
        }
        Ok(Self {
            minor: u16_at(6),
            kind,
            flags,
            stream_id: u64::from_le_bytes(stream),
            body_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub header: Header,
    pub body: Vec<u8>,
}

impl Frame {
    pub fn json(&self) -> WireResult<Value> {
        serde_json::from_slice(&self.body)
            .map_err(|error| malformed(format!("body is not JSON: {error}")))
    }
}

pub struct FrameReader<R> {
    source: R,
}

impl<R: Read> FrameReader<R> {
    pub fn new(source: R) -> Self {
        Self { source }
    }

    pub fn into_inner(self) -> R {
        self.source
    }

    /// Read one frame. `Ok(None)` is a clean end of input *between* frames only;
    /// the caller still decides whether the stream it was reading had finished.
    pub fn read_frame(&mut self, max_body_bytes: u64) -> WireResult<Option<Frame>> {
        let mut header = [0u8; HEADER_BYTES];
        let mut filled = 0;
        while filled < HEADER_BYTES {
            match self.source.read(&mut header[filled..]) {
                Ok(0) if filled == 0 => return Ok(None),
                Ok(0) => {
                    return Err(WireError::new(
                        WireErrorKind::TruncatedHeader,
                        format!("input ended after {filled} of {HEADER_BYTES} header bytes"),
                    ));
                }
                Ok(count) => filled += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(WireError::new(WireErrorKind::Io, error.to_string())),
            }
        }
        let header = Header::decode(&header, max_body_bytes)?;
        let mut body = Vec::new();
        let wanted = header.body_bytes;
        // The length is already bounded; reading through `take` still never
        // allocates the declared size up front.
        let got = (&mut self.source)
            .take(wanted)
            .read_to_end(&mut body)
            .map_err(|error| WireError::new(WireErrorKind::Io, error.to_string()))?;
        if got as u64 != wanted {
            return Err(WireError::new(
                WireErrorKind::TruncatedBody,
                format!("input ended after {got} of {wanted} body bytes"),
            ));
        }
        Ok(Some(Frame { header, body }))
    }
}

pub struct FrameWriter<W> {
    sink: W,
    max_body_bytes: u64,
    /// Set by the first I/O failure: a frame may be half written, so nothing
    /// more may follow it on this sink.
    failed: bool,
}

impl<W: Write> FrameWriter<W> {
    /// Frames only go to a dedicated worker channel, never to MCP stdout or stderr.
    pub fn new(sink: W, channel: ChannelKind, max_body_bytes: u64) -> WireResult<Self> {
        if channel != ChannelKind::Dedicated {
            return Err(WireError::new(
                WireErrorKind::ChannelNotDedicated,
                format!("binary frames are not allowed on {}", channel.name()),
            ));
        }
        Ok(Self {
            sink,
            max_body_bytes,
            failed: false,
        })
    }

    pub fn write_frame(&mut self, kind: FrameKind, stream_id: u64, body: &[u8]) -> WireResult<()> {
        if self.failed {
            return Err(WireError::new(
                WireErrorKind::Io,
                "an earlier write failed and may have left a partial frame",
            ));
        }
        if body.len() as u64 > self.max_body_bytes {
            return Err(WireError::new(
                WireErrorKind::FrameTooLarge,
                format!(
                    "body of {} bytes exceeds the {} byte limit",
                    body.len(),
                    self.max_body_bytes
                ),
            ));
        }
        let header = Header::new(kind, stream_id, body.len() as u64).encode();
        let result = self
            .sink
            .write_all(&header)
            .and_then(|()| self.sink.write_all(body))
            .and_then(|()| self.sink.flush());
        result.map_err(|error| {
            self.failed = true;
            WireError::new(WireErrorKind::Io, error.to_string())
        })
    }

    pub fn into_inner(self) -> W {
        self.sink
    }
}

/// What one side offers in its Hello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hello {
    /// Supported `(major, highest minor)` pairs.
    pub versions: Vec<(u16, u16)>,
    pub max_frame_bytes: u64,
    /// Batch encodings in preference order. `json` is the verifiable baseline.
    pub encodings: Vec<String>,
}

impl Hello {
    pub fn v1(max_frame_bytes: u64) -> Self {
        Self {
            versions: vec![(MAJOR, MINOR)],
            max_frame_bytes,
            encodings: vec!["json".to_owned()],
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "protocol": "mdd-wire",
            "versions": self.versions.iter().map(|(major, minor)| json!({"major": major, "minor": minor})).collect::<Vec<_>>(),
            "max_frame_bytes": self.max_frame_bytes.to_string(),
            "encodings": self.encodings,
        })
    }

    pub fn from_json(value: &Value) -> WireResult<Self> {
        let object = value
            .as_object()
            .ok_or_else(|| malformed("hello must be a JSON object"))?;
        if let Some(extra) = object.keys().find(|key| {
            !["protocol", "versions", "max_frame_bytes", "encodings"].contains(&key.as_str())
        }) {
            return Err(malformed(format!("hello has an unknown field `{extra}`")));
        }
        if object.get("protocol").and_then(Value::as_str) != Some("mdd-wire") {
            return Err(malformed("hello protocol is not mdd-wire"));
        }
        let versions = object
            .get("versions")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("hello lacks versions"))?
            .iter()
            .map(|entry| {
                let major = entry
                    .get("major")
                    .and_then(Value::as_u64)
                    .and_then(|v| u16::try_from(v).ok());
                let minor = entry
                    .get("minor")
                    .and_then(Value::as_u64)
                    .and_then(|v| u16::try_from(v).ok());
                major
                    .zip(minor)
                    .ok_or_else(|| malformed("hello version entry is malformed"))
            })
            .collect::<WireResult<Vec<_>>>()?;
        let max_frame_bytes = object
            .get("max_frame_bytes")
            .and_then(Value::as_str)
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| malformed("hello max_frame_bytes must be a decimal string"))?;
        let encodings = object
            .get("encodings")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("hello lacks encodings"))?
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| malformed("encoding must be a string"))
            })
            .collect::<WireResult<Vec<_>>>()?;
        Ok(Self {
            versions,
            max_frame_bytes,
            encodings,
        })
    }
}

/// The connection parameters both sides agreed on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Agreed {
    pub major: u16,
    pub minor: u16,
    pub max_frame_bytes: u64,
    pub encoding: String,
}

/// Agree on version, frame size and encoding. The largest frame is the smaller of
/// the two offers and must not be below [`MIN_FRAME_BYTES`]; the encoding is the
/// first one of `local`'s preference that `peer` also lists and that this
/// implementation can read (`json` only).
pub fn negotiate(local: &Hello, peer: &Hello) -> WireResult<Agreed> {
    // Only a major this implementation speaks can be agreed. A higher major both
    // sides happen to list is not a reason to fail while major 1 is common too.
    let minor = [&local.versions, &peer.versions]
        .map(|versions| {
            versions
                .iter()
                .filter(|(major, _)| *major == MAJOR)
                .map(|(_, minor)| *minor)
                .max()
        })
        .into_iter()
        .collect::<Option<Vec<u16>>>()
        .and_then(|minors| minors.into_iter().min());
    let Some(minor) = minor else {
        return Err(WireError::new(
            WireErrorKind::NegotiationFailed,
            format!(
                "no common implemented major version (this implementation speaks major {MAJOR})"
            ),
        ));
    };
    let major = MAJOR;
    let max_frame_bytes = local.max_frame_bytes.min(peer.max_frame_bytes);
    if max_frame_bytes < MIN_FRAME_BYTES {
        return Err(WireError::new(
            WireErrorKind::NegotiationFailed,
            format!("agreed frame size {max_frame_bytes} is below {MIN_FRAME_BYTES}"),
        ));
    }
    let encoding = local
        .encodings
        .iter()
        .find(|encoding| encoding.as_str() == "json" && peer.encodings.contains(encoding))
        .cloned()
        .ok_or_else(|| {
            WireError::new(WireErrorKind::NegotiationFailed, "no common batch encoding")
        })?;
    Ok(Agreed {
        major,
        minor,
        max_frame_bytes,
        encoding,
    })
}
