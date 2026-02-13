//! Data channel: binary frame encoding/decoding.
//!
//! All messages on the data channel use this compact binary envelope:
//!
//!   [1 byte: frame_type] [N bytes: payload]
//!
//! Frame types:
//!   0x01 = Control (JSON-encoded ControlMessage)
//!   0x02 = Chunk   (binary: 16 bytes file_id + 4 bytes seq + raw data)
//!
//! This eliminates JSON+base64 overhead for bulk data transfer.
//! A 256 KB chunk costs 256 KB + 21 bytes framing + 29 bytes AES-GCM envelope
//! instead of ~700 KB with JSON+base64.
//! Reliable delivery is guaranteed by WebRTC's SCTP layer (no application-level ACKs).

use anyhow::Result;
use bytes::BufMut;
use uuid::Uuid;

use super::{ControlMessage, FRAME_CHUNK, FRAME_CONTROL};

/// Encode a binary chunk frame into a reusable buffer, clearing it first.
/// [0x02][16 bytes uuid][4 bytes seq BE][payload]
pub fn encode_chunk_frame_into(buf: &mut Vec<u8>, file_id: Uuid, seq: u32, payload: &[u8]) {
    buf.clear();
    buf.reserve(1 + 16 + 4 + payload.len());
    buf.put_u8(FRAME_CHUNK);
    buf.extend_from_slice(file_id.as_bytes());
    buf.put_u32(seq);
    buf.extend_from_slice(payload);
}

/// Encode a control frame: [0x01][json bytes]
pub fn encode_control_frame(msg: &ControlMessage) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let mut buf = Vec::with_capacity(1 + json.len());
    buf.put_u8(FRAME_CONTROL);
    buf.extend_from_slice(&json);
    Ok(buf)
}
