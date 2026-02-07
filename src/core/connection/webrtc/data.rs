//! Data channel: binary frame encoding/decoding.
//!
//! All messages on the data channel use this compact binary envelope:
//!
//! ```text
//! [1 byte: frame_type] [N bytes: payload]
//! ```
//!
//! ## Frame Types
//!
//! | Type | Value | Description |
//! |------|-------|-------------|
//! | `FRAME_CONTROL` | 0x01 | JSON-encoded ControlMessage |
//! | `FRAME_CHUNK` | 0x02 | Binary: 16 bytes file_id + 4 bytes seq + raw data |
//!
//! ## Efficiency
//!
//! This eliminates JSON+base64 overhead for bulk data transfer.
//! A 256 KB chunk costs 256 KB + 21 bytes framing + 29 bytes AES-GCM envelope
//! instead of ~700 KB with JSON+base64.
//!
//! Reliable delivery is guaranteed by WebRTC's SCTP layer (no application-level ACKs).

use anyhow::{anyhow, Result};
use bytes::BufMut;
use uuid::Uuid;

use super::{ControlMessage, FRAME_CHUNK, FRAME_CONTROL};

// ── Frame Header Sizes ───────────────────────────────────────────────────────

/// Size of the frame type byte.
const FRAME_TYPE_SIZE: usize = 1;

/// Size of a UUID in bytes.
const UUID_SIZE: usize = 16;

/// Size of the chunk sequence number (u32 BE).
const SEQ_SIZE: usize = 4;

/// Minimum size of a valid chunk frame (frame_type + uuid + seq).
pub const CHUNK_FRAME_MIN_SIZE: usize = FRAME_TYPE_SIZE + UUID_SIZE + SEQ_SIZE;

// ── Encoding Functions ────────────────────────────────────────────────────────

/// Encode a binary chunk frame into a reusable buffer, clearing it first.
///
/// Frame format: `[0x02][16 bytes uuid][4 bytes seq BE][payload]`
///
/// # Arguments
///
/// * `buf` - Reusable buffer to write into (cleared first)
/// * `file_id` - UUID of the file being transferred
/// * `seq` - Zero-indexed chunk sequence number
/// * `payload` - Raw chunk data
#[inline]
pub fn encode_chunk_frame_into(buf: &mut Vec<u8>, file_id: Uuid, seq: u32, payload: &[u8]) {
    buf.clear();
    buf.reserve(FRAME_TYPE_SIZE + UUID_SIZE + SEQ_SIZE + payload.len());
    buf.put_u8(FRAME_CHUNK);
    buf.extend_from_slice(file_id.as_bytes());
    buf.put_u32(seq);
    buf.extend_from_slice(payload);
}

/// Encode a control frame.
///
/// Frame format: `[0x01][json bytes]`
///
/// # Arguments
///
/// * `msg` - Control message to encode
///
/// # Returns
///
/// JSON-encoded control frame ready for encryption.
pub fn encode_control_frame(msg: &ControlMessage) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let mut buf = Vec::with_capacity(FRAME_TYPE_SIZE + json.len());
    buf.put_u8(FRAME_CONTROL);
    buf.extend_from_slice(&json);
    Ok(buf)
}

// ── Decoding Functions ────────────────────────────────────────────────────────

/// Decoded frame type from the data channel.
#[derive(Debug, Clone)]
pub enum DecodedFrame<'a> {
    /// Control message (JSON-encoded).
    Control(&'a [u8]),
    /// Chunk frame with file_id, sequence number, and payload.
    Chunk {
        file_id: Uuid,
        seq: u32,
        payload: &'a [u8],
    },
}

/// Decode a frame from its decrypted payload.
///
/// # Arguments
///
/// * `data` - Decrypted frame data (after decryption, before decompression)
///
/// # Returns
///
/// - `Ok(DecodedFrame::Control(payload))` for control frames
/// - `Ok(DecodedFrame::Chunk { ... })` for chunk frames
/// - `Err` if the frame is malformed
///
/// # Errors
///
/// Returns an error if:
/// - The frame is empty
/// - A chunk frame is too short (< 21 bytes)
/// - The frame type is unknown
#[inline]
pub fn decode_frame(data: &[u8]) -> Result<DecodedFrame<'_>> {
    if data.is_empty() {
        return Err(anyhow!("Empty frame"));
    }

    let frame_type = data[0];
    let payload = &data[FRAME_TYPE_SIZE..];

    match frame_type {
        FRAME_CONTROL => Ok(DecodedFrame::Control(payload)),
        FRAME_CHUNK => decode_chunk_frame(payload),
        _ => Err(anyhow!("Unknown frame type: 0x{:02x}", frame_type)),
    }
}

/// Decode a chunk frame payload.
///
/// Expected format: `[16 bytes uuid][4 bytes seq BE][chunk data]`
#[inline]
fn decode_chunk_frame(payload: &[u8]) -> Result<DecodedFrame<'_>> {
    if payload.len() < UUID_SIZE + SEQ_SIZE {
        return Err(anyhow!(
            "Chunk frame too short: {} bytes (need at least {})",
            payload.len(),
            UUID_SIZE + SEQ_SIZE
        ));
    }

    let file_id = Uuid::from_bytes(payload[..UUID_SIZE].try_into().unwrap());
    let seq = u32::from_be_bytes(payload[UUID_SIZE..UUID_SIZE + SEQ_SIZE].try_into().unwrap());
    let chunk_data = &payload[UUID_SIZE + SEQ_SIZE..];

    Ok(DecodedFrame::Chunk {
        file_id,
        seq,
        payload: chunk_data,
    })
}

/// Parse a control message from its JSON payload.
///
/// # Arguments
///
/// * `payload` - JSON bytes from a control frame
///
/// # Returns
///
/// The parsed `ControlMessage`.
#[inline]
pub fn parse_control_message(payload: &[u8]) -> Result<ControlMessage> {
    serde_json::from_slice(payload).map_err(|e| anyhow!("Failed to parse control message: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_chunk_frame() {
        let file_id = Uuid::new_v4();
        let seq = 42u32;
        let payload = b"test chunk data";

        let mut buf = Vec::new();
        encode_chunk_frame_into(&mut buf, file_id, seq, payload);

        // Simulate decryption: skip the frame type byte
        let decrypted = &buf;
        let frame = decode_frame(decrypted).unwrap();

        match frame {
            DecodedFrame::Chunk {
                file_id: decoded_id,
                seq: decoded_seq,
                payload: decoded_payload,
            } => {
                assert_eq!(decoded_id, file_id);
                assert_eq!(decoded_seq, seq);
                assert_eq!(decoded_payload, payload);
            }
            _ => panic!("Expected chunk frame"),
        }
    }

    #[test]
    fn test_encode_decode_control_frame() {
        let msg = ControlMessage::Typing;
        let encoded = encode_control_frame(&msg).unwrap();

        let frame = decode_frame(&encoded).unwrap();
        match frame {
            DecodedFrame::Control(payload) => {
                let decoded = parse_control_message(payload).unwrap();
                matches!(decoded, ControlMessage::Typing);
            }
            _ => panic!("Expected control frame"),
        }
    }

    #[test]
    fn test_decode_empty_frame() {
        let result = decode_frame(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_unknown_frame_type() {
        let result = decode_frame(&[0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_short_chunk_frame() {
        // Frame type + insufficient data
        let data = [FRAME_CHUNK, 0, 1, 2, 3]; // Only 4 bytes after frame type
        let result = decode_frame(&data);
        assert!(result.is_err());
    }
}
