//! Sender: TX operations — sending files, messages, control frames.

use aes_gcm::{aead::KeyInit, Aes256Gcm};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;

use crate::core::config::{CHUNK_SIZE, PIPELINE_SIZE};
use crate::core::connection::webrtc::data::{encode_chunk_frame_into, encode_control_frame};
use crate::core::security::message_auth::MessageAuthenticator;
use crate::core::transaction::TransactionManifest;

use super::{
    compress_data, encrypt, encrypt_with, ConnectionMessage, ControlMessage, WireStats,
    WebRTCConnection, CHAT_HMAC_CHANNEL, derive_chat_hmac_key,
};

impl WebRTCConnection {
    // ── Send helpers ─────────────────────────────────────────────────────

    /// Send an encrypted frame on the given data channel.
    ///
    /// Wire envelope: `encrypt( [1-byte compress flag] + [payload] )`
    ///
    /// When `compress` is **true** the payload is brotli-compressed before
    /// encryption (good for small JSON control messages).  When **false** the
    /// raw payload is sent as-is (avoids wasting CPU on already-compressed
    /// file data and prevents brotli from *expanding* incompressible content).
    pub(crate) async fn send_encrypted(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        plaintext: &[u8],
        compress: bool,
        wire_stats: &Arc<WireStats>,
    ) -> Result<usize> {
        if dc.ready_state() != RTCDataChannelState::Open {
            warn!(event = "send_channel_not_open", state = ?dc.ready_state(), "Attempted send on non-open data channel");
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }

        // Build envelope: [compress_flag] + [maybe_compressed_plaintext]
        let envelope = if compress {
            let compressed = compress_data(plaintext).map_err(|e| {
                error!(event = "compress_failure", bytes = plaintext.len(), error = %e, "Compression failed before send");
                e
            })?;
            let mut env = Vec::with_capacity(1 + compressed.len());
            env.push(0x01);
            env.extend_from_slice(&compressed);
            env
        } else {
            let mut env = Vec::with_capacity(1 + plaintext.len());
            env.push(0x00);
            env.extend_from_slice(plaintext);
            env
        };

        let encrypted = encrypt(key, &envelope).map_err(|e| {
            error!(event = "encrypt_failure", bytes = envelope.len(), error = %e, "Encryption failed before send");
            e
        })?;
        let wire_bytes = encrypted.len();
        dc.send(&Bytes::from(encrypted)).await?;
        // Track every byte leaving the wire
        wire_stats.add_tx(wire_bytes as u64);
        Ok(wire_bytes)
    }

    /// Send an encrypted frame using a pre-initialized cipher (avoids
    /// re-creating AES-256-GCM state per call — useful in hot loops).
    pub(crate) async fn send_encrypted_with_cipher(
        dc: &Arc<RTCDataChannel>,
        cipher: &Aes256Gcm,
        plaintext: &[u8],
        compress: bool,
        wire_stats: &Arc<WireStats>,
    ) -> Result<usize> {
        if dc.ready_state() != RTCDataChannelState::Open {
            warn!(event = "send_channel_not_open", state = ?dc.ready_state(), "Attempted send on non-open data channel");
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }

        let envelope = if compress {
            let compressed = compress_data(plaintext).map_err(|e| {
                error!(event = "compress_failure", bytes = plaintext.len(), error = %e, "Compression failed before send");
                e
            })?;
            let mut env = Vec::with_capacity(1 + compressed.len());
            env.push(0x01);
            env.extend_from_slice(&compressed);
            env
        } else {
            let mut env = Vec::with_capacity(1 + plaintext.len());
            env.push(0x00);
            env.extend_from_slice(plaintext);
            env
        };

        let encrypted = encrypt_with(cipher, &envelope).map_err(|e| {
            error!(event = "encrypt_failure", bytes = envelope.len(), error = %e, "Encryption failed before send");
            e
        })?;
        let wire_bytes = encrypted.len();
        dc.send(&Bytes::from(encrypted)).await?;
        // Track every byte leaving the wire
        wire_stats.add_tx(wire_bytes as u64);
        Ok(wire_bytes)
    }

    /// Send a control message on the control channel, returning wire bytes sent.
    pub(crate) async fn send_control_counted(&self, msg: &ControlMessage) -> Result<usize> {
        let dc = self
            .control_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Control channel not available"))?;
        let frame = encode_control_frame(msg)?;
        let key = *self.shared_key.read().await;
        Self::send_encrypted(&dc, &key, &frame, true, &self.wire_stats).await
    }

    /// Send a control message on the control channel.
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<()> {
        self.send_control_counted(msg).await.map(|_| ())
    }

    /// Send a control message on a specific data channel (static version).
    pub(crate) async fn send_control_on(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        msg: &ControlMessage,
        wire_stats: &Arc<WireStats>,
    ) -> Result<()> {
        let frame = encode_control_frame(msg)?;
        Self::send_encrypted(dc, key, &frame, true, wire_stats).await?;
        Ok(())
    }

    // ── Public send API ──────────────────────────────────────────────────

    /// Send a chat message (HMAC + counter authenticated, encrypted) — broadcast / room.
    pub async fn send_message(&self, bytes: Vec<u8>) -> Result<()> {
        let key = *self.shared_key.read().await;
        let hmac_key = derive_chat_hmac_key(&key);
        let counter = {
            let mut c = self.chat_send_counter.write().await;
            *c += 1;
            *c
        };
        let auth_msg = MessageAuthenticator::create(&hmac_key, CHAT_HMAC_CHANNEL, counter, bytes);
        let envelope = serde_json::to_vec(&auth_msg)?;
        self.send_control(&ControlMessage::AuthenticatedText(envelope))
            .await
    }

    /// Send a direct (1-to-1) chat message (HMAC + counter authenticated, encrypted).
    pub async fn send_dm(&self, bytes: Vec<u8>) -> Result<()> {
        let key = *self.shared_key.read().await;
        let hmac_key = derive_chat_hmac_key(&key);
        let counter = {
            let mut c = self.chat_send_counter.write().await;
            *c += 1;
            *c
        };
        let auth_msg = MessageAuthenticator::create(&hmac_key, CHAT_HMAC_CHANNEL, counter, bytes);
        let envelope = serde_json::to_vec(&auth_msg)?;
        self.send_control(&ControlMessage::AuthenticatedDm(envelope))
            .await
    }

    /// Send an ephemeral typing indicator.
    pub async fn send_typing(&self) -> Result<()> {
        self.send_control(&ControlMessage::Typing).await
    }

    /// Send display name to peer.
    pub async fn send_display_name(&self, name: String) -> Result<()> {
        self.send_control(&ControlMessage::DisplayName(name)).await
    }

    /// Send a file from disk with streaming read-ahead — no full-file memory allocation.
    pub async fn send_file(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
        filename: impl Into<String>,
    ) -> Result<()> {
        self.send_file_resuming(file_id, file_path, filesize, filename, 0)
            .await
    }

    /// Send a file from disk, skipping the first `start_chunk` chunks (for resume).
    /// Chunks 0..start_chunk are still hashed but NOT transmitted.
    ///
    /// Streaming: reads chunks from disk via a prefetch buffer, never holds the
    /// entire file in memory.
    pub async fn send_file_resuming(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
        filename: impl Into<String>,
        start_chunk: u32,
    ) -> Result<()> {
        let filename = filename.into();
        let file_path = file_path.into();
        self.wait_data_channels_open().await?;

        let dc = self
            .data_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Data channel not available"))?;

        let chunk_size = CHUNK_SIZE;
        let total_chunks = ((filesize as f64) / (chunk_size as f64)).ceil().max(1.0) as u32;

        // Send metadata on control channel first
        let metadata_wb = self
            .send_control_counted(&ControlMessage::Metadata {
                file_id,
                total_chunks,
                filename: filename.clone(),
                filesize,
            })
            .await? as u64;

        // Short sleep to give the Metadata frame a head-start on the control channel.
        tokio::time::sleep(Duration::from_millis(50)).await;

        info!(event = "file_send_start", file_id = %file_id, filename = %filename, filesize, total_chunks, start_chunk, "Starting file send");

        // Spawn disk reader with prefetch buffer
        let (mut chunk_rx, reader_handle) = crate::core::pipeline::sender::spawn_reader(
            file_path,
            filesize,
            total_chunks,
            chunk_size,
            start_chunk,
        );

        let mut sent_chunks: u32 = start_chunk;
        let key_lock = self.shared_key.clone();
        // Include metadata wire bytes in the first batch report.
        let mut batch_wire_bytes: u64 = metadata_wb;
        let mut batch_count: u32 = 0;

        let key = *key_lock.read().await;

        // Reuse cipher instance across the chunk loop
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        // Reusable frame buffer
        let mut chunk_frame_buf: Vec<u8> = Vec::with_capacity(1 + 16 + 4 + chunk_size);

        // Drain prefetched chunks and send them
        while let Some(read_chunk) = chunk_rx.recv().await {
            encode_chunk_frame_into(
                &mut chunk_frame_buf,
                file_id,
                read_chunk.seq,
                &read_chunk.data,
            );
            let wb = Self::send_encrypted_with_cipher(
                &dc,
                &cipher,
                &chunk_frame_buf,
                false,
                &self.wire_stats,
            )
            .await?;
            batch_wire_bytes += wb as u64;
            batch_count += 1;
            sent_chunks += 1;

            // Report progress every PIPELINE_SIZE chunks
            if batch_count >= PIPELINE_SIZE as u32 {
                if let Some(tx) = &self.app_tx {
                    let _ = tx.send(ConnectionMessage::SendProgress {
                        file_id,
                        filename: filename.clone(),
                        sent_chunks,
                        total_chunks,
                        wire_bytes: batch_wire_bytes,
                    });
                }
                batch_wire_bytes = 0;
                batch_count = 0;
            }
        }

        // Wait for the reader to finish and get hash results
        let reader_result = reader_handle
            .await
            .map_err(|e| anyhow!("Reader task panicked: {}", e))?
            .map_err(|e| anyhow!("Reader error: {}", e))?;

        // Send final hash + Merkle root on control channel.
        let merkle_tree =
            crate::core::pipeline::merkle::MerkleTree::build(&reader_result.chunk_hashes);
        let hash_wb = self
            .send_control_counted(&ControlMessage::Hash {
                file_id,
                sha3_256: reader_result.sha3_256,
                merkle_root: Some(*merkle_tree.root()),
            })
            .await? as u64;

        batch_wire_bytes += hash_wb;

        // Report any remaining progress
        if batch_wire_bytes > 0 || batch_count > 0 {
            if let Some(tx) = &self.app_tx {
                let _ = tx.send(ConnectionMessage::SendProgress {
                    file_id,
                    filename: filename.clone(),
                    sent_chunks,
                    total_chunks,
                    wire_bytes: batch_wire_bytes,
                });
            }
        }

        Ok(())
    }

    // ── Transaction-level API ────────────────────────────────────────────

    /// Send a transaction request to the peer.
    pub async fn send_transaction_request(
        &self,
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionRequest {
            transaction_id,
            display_name,
            manifest,
            total_size,
        })
        .await
    }

    /// Send a transaction response (accept/reject).
    pub async fn send_transaction_response(
        &self,
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionResponse {
            transaction_id,
            accepted,
            dest_path,
            reject_reason,
        })
        .await
    }

    /// Send a transaction resume response.
    pub async fn send_transaction_resume_response(
        &self,
        transaction_id: Uuid,
        accepted: bool,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionResumeResponse {
            transaction_id,
            accepted,
        })
        .await
    }

    pub async fn send_transaction_cancel(
        &self,
        transaction_id: Uuid,
        reason: Option<String>,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionCancel {
            transaction_id,
            reason,
        })
        .await
    }

    pub async fn close(&self) -> Result<()> {
        self.peer_connection.close().await?;
        Ok(())
    }

    /// Register a destination path for a file_id so that incoming Metadata
    /// frames can find the correct save directory.
    pub async fn register_file_destination(&self, file_id: Uuid, dest_path: PathBuf) {
        self.accepted_destinations
            .write()
            .await
            .insert(file_id, dest_path);
    }

    /// Initiate a key rotation by generating a fresh ephemeral keypair,
    /// storing it in `pending_rotation`, and sending the public key to the peer.
    pub async fn initiate_key_rotation(&self) -> Result<()> {
        use crate::core::connection::crypto;

        if self.key_manager.is_none() {
            return Err(anyhow!("No SessionKeyManager — cannot rotate keys"));
        }
        let eph = crypto::prepare_rotation();
        let pub_bytes = eph.public.to_vec();
        *self.pending_rotation.write().await = Some(eph);
        self.send_control(&ControlMessage::KeyRotation {
            ephemeral_pub: pub_bytes,
        })
        .await?;
        info!(
            event = "key_rotation_initiated",
            "Sent ephemeral public key for rotation"
        );
        Ok(())
    }
}
