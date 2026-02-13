//! Sender: TX operations — sending files, messages, control frames.

use aes_gcm::{aead::KeyInit, Aes256Gcm};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;

use crate::core::config::{
    CHUNK_SIZE, DC_BUFFERED_AMOUNT_HIGH, DC_REOPEN_TIMEOUT, DC_SEND_MAX_RETRIES, PIPELINE_SIZE,
};
use crate::core::connection::webrtc::data::{encode_chunk_frame_into, encode_control_frame};
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::merkle::IncrementalMerkleBuilder;
use crate::core::security::message_auth::MessageAuthenticator;
use crate::core::transaction::TransactionManifest;
use sha3::Digest;

use super::{
    compress_data, derive_chat_hmac_key, encrypt, encrypt_with, ConnectionMessage,
    ControlMessage, WebRTCConnection, CHAT_HMAC_CHANNEL,
};

impl WebRTCConnection {
    // ── Send helpers ─────────────────────────────────────────────────────

    /// Send an encrypted frame on the given data channel.
    ///
    /// Wire format:
    /// - compress=false: [0x00] + encrypted(plaintext)
    /// - compress=true:  [0x01] + encrypted(compressed(plaintext))
    ///
    /// For chunks, use `send_encrypted_with_cipher` which supports the same format
    /// but with a pre-initialized cipher for better performance.
    pub(crate) async fn send_encrypted(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        plaintext: &[u8],
        compress: bool,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<usize> {
        if dc.ready_state() != RTCDataChannelState::Open {
            warn!(event = "send_channel_not_open", state = ?dc.ready_state(), "Attempted send on non-open data channel");
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }

        // Wire format: [compress_flag] + encrypted([maybe_compressed_plaintext])
        // The flag is OUTSIDE the encryption so receiver knows how to process.
        let (flag, data_to_encrypt) = if compress {
            let compressed = compress_data(plaintext).map_err(|e| {
                error!(event = "compress_failure", bytes = plaintext.len(), error = %e, "Compression failed before send");
                e
            })?;
            (0x01, compressed)
        } else {
            (0x00, plaintext.to_vec())
        };

        let encrypted = encrypt(key, &data_to_encrypt).map_err(|e| {
            error!(event = "encrypt_failure", bytes = data_to_encrypt.len(), error = %e, "Encryption failed before send");
            e
        })?;

        // Build wire data: [flag] + [encrypted]
        let mut wire_data = Vec::with_capacity(1 + encrypted.len());
        wire_data.push(flag);
        wire_data.extend_from_slice(&encrypted);

        let wire_bytes = wire_data.len();
        dc.send(&Bytes::from(wire_data)).await?;
        // Track every byte leaving the wire
        wire_tx.fetch_add(wire_bytes as u64, Ordering::Relaxed);
        Ok(wire_bytes)
    }

    /// Send an encrypted frame using a pre-initialized cipher (avoids
    /// re-creating AES-256-GCM state per call — useful in hot loops).
    /// Includes backpressure handling via buffered_amount monitoring.
    ///
    /// # Compression modes
    ///
    /// When `compress` is true, the data is compressed BEFORE encryption.
    /// Wire format: [compress_flag=0x01] + [encrypted(compressed(plaintext))]
    ///
    /// When `compress` is false, no compression is applied.
    /// Wire format: [compress_flag=0x00] + [encrypted(plaintext)]
    pub(crate) async fn send_encrypted_with_cipher(
        dc: &Arc<RTCDataChannel>,
        cipher: &Aes256Gcm,
        plaintext: &[u8],
        compress: bool,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<usize> {
        if dc.ready_state() != RTCDataChannelState::Open {
            warn!(event = "send_channel_not_open", state = ?dc.ready_state(), "Attempted send on non-open data channel");
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }

        // Compress first (if requested), then encrypt.
        // When compress=false (file chunks), we encrypt plaintext directly
        // without an intermediate copy — saving one allocation per chunk.
        let (flag, encrypted) = if compress {
            let compressed = compress_data(plaintext).map_err(|e| {
                error!(event = "compress_failure", bytes = plaintext.len(), error = %e, "Compression failed before send");
                e
            })?;
            let enc = encrypt_with(cipher, &compressed).map_err(|e| {
                error!(event = "encrypt_failure", bytes = compressed.len(), error = %e, "Encryption failed before send");
                e
            })?;
            (0x01u8, enc)
        } else {
            let enc = encrypt_with(cipher, plaintext).map_err(|e| {
                error!(event = "encrypt_failure", bytes = plaintext.len(), error = %e, "Encryption failed before send");
                e
            })?;
            (0x00u8, enc)
        };

        // Build wire data: [flag] + [encrypted]
        let mut wire_data = Vec::with_capacity(1 + encrypted.len());
        wire_data.push(flag);
        wire_data.extend_from_slice(&encrypted);

        let wire_bytes = wire_data.len();

        // Apply backpressure: wait if buffered_amount is too high
        Self::wait_for_buffer_space(dc, wire_bytes).await?;

        dc.send(&Bytes::from(wire_data)).await?;
        // Track every byte leaving the wire
        wire_tx.fetch_add(wire_bytes as u64, Ordering::Relaxed);
        Ok(wire_bytes)
    }

    /// Wait for the SCTP send buffer to have enough space for the next message.
    /// This prevents overwhelming the transport on slow links (TURN, mobile).
    /// Simplified version: just check and proceed, with optional short wait.
    async fn wait_for_buffer_space(dc: &Arc<RTCDataChannel>, next_msg_size: usize) -> Result<()> {
        // Quick check - if channel not open, fail fast
        if dc.ready_state() != RTCDataChannelState::Open {
            return Err(anyhow!("Data channel not open: {:?}", dc.ready_state()));
        }

        let buffered = dc.buffered_amount().await as usize;

        // If we're below the high water mark, we can send immediately
        if buffered + next_msg_size <= DC_BUFFERED_AMOUNT_HIGH {
            return Ok(());
        }

        // Log that we're applying backpressure
        info!(
            channel = %dc.label(),
            buffered = buffered,
            next_msg = next_msg_size,
            high_watermark = DC_BUFFERED_AMOUNT_HIGH,
            "Applying backpressure - waiting for buffer to drain"
        );

        // Simple approach: wait a short time for buffer to drain.
        // Use a tight poll interval (10ms) to minimise inter-chunk
        // latency when the SCTP buffer drains quickly.
        let max_wait = Duration::from_secs(10);
        let check_interval = Duration::from_millis(10);
        let start = std::time::Instant::now();

        while start.elapsed() < max_wait {
            // Check if channel is still open
            if dc.ready_state() != RTCDataChannelState::Open {
                return Err(anyhow!(
                    "DataChannel '{}' closed during backpressure wait",
                    dc.label()
                ));
            }

            let current_buffered = dc.buffered_amount().await as usize;
            if current_buffered + next_msg_size <= DC_BUFFERED_AMOUNT_HIGH {
                return Ok(());
            }

            tokio::time::sleep(check_interval).await;
        }

        // Timeout - check if channel is still usable and proceed anyway
        if dc.ready_state() == RTCDataChannelState::Open {
            let final_buffered = dc.buffered_amount().await;
            warn!(
                channel = %dc.label(),
                buffered = final_buffered,
                "Buffer drain timeout - proceeding anyway"
            );
            Ok(())
        } else {
            Err(anyhow!(
                "DataChannel '{}' closed during backpressure wait",
                dc.label()
            ))
        }
    }

    /// Wait for the data channel to be open with retry logic.
    /// Returns Ok(()) if the channel is open, Err if permanently closed.
    pub(crate) async fn wait_for_data_channel_open(
        dc: &Arc<RTCDataChannel>,
        max_retries: u32,
        retry_delay: Duration,
    ) -> Result<()> {
        for attempt in 0..=max_retries {
            match dc.ready_state() {
                RTCDataChannelState::Open => return Ok(()),
                RTCDataChannelState::Closed => {
                    return Err(anyhow!(
                        "DataChannel '{}' is permanently closed",
                        dc.label()
                    ));
                }
                _ => {
                    if attempt < max_retries {
                        debug!(
                            channel = %dc.label(),
                            attempt = attempt + 1,
                            max_retries,
                            state = ?dc.ready_state(),
                            "Waiting for data channel to open"
                        );
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }

        // Final check
        match dc.ready_state() {
            RTCDataChannelState::Open => Ok(()),
            RTCDataChannelState::Closed => Err(anyhow!(
                "DataChannel '{}' is permanently closed",
                dc.label()
            )),
            state => Err(anyhow!(
                "DataChannel '{}' not open after {} retries (state: {:?})",
                dc.label(),
                max_retries,
                state
            )),
        }
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
        Self::send_encrypted(&dc, &key, &frame, true, &self.wire_tx).await
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
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<()> {
        let frame = encode_control_frame(msg)?;
        Self::send_encrypted(dc, key, &frame, true, wire_tx).await?;
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
    ///
    /// # Incremental Merkle Verification
    ///
    /// Chunk hashes are computed and sent in batches as chunks are being sent.
    /// This eliminates the need to pre-compute all hashes before sending,
    /// reducing latency for large files.
    /// The receiver verifies each chunk as it arrives and can request
    /// retransmission of corrupted chunks immediately.
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

        info!(event = "file_send_start", file_id = %file_id, filename = %filename, filesize, total_chunks, start_chunk, "Starting file send with incremental Merkle");

        // Spawn disk reader with prefetch buffer
        let (mut chunk_rx, reader_handle) = crate::core::pipeline::sender::spawn_reader(
            file_path.clone(),
            filesize,
            total_chunks,
            chunk_size,
            start_chunk,
        );

        debug!(event = "reader_spawned", file_id = %file_id, "Disk reader spawned");

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

        // Incremental Merkle builder - compute hashes as we send
        let mut merkle_builder = IncrementalMerkleBuilder::with_capacity(total_chunks as usize);
        
        // Buffer for collecting chunk hashes to send in batches BEFORE chunks
        let mut pending_hashes: Vec<[u8; 32]> = Vec::with_capacity(PIPELINE_SIZE);
        let mut pending_hash_start: u32 = 0;
        // Buffer for chunks waiting to be sent (after their hashes are sent)
        let mut pending_chunks: Vec<(u32, Vec<u8>)> = Vec::with_capacity(PIPELINE_SIZE);

        // Drain prefetched chunks and send them with retry logic
        while let Some(read_chunk) = chunk_rx.recv().await {
            let seq = read_chunk.seq;
            let data = &read_chunk.data;
            let chunk_hash = read_chunk.hash;

            // Use pre-computed chunk hash for incremental Merkle tree
            merkle_builder.add_leaf(chunk_hash);
            
            // Add to pending hashes batch
            if pending_hashes.is_empty() {
                pending_hash_start = seq;
            }
            pending_hashes.push(chunk_hash);
            // Store chunk data for later sending (after hash batch is sent)
            pending_chunks.push((seq, data.to_vec()));

            // Send chunk hashes in batches BEFORE sending the chunks
            if pending_hashes.len() >= PIPELINE_SIZE {
                let hash_batch_wb = self
                    .send_control_counted(&ControlMessage::ChunkHashBatch {
                        file_id,
                        start_index: pending_hash_start,
                        chunk_hashes: std::mem::take(&mut pending_hashes),
                    })
                    .await? as u64;
                batch_wire_bytes += hash_batch_wb;
                
                // Small delay to ensure hash batch arrives before chunks
                tokio::time::sleep(Duration::from_millis(5)).await;
                
                // Now send all pending chunks
                for (chunk_seq, chunk_data) in pending_chunks.drain(..) {
                    encode_chunk_frame_into(
                        &mut chunk_frame_buf,
                        file_id,
                        chunk_seq,
                        &chunk_data,
                    );

                    // Retry loop for transient failures.
                    // Chunks are sent WITHOUT Brotli compression (compress=false):
                    // - File data is typically already compressed or incompressible
                    // - Removing Brotli saves ~0.5-1ms CPU per chunk, which dominates
                    //   throughput on fast networks (>10x improvement for binary data)
                    // - Control messages still use compression (JSON compresses well)
                    let mut retry_count = 0u32;
                    let wb = loop {
                        match Self::send_encrypted_with_cipher(
                            &dc,
                            &cipher,
                            &chunk_frame_buf,
                            false, // no compression for file chunks — pure encryption
                            &self.wire_tx,
                        )
                        .await
                        {
                            Ok(wb) => break wb,
                            Err(e) => {
                                // Check if this is a transient "not open" error
                                let is_transient = e.to_string().contains("not open");

                                if is_transient && retry_count < DC_SEND_MAX_RETRIES {
                                    retry_count += 1;
                                    warn!(
                                        event = "send_retry",
                                        file_id = %file_id,
                                        chunk = chunk_seq,
                                        retry = retry_count,
                                        max_retries = DC_SEND_MAX_RETRIES,
                                        error = %e,
                                        "Data channel not open, waiting before retry"
                                    );

                                    // Wait for the channel to potentially reopen
                                    if let Err(wait_err) = Self::wait_for_data_channel_open(
                                        &dc,
                                        DC_SEND_MAX_RETRIES - retry_count,
                                        DC_REOPEN_TIMEOUT,
                                    )
                                    .await
                                    {
                                        error!(
                                            event = "channel_wait_failed",
                                            file_id = %file_id,
                                            error = %wait_err,
                                            "Data channel failed to reopen"
                                        );
                                        return Err(wait_err);
                                    }
                                } else {
                                    // Non-transient error or max retries exceeded
                                    error!(
                                        event = "send_failed",
                                        file_id = %file_id,
                                        chunk = chunk_seq,
                                        retries = retry_count,
                                        error = %e,
                                        "Failed to send chunk"
                                    );
                                    return Err(e);
                                }
                            }
                        }
                    };

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
            }
        }

        // Report final progress to ensure the last batch is persisted
        if batch_count > 0 || batch_wire_bytes > 0 {
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

        // Wait for the reader to finish and get the final result
        let reader_result = reader_handle
            .await
            .map_err(|e| anyhow!("Reader task panicked: {}", e))?
            .map_err(|e| anyhow!("Reader error: {}", e))?;

        // Send any remaining pending hashes BEFORE remaining chunks
        if !pending_hashes.is_empty() {
            let hash_batch_wb = self
                .send_control_counted(&ControlMessage::ChunkHashBatch {
                    file_id,
                    start_index: pending_hash_start,
                    chunk_hashes: std::mem::take(&mut pending_hashes),
                })
                .await? as u64;
            batch_wire_bytes += hash_batch_wb;
            
            // Small delay to ensure hash batch arrives before chunks
            tokio::time::sleep(Duration::from_millis(5)).await;
            
            // Send any remaining pending chunks
            for (chunk_seq, chunk_data) in pending_chunks.drain(..) {
                encode_chunk_frame_into(
                    &mut chunk_frame_buf,
                    file_id,
                    chunk_seq,
                    &chunk_data,
                );

                let wb = Self::send_encrypted_with_cipher(
                    &dc,
                    &cipher,
                    &chunk_frame_buf,
                    false,
                    &self.wire_tx,
                )
                .await?;

                batch_wire_bytes += wb as u64;
                batch_count += 1;
                sent_chunks += 1;
            }
        }

        // Build the final Merkle tree from incrementally collected hashes
        let merkle_tree = merkle_builder.build();
        let merkle_root = *merkle_tree.root();

        info!(
            event = "merkle_tree_built",
            file_id = %file_id,
            chunk_count = merkle_tree.leaves().len(),
            "Built Merkle tree incrementally during send"
        );

        // Send final hash + Merkle root on control channel
        let hash_wb = self
            .send_control_counted(&ControlMessage::Hash {
                file_id,
                sha3_256: reader_result.whole_file_hash,
                merkle_root: Some(merkle_root),
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

    /// Send specific chunks of a file (for retransmission after Merkle integrity failure).
    ///
    /// This method reads and sends only the specified chunks, allowing targeted
    /// retransmission when the receiver detects corruption via Merkle proof verification.
    pub async fn send_file_chunks(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
        filename: impl Into<String>,
        chunk_indices: Vec<u32>,
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

        info!(
            event = "file_chunks_send_start",
            file_id = %file_id,
            filename = %filename,
            chunks = ?chunk_indices,
            "Sending specific chunks for retransmission"
        );

        let key = *self.shared_key.read().await;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        // Read and send only the requested chunks
        let mut file = tokio::fs::File::open(&file_path).await?;
        let mut chunk_frame_buf: Vec<u8> = Vec::with_capacity(1 + 16 + 4 + chunk_size);

        for seq in chunk_indices {
            if seq >= total_chunks {
                warn!(
                    event = "invalid_chunk_index",
                    file_id = %file_id,
                    seq = seq,
                    total_chunks = total_chunks,
                    "Skipping invalid chunk index"
                );
                continue;
            }

            let offset = (seq as u64) * (chunk_size as u64);
            let remaining = filesize.saturating_sub(offset);
            let len = (chunk_size as u64).min(remaining) as usize;

            file.seek(SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).await?;

            encode_chunk_frame_into(&mut chunk_frame_buf, file_id, seq, &buf);

            // No compression for retransmitted chunks (same as regular chunks)
            Self::send_encrypted_with_cipher(&dc, &cipher, &chunk_frame_buf, false, &self.wire_tx)
                .await?;

            if let Some(tx) = &self.app_tx {
                let _ = tx.send(ConnectionMessage::SendProgress {
                    file_id,
                    filename: filename.clone(),
                    sent_chunks: seq + 1,
                    total_chunks,
                    wire_bytes: buf.len() as u64,
                });
            }
        }

        info!(
            event = "file_chunks_send_complete",
            file_id = %file_id,
            filename = %filename,
            "Completed sending requested chunks"
        );

        Ok(())
    }

    /// Send a file from disk, skipping chunks that are already received according to the bitmap.
    /// This is the preferred method for resume as it handles non-contiguous chunk gaps.
    ///
    /// The bitmap indicates which chunks the receiver already has. Only missing chunks
    /// are sent, regardless of their position in the file.
    pub async fn send_file_with_bitmap(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
        filename: impl Into<String>,
        bitmap: ChunkBitmap,
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

        // Get missing chunks from the bitmap
        let missing_chunks: Vec<u32> = bitmap.missing_chunks().collect();
        let missing_count = missing_chunks.len() as u32;

        if missing_count == 0 {
            info!(
                event = "file_send_complete_all_chunks",
                file_id = %file_id,
                filename = %filename,
                "All chunks already received, nothing to send"
            );
            return Ok(());
        }

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

        info!(
            event = "file_send_resume_bitmap",
            file_id = %file_id,
            filename = %filename,
            filesize,
            total_chunks,
            missing_count,
            "Resuming file send with bitmap (sending {} missing chunks)",
            missing_count
        );

        let key = *self.shared_key.read().await;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

        // Open file for random access
        let mut file = tokio::fs::File::open(&file_path).await?;
        let mut chunk_frame_buf: Vec<u8> = Vec::with_capacity(1 + 16 + 4 + chunk_size);

        // Incremental Merkle builder - we need to add ALL chunk hashes (even already-received ones)
        // to compute the correct Merkle root. We'll read and hash all chunks but only send missing ones.
        let mut merkle_builder = IncrementalMerkleBuilder::with_capacity(total_chunks as usize);

        // Buffer for collecting chunk hashes to send in batches
        let mut pending_hashes: Vec<[u8; 32]> = Vec::with_capacity(PIPELINE_SIZE);
        let mut pending_hash_start: u32 = 0;

        let mut sent_chunks = 0u32;
        let mut batch_wire_bytes: u64 = metadata_wb;

        // Process all chunks: compute hashes for Merkle tree, but only send missing chunks
        for seq in 0..total_chunks {
            let offset = (seq as u64) * (chunk_size as u64);
            let remaining = filesize.saturating_sub(offset);
            let len = (chunk_size as u64).min(remaining) as usize;

            file.seek(SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).await?;

            // Compute chunk hash for Merkle tree
            let chunk_hash = crate::core::pipeline::merkle::hash_chunk(&buf);
            merkle_builder.add_leaf(chunk_hash);

            // Add to pending hashes batch
            if pending_hashes.is_empty() {
                pending_hash_start = seq;
            }
            pending_hashes.push(chunk_hash);

            // Send hash batches as we go (for all chunks, not just missing ones)
            if pending_hashes.len() >= PIPELINE_SIZE {
                let hash_batch_wb = self
                    .send_control_counted(&ControlMessage::ChunkHashBatch {
                        file_id,
                        start_index: pending_hash_start,
                        chunk_hashes: std::mem::take(&mut pending_hashes),
                    })
                    .await? as u64;
                batch_wire_bytes += hash_batch_wb;
            }

            // Only send the chunk if it's missing from the receiver's bitmap
            if !bitmap.is_set(seq) {
                encode_chunk_frame_into(&mut chunk_frame_buf, file_id, seq, &buf);

                let wb = Self::send_encrypted_with_cipher(
                    &dc,
                    &cipher,
                    &chunk_frame_buf,
                    false, // no compression for file chunks
                    &self.wire_tx,
                )
                .await?;

                sent_chunks += 1;
                batch_wire_bytes += wb as u64;

                // Report progress periodically
                if sent_chunks % 20 == 0 {
                    if let Some(tx) = &self.app_tx {
                        let _ = tx.send(ConnectionMessage::SendProgress {
                            file_id,
                            filename: filename.clone(),
                            sent_chunks,
                            total_chunks: missing_count, // Report progress relative to missing chunks
                            wire_bytes: batch_wire_bytes,
                        });
                    }
                    batch_wire_bytes = 0;
                }
            }
        }

        // Send any remaining hashes
        if !pending_hashes.is_empty() {
            let hash_batch_wb = self
                .send_control_counted(&ControlMessage::ChunkHashBatch {
                    file_id,
                    start_index: pending_hash_start,
                    chunk_hashes: std::mem::take(&mut pending_hashes),
                })
                .await? as u64;
            batch_wire_bytes += hash_batch_wb;
        }

        // Send final hash with Merkle root
        let merkle_tree = merkle_builder.build();
        let merkle_root = *merkle_tree.root();
        let final_hash = {
            let mut hasher = sha3::Sha3_256::default();
            // Re-read the file for whole-file hash (or we could use the Merkle root)
            file.seek(SeekFrom::Start(0)).await?;
            let mut remaining = filesize;
            while remaining > 0 {
                let to_read = (chunk_size as u64).min(remaining) as usize;
                let mut buf = vec![0u8; to_read];
                file.read_exact(&mut buf).await?;
                sha3::Digest::update(&mut hasher, &buf);
                remaining -= to_read as u64;
            }
            hasher.finalize().to_vec()
        };

        self.send_control(&ControlMessage::Hash {
            file_id,
            sha3_256: final_hash,
            merkle_root: Some(merkle_root),
        })
        .await?;

        // Final progress report
        if let Some(tx) = &self.app_tx {
            let _ = tx.send(ConnectionMessage::SendProgress {
                file_id,
                filename: filename.clone(),
                sent_chunks: missing_count,
                total_chunks: missing_count,
                wire_bytes: batch_wire_bytes,
            });
        }

        info!(
            event = "file_send_resume_complete",
            file_id = %file_id,
            filename = %filename,
            sent_chunks = sent_chunks,
            "Completed file resume send"
        );

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

    /// Register a chunk bitmap for a file_id so that the Metadata handler
    /// can resume the file writer from the existing temp file instead of
    /// truncating it.  Called before sending a resume request.
    pub async fn register_resume_bitmap(
        &self,
        file_id: Uuid,
        bitmap: crate::core::pipeline::chunk::ChunkBitmap,
    ) {
        self.resume_bitmaps.write().await.insert(file_id, bitmap);
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
