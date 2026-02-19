//! Sender: TX operations — sending files, messages, control frames.

use super::{
    compress_data, derive_chat_hmac_key, encrypt, encrypt_with, ConnectionMessage,
    ControlMessage, WebRTCConnection, CHAT_HMAC_CHANNEL,
};
use crate::core::config::{
    CHUNK_SIZE, DC_BUFFERED_AMOUNT_HIGH, DC_REOPEN_TIMEOUT, DC_SEND_MAX_RETRIES, PIPELINE_SIZE,
};
use crate::core::connection::webrtc::data::{encode_chunk_frame_into, encode_control_frame};
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::merkle::IncrementalMerkleBuilder;
use crate::core::security::message_auth::MessageAuthenticator;
use crate::core::transaction::TransactionManifest;
use aes_gcm::{aead::KeyInit, Aes256Gcm};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use sha3::Digest;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;

// ── Wire-level send primitives ────────────────────────────────────────────────

/// Outcome of a single encrypted send: wire bytes written.
type WireBytes = usize;

/// Shared arguments for the hot-path encrypted send functions.
/// Groups the data channel + wire counter together to reduce parameter lists.
struct SendTarget<'a> {
    dc: &'a Arc<RTCDataChannel>,
    wire_tx: &'a Arc<AtomicU64>,
}

impl<'a> SendTarget<'a> {
    fn new(dc: &'a Arc<RTCDataChannel>, wire_tx: &'a Arc<AtomicU64>) -> Self {
        Self { dc, wire_tx }
    }

    /// Verify the channel is `Open`; return an error otherwise.
    fn assert_open(&self) -> Result<()> {
        let state = self.dc.ready_state();
        if state == RTCDataChannelState::Open {
            Ok(())
        } else {
            warn!(
                event = "send_channel_not_open",
                ?state,
                "Attempted send on non-open data channel"
            );
            Err(anyhow!("Data channel not open: {:?}", state))
        }
    }

    /// Account for bytes that left the wire.
    fn record(&self, n: usize) {
        self.wire_tx.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Build the on-wire frame: `[compress_flag] ++ encrypted([maybe_compressed] plaintext)`.
///
/// When `compress=false` the flag byte is `0x00` and no intermediate copy is made.
/// When `compress=true`  the flag byte is `0x01` and plaintext is compressed first.
fn build_wire_frame_key(key: &[u8; 32], plaintext: &[u8], compress: bool) -> Result<Vec<u8>> {
    let (flag, ciphertext) = if compress {
        let compressed = compress_data(plaintext).map_err(|e| {
            error!(event = "compress_failure", bytes = plaintext.len(), %e);
            e
        })?;
        let ct = encrypt(key, &compressed).map_err(|e| {
            error!(event = "encrypt_failure", bytes = compressed.len(), %e);
            e
        })?;
        (0x01u8, ct)
    } else {
        let ct = encrypt(key, plaintext).map_err(|e| {
            error!(event = "encrypt_failure", bytes = plaintext.len(), %e);
            e
        })?;
        (0x00u8, ct)
    };
    Ok(prepend_flag(flag, &ciphertext))
}

fn build_wire_frame_cipher(
    cipher: &Aes256Gcm,
    plaintext: &[u8],
    compress: bool,
) -> Result<Vec<u8>> {
    let (flag, ciphertext) = if compress {
        let compressed = compress_data(plaintext).map_err(|e| {
            error!(event = "compress_failure", bytes = plaintext.len(), %e);
            e
        })?;
        let ct = encrypt_with(cipher, &compressed).map_err(|e| {
            error!(event = "encrypt_failure", bytes = compressed.len(), %e);
            e
        })?;
        (0x01u8, ct)
    } else {
        let ct = encrypt_with(cipher, plaintext).map_err(|e| {
            error!(event = "encrypt_failure", bytes = plaintext.len(), %e);
            e
        })?;
        (0x00u8, ct)
    };
    Ok(prepend_flag(flag, &ciphertext))
}

#[inline]
fn prepend_flag(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + payload.len());
    frame.push(flag);
    frame.extend_from_slice(payload);
    frame
}

// ── Backpressure ──────────────────────────────────────────────────────────────

/// Poll until the SCTP send buffer has room for `next_msg_size` bytes, or time out.
async fn wait_for_buffer_space(dc: &Arc<RTCDataChannel>, next_msg_size: usize) -> Result<()> {
    let state = dc.ready_state();
    if state != RTCDataChannelState::Open {
        return Err(anyhow!("Data channel not open: {:?}", state));
    }

    if dc.buffered_amount().await as usize + next_msg_size <= DC_BUFFERED_AMOUNT_HIGH {
        return Ok(());
    }

    let buffered_amount = dc.buffered_amount().await;
    info!(
        channel = %dc.label(),
        buffered = buffered_amount,
        next_msg = next_msg_size,
        high_watermark = DC_BUFFERED_AMOUNT_HIGH,
        "Applying backpressure - waiting for buffer to drain"
    );

    const MAX_WAIT: Duration = Duration::from_secs(10);
    const POLL_INTERVAL: Duration = Duration::from_millis(10);
    let deadline = std::time::Instant::now() + MAX_WAIT;

    loop {
        if dc.ready_state() != RTCDataChannelState::Open {
            return Err(anyhow!(
                "DataChannel '{}' closed during backpressure wait",
                dc.label()
            ));
        }
        if dc.buffered_amount().await as usize + next_msg_size <= DC_BUFFERED_AMOUNT_HIGH {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    if dc.ready_state() == RTCDataChannelState::Open {
        let buffered_amount = dc.buffered_amount().await;
        warn!(channel = %dc.label(), buffered = buffered_amount, "Buffer drain timeout - proceeding anyway");
        Ok(())
    } else {
        Err(anyhow!(
            "DataChannel '{}' closed during backpressure wait",
            dc.label()
        ))
    }
}

// ── WebRTCConnection send methods ────────────────────────────────────────────

impl WebRTCConnection {
    // ── Low-level encrypted send ──────────────────────────────────────────

    /// Send an encrypted frame on a data channel (derives cipher per call).
    ///
    /// Wire format: `[0x00|0x01] ++ AES-256-GCM([maybe_compressed] plaintext)`
    pub async fn send_encrypted(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        plaintext: &[u8],
        compress: bool,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<WireBytes> {
        let target = SendTarget::new(dc, wire_tx);
        target.assert_open()?;
        let frame = build_wire_frame_key(key, plaintext, compress)?;
        let n = frame.len();
        dc.send(&Bytes::from(frame)).await?;
        target.record(n);
        Ok(n)
    }

    /// Send an encrypted frame using a pre-initialized cipher (hot-path variant).
    ///
    /// Includes backpressure: blocks if the SCTP send buffer is above the high watermark.
    pub async fn send_encrypted_with_cipher(
        dc: &Arc<RTCDataChannel>,
        cipher: &Aes256Gcm,
        plaintext: &[u8],
        compress: bool,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<WireBytes> {
        let target = SendTarget::new(dc, wire_tx);
        target.assert_open()?;
        let frame = build_wire_frame_cipher(cipher, plaintext, compress)?;
        wait_for_buffer_space(dc, frame.len()).await?;
        let n = frame.len();
        dc.send(&Bytes::from(frame)).await?;
        target.record(n);
        Ok(n)
    }

    /// Wait for `dc` to enter `Open` state, retrying up to `max_retries` times.
    pub async fn wait_for_data_channel_open(
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
                state => {
                    if attempt < max_retries {
                        debug!(
                            channel = %dc.label(),
                            attempt = attempt + 1,
                            max_retries,
                            ?state,
                            "Waiting for data channel to open"
                        );
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }
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

    // ── Control channel helpers ───────────────────────────────────────────

    /// Encode, compress, and encrypt a control message; return wire bytes sent.
    pub async fn send_control_counted(&self, msg: &ControlMessage) -> Result<u64> {
        let dc = self
            .control_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Control channel not available"))?;
        let frame = encode_control_frame(msg)?;
        let key = *self.shared_key.read().await;
        Self::send_encrypted(&dc, &key, &frame, true, &self.wire_tx)
            .await
            .map(|n| n as u64)
    }

    /// Encode and send a control message; discard the byte count.
    pub async fn send_control(&self, msg: &ControlMessage) -> Result<()> {
        self.send_control_counted(msg).await.map(|_| ())
    }

    /// Send a control message on an arbitrary data channel (static helper).
    pub async fn send_control_on(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        msg: &ControlMessage,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<()> {
        let frame = encode_control_frame(msg)?;
        Self::send_encrypted(dc, key, &frame, true, wire_tx).await?;
        Ok(())
    }

    // ── Public messaging API ──────────────────────────────────────────────

    /// Send an HMAC-authenticated, encrypted chat broadcast.
    pub async fn send_message(&self, bytes: Vec<u8>) -> Result<()> {
        let envelope = self.build_authenticated_envelope(bytes).await?;
        self.send_control(&ControlMessage::AuthenticatedText(envelope))
            .await
    }

    /// Send an HMAC-authenticated, encrypted direct message.
    pub async fn send_dm(&self, bytes: Vec<u8>) -> Result<()> {
        let envelope = self.build_authenticated_envelope(bytes).await?;
        self.send_control(&ControlMessage::AuthenticatedDm(envelope))
            .await
    }

    /// Build and serialize an `AuthenticatedMessage` envelope.
    async fn build_authenticated_envelope(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        let key = *self.shared_key.read().await;
        let hmac_key = derive_chat_hmac_key(&key);
        let counter = {
            let mut c = self.chat_send_counter.write().await;
            *c += 1;
            *c
        };
        let auth_msg = MessageAuthenticator::create(&hmac_key, CHAT_HMAC_CHANNEL, counter, payload);
        Ok(serde_json::to_vec(&auth_msg)?)
    }

    pub async fn send_typing(&self) -> Result<()> {
        self.send_control(&ControlMessage::Typing).await
    }

    pub async fn send_display_name(&self, name: String) -> Result<()> {
        self.send_control(&ControlMessage::DisplayName(name)).await
    }

    // ── File send API ─────────────────────────────────────────────────────

    /// Send a complete file; delegates to `send_file_resuming` with `start_chunk = 0`.
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

    /// Send a file, skipping already-sent chunks (`0..start_chunk`).
    ///
    /// Uses a streaming disk reader with a prefetch buffer to avoid loading the
    /// full file into memory.  Chunk hashes are sent in batches ahead of their
    /// data chunks so the receiver can start incremental Merkle verification.
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

        let total_chunks = total_chunks(filesize);

        // Send metadata first; include its wire bytes in the first progress report.
        let mut batch_wire: u64 = self
            .send_control_counted(&ControlMessage::Metadata {
                file_id,
                total_chunks,
                filename: filename.clone(),
                filesize,
            })
            .await?;

        // Give the Metadata frame a head-start on the control channel.
        tokio::time::sleep(Duration::from_millis(50)).await;

        info!(
            event = "file_send_start",
            %file_id, %filename, filesize, total_chunks, start_chunk,
            "Starting file send with incremental Merkle"
        );

        let (mut chunk_rx, reader_handle) = crate::core::pipeline::sender::spawn_reader(
            file_path.clone(),
            filesize,
            total_chunks,
            CHUNK_SIZE,
            start_chunk,
        );

        debug!(event = "reader_spawned", %file_id, "Disk reader spawned");

        let key = *self.shared_key.read().await;
        let cipher = make_cipher(&key)?;
        let mut chunk_frame_buf = chunk_frame_buf();
        let mut merkle = IncrementalMerkleBuilder::with_capacity(total_chunks as usize);

        // Pending hash / chunk batches: hashes are sent before their data.
        let mut hash_batch: Vec<[u8; 32]> = Vec::with_capacity(PIPELINE_SIZE);
        let mut hash_batch_start: u32 = 0;
        let mut chunk_batch: Vec<(u32, Vec<u8>)> = Vec::with_capacity(PIPELINE_SIZE);

        let mut sent_chunks: u32 = start_chunk;
        let mut batch_count: u32 = 0;

        while let Some(rc) = chunk_rx.recv().await {
            merkle.add_leaf(rc.hash);

            if hash_batch.is_empty() {
                hash_batch_start = rc.seq;
            }
            hash_batch.push(rc.hash);
            chunk_batch.push((rc.seq, rc.data.to_vec()));

            if hash_batch.len() >= PIPELINE_SIZE {
                batch_wire += self
                    .flush_hash_batch(file_id, hash_batch_start, &mut hash_batch)
                    .await?;

                for (seq, data) in chunk_batch.drain(..) {
                    batch_wire += self
                        .send_chunk_with_retry(
                            &dc,
                            &cipher,
                            &mut chunk_frame_buf,
                            file_id,
                            seq,
                            &data,
                        )
                        .await? as u64;
                    batch_count += 1;
                    sent_chunks += 1;
                }

                if batch_count >= PIPELINE_SIZE as u32 {
                    self.report_progress(file_id, &filename, sent_chunks, total_chunks, batch_wire);
                    batch_wire = 0;
                    batch_count = 0;
                }
            }
        }

        // Final progress for any incomplete batch
        if batch_count > 0 || batch_wire > 0 {
            self.report_progress(file_id, &filename, sent_chunks, total_chunks, batch_wire);
        }

        // Await reader completion.
        let reader_result = reader_handle
            .await
            .map_err(|e| anyhow!("Reader task panicked: {}", e))?
            .map_err(|e| anyhow!("Reader error: {}", e))?;

        // Flush any leftover hash/chunk batches.
        let mut tail_wire: u64 = 0;
        if !hash_batch.is_empty() {
            tail_wire += self
                .flush_hash_batch(file_id, hash_batch_start, &mut hash_batch)
                .await?;

            for (seq, data) in chunk_batch.drain(..) {
                tail_wire += self
                    .send_chunk_with_retry(&dc, &cipher, &mut chunk_frame_buf, file_id, seq, &data)
                    .await? as u64;
                sent_chunks += 1;
            }
        }

        let merkle_root = *merkle.build().root();
        info!(
            event = "merkle_tree_built",
            %file_id,
            chunk_count = total_chunks,
            "Built Merkle tree incrementally during send"
        );

        tail_wire += self
            .send_control_counted(&ControlMessage::Hash {
                file_id,
                sha3_256: reader_result.whole_file_hash,
                merkle_root: Some(merkle_root),
            })
            .await?;

        if tail_wire > 0 {
            self.report_progress(file_id, &filename, sent_chunks, total_chunks, tail_wire);
        }

        Ok(())
    }

    /// Send only the specified chunks of a file (targeted retransmission).
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

        let total_chunks = total_chunks(filesize);

        info!(
            event = "file_chunks_send_start",
            %file_id, %filename, chunks = ?chunk_indices,
            "Sending specific chunks for retransmission"
        );

        let key = *self.shared_key.read().await;
        let cipher = make_cipher(&key)?;
        let mut file = tokio::fs::File::open(&file_path).await?;
        let mut frame_buf = chunk_frame_buf();

        for seq in chunk_indices {
            if seq >= total_chunks {
                warn!(event = "invalid_chunk_index", %file_id, seq, total_chunks, "Skipping invalid chunk index");
                continue;
            }

            let buf = read_chunk(&mut file, filesize, seq).await?;
            encode_chunk_frame_into(&mut frame_buf, file_id, seq, &buf);

            let wb =
                Self::send_encrypted_with_cipher(&dc, &cipher, &frame_buf, false, &self.wire_tx)
                    .await?;

            if let Some(tx) = &self.app_tx {
                let _ = tx.send(ConnectionMessage::SendProgress {
                    file_id,
                    filename: filename.clone(),
                    sent_chunks: seq + 1,
                    total_chunks,
                    wire_bytes: wb as u64,
                });
            }
        }

        info!(event = "file_chunks_send_complete", %file_id, %filename, "Completed sending requested chunks");
        Ok(())
    }

    /// Send missing chunks according to a bitmap (non-contiguous resume).
    ///
    /// All chunk hashes are computed for Merkle correctness; only missing chunks
    /// are sent over the wire.
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

        let total_chunks = total_chunks(filesize);
        let missing: Vec<u32> = bitmap.missing_chunks().collect();
        let missing_count = missing.len() as u32;

        if missing_count == 0 {
            info!(event = "file_send_complete_all_chunks", %file_id, %filename, "All chunks already received, nothing to send");
            return Ok(());
        }

        let mut batch_wire: u64 = self
            .send_control_counted(&ControlMessage::Metadata {
                file_id,
                total_chunks,
                filename: filename.clone(),
                filesize,
            })
            .await?;

        tokio::time::sleep(Duration::from_millis(50)).await;

        info!(
            event = "file_send_resume_bitmap",
            %file_id, %filename, filesize, total_chunks, missing_count,
            "Resuming file send with bitmap ({} missing chunks)", missing_count
        );

        let key = *self.shared_key.read().await;
        let cipher = make_cipher(&key)?;
        let mut file = tokio::fs::File::open(&file_path).await?;
        let mut frame_buf = chunk_frame_buf();
        let mut merkle = IncrementalMerkleBuilder::with_capacity(total_chunks as usize);

        let mut hash_batch: Vec<[u8; 32]> = Vec::with_capacity(PIPELINE_SIZE);
        let mut hash_batch_start: u32 = 0;
        let mut sent_chunks: u32 = 0;

        for seq in 0..total_chunks {
            let buf = read_chunk(&mut file, filesize, seq).await?;
            let hash = crate::core::pipeline::merkle::hash_chunk(&buf);
            merkle.add_leaf(hash);

            if hash_batch.is_empty() {
                hash_batch_start = seq;
            }
            hash_batch.push(hash);

            if hash_batch.len() >= PIPELINE_SIZE {
                batch_wire += self
                    .flush_hash_batch(file_id, hash_batch_start, &mut hash_batch)
                    .await?;
            }

            if !bitmap.is_set(seq) {
                encode_chunk_frame_into(&mut frame_buf, file_id, seq, &buf);
                let wb = Self::send_encrypted_with_cipher(
                    &dc,
                    &cipher,
                    &frame_buf,
                    false,
                    &self.wire_tx,
                )
                .await?;
                sent_chunks += 1;
                batch_wire += wb as u64;

                if sent_chunks % 20 == 0 {
                    self.report_progress(
                        file_id,
                        &filename,
                        sent_chunks,
                        missing_count,
                        batch_wire,
                    );
                    batch_wire = 0;
                }
            }
        }

        // Flush remaining hashes.
        if !hash_batch.is_empty() {
            batch_wire += self
                .flush_hash_batch(file_id, hash_batch_start, &mut hash_batch)
                .await?;
        }

        // Compute whole-file hash and send final Hash message.
        let merkle_root = *merkle.build().root();
        let final_hash = hash_file_streaming(&mut file, filesize).await?;

        self.send_control(&ControlMessage::Hash {
            file_id,
            sha3_256: final_hash,
            merkle_root: Some(merkle_root),
        })
        .await?;

        self.report_progress(file_id, &filename, missing_count, missing_count, batch_wire);

        info!(event = "file_send_resume_complete", %file_id, %filename, sent_chunks, "Completed file resume send");
        Ok(())
    }

    // ── Transaction API ───────────────────────────────────────────────────

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

    pub async fn register_file_destination(&self, file_id: Uuid, dest_path: PathBuf) {
        self.accepted_destinations
            .write()
            .await
            .insert(file_id, dest_path);
    }

    pub async fn register_resume_bitmap(
        &self,
        file_id: Uuid,
        bitmap: crate::core::pipeline::chunk::ChunkBitmap,
    ) {
        self.resume_bitmaps.write().await.insert(file_id, bitmap);
    }

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

    // ── Private helpers ───────────────────────────────────────────────────

    /// Flush a pending hash batch over the control channel; clears `batch`.
    async fn flush_hash_batch(
        &self,
        file_id: Uuid,
        start_index: u32,
        batch: &mut Vec<[u8; 32]>,
    ) -> Result<u64> {
        let wb = self
            .send_control_counted(&ControlMessage::ChunkHashBatch {
                file_id,
                start_index,
                chunk_hashes: std::mem::take(batch),
            })
            .await?;
        // Small delay: ensure hash batch arrives before the data chunks that follow.
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(wb)
    }

    /// Send one chunk with retry logic for transient "channel not open" errors.
    async fn send_chunk_with_retry(
        &self,
        dc: &Arc<RTCDataChannel>,
        cipher: &Aes256Gcm,
        frame_buf: &mut Vec<u8>,
        file_id: Uuid,
        seq: u32,
        data: &[u8],
    ) -> Result<WireBytes> {
        encode_chunk_frame_into(frame_buf, file_id, seq, data);

        let mut retries = 0u32;
        loop {
            match Self::send_encrypted_with_cipher(dc, cipher, frame_buf, false, &self.wire_tx)
                .await
            {
                Ok(n) => return Ok(n),
                Err(e) if e.to_string().contains("not open") && retries < DC_SEND_MAX_RETRIES => {
                    retries += 1;
                    warn!(
                        event = "send_retry",
                        %file_id, seq, retry = retries, max = DC_SEND_MAX_RETRIES, %e,
                        "Data channel not open, waiting before retry"
                    );
                    Self::wait_for_data_channel_open(dc, DC_SEND_MAX_RETRIES - retries, DC_REOPEN_TIMEOUT)
                        .await
                        .map_err(|we| {
                            error!(event = "channel_wait_failed", %file_id, error = %we, "Data channel failed to reopen");
                            we
                        })?;
                }
                Err(e) => {
                    error!(event = "send_failed", %file_id, seq, retries, %e, "Failed to send chunk");
                    return Err(e);
                }
            }
        }
    }

    /// Emit a `SendProgress` event if an app channel is registered.
    fn report_progress(
        &self,
        file_id: Uuid,
        filename: &str,
        sent_chunks: u32,
        total_chunks: u32,
        wire_bytes: u64,
    ) {
        if let Some(tx) = &self.app_tx {
            let _ = tx.send(ConnectionMessage::SendProgress {
                file_id,
                filename: filename.to_owned(),
                sent_chunks,
                total_chunks,
                wire_bytes,
            });
        }
    }
}

// ── Module-level helpers ──────────────────────────────────────────────────────

/// Compute the total number of CHUNK_SIZE chunks required to cover `filesize` bytes.
#[inline]
fn total_chunks(filesize: u64) -> u32 {
    ((filesize as f64) / (CHUNK_SIZE as f64)).ceil().max(1.0) as u32
}

/// Create a reusable AES-256-GCM cipher from a 32-byte key.
#[inline]
fn make_cipher(key: &[u8; 32]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("Failed to create AES cipher: {}", e))
}

/// Allocate the reusable chunk-frame buffer (header + max chunk payload).
#[inline]
fn chunk_frame_buf() -> Vec<u8> {
    // 1 byte type tag + 16 bytes UUID + 4 bytes seq + CHUNK_SIZE data
    Vec::with_capacity(1 + 16 + 4 + CHUNK_SIZE)
}

/// Read exactly the bytes belonging to chunk `seq` from `file`.
async fn read_chunk(file: &mut tokio::fs::File, filesize: u64, seq: u32) -> Result<Vec<u8>> {
    let offset = seq as u64 * CHUNK_SIZE as u64;
    let len = (CHUNK_SIZE as u64).min(filesize.saturating_sub(offset)) as usize;
    file.seek(SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Hash the entire file by streaming it in CHUNK_SIZE windows.
async fn hash_file_streaming(file: &mut tokio::fs::File, filesize: u64) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0)).await?;
    let mut hasher = sha3::Sha3_256::default();
    let mut remaining = filesize;
    while remaining > 0 {
        let to_read = (CHUNK_SIZE as u64).min(remaining) as usize;
        let mut buf = vec![0u8; to_read];
        file.read_exact(&mut buf).await?;
        sha3::Digest::update(&mut hasher, &buf);
        remaining -= to_read as u64;
    }
    Ok(hasher.finalize().to_vec())
}
