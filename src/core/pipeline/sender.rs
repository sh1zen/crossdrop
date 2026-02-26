//! Sender file-transfer pipeline.
//!
//! Owns the file send hot path (chunk read/hash/send, resume and retransmit).

use crate::core::config::{
    CHUNK_SIZE, DATA_ACK_INTERVAL_BYTES, FILE_ACK_POLL_INTERVAL, MAX_PENDING_FILE_ACKS,
    PIPELINE_SIZE,
};
use crate::core::connection::webrtc::data::{encode_chunk_frame_into, CHUNK_FRAME_MIN_SIZE};
use crate::core::connection::webrtc::types::ReceiverDecision;
use crate::core::connection::webrtc::{ConnectionMessage, ControlMessage, WebRTCConnection};
use crate::core::helpers::compute_total_chunks;
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::merkle::IncrementalMerkleBuilder;
use aes_gcm::{aead::KeyInit, Aes256Gcm};
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tracing::{error, info, warn};
use uuid::Uuid;

impl WebRTCConnection {
    /// Precompute and cache per-chunk hashes to reduce send warm-up latency.
    pub async fn prewarm_file_hashes(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
    ) -> Result<()> {
        if self.prewarmed_hashes.lock().await.contains_key(&file_id) {
            return Ok(());
        }

        let file_path = file_path.into();
        let total_chunks = compute_total_chunks(filesize);
        let mut file = tokio::fs::File::open(&file_path).await?;
        let mut hashes = Vec::with_capacity(total_chunks as usize);

        for seq in 0..total_chunks {
            let buf = read_chunk(&mut file, filesize, seq).await?;
            hashes.push(crate::core::pipeline::merkle::hash_chunk(&buf));
        }

        self.prewarmed_hashes.lock().await.insert(file_id, hashes);
        Ok(())
    }

    /// Send a complete file using the interleaved hash+data protocol.
    ///
    /// Delegates to [`send_file_resuming`] with `start_chunk = 0`.
    pub async fn send_file(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
        filename: impl Into<String>,
        transaction_id: Option<Uuid>,
    ) -> Result<()> {
        info!(event = "send_file_called", %file_id, filesize, "send_file called");
        if let Some(txn_id) = transaction_id {
            self.file_to_transaction
                .lock()
                .await
                .insert(file_id, txn_id);
        }
        self.send_file_resuming(file_id, file_path, filesize, filename, 0, transaction_id)
            .await
    }

    /// Send a file using the two-phase hash-verification protocol.
    ///
    /// **Phase 1** - hash all chunks, send `ChunkHashBatch` messages, send `AllHashesSent`.
    /// **Wait**    - block until the receiver replies with `FileSkip` or `FileHaveChunks`
    ///               (or until a 5-second timeout, in which case all chunks are sent).
    /// **Phase 2** - send only the chunks the receiver reported as missing.
    ///
    /// `start_chunk` is kept for API compatibility; it is folded into the bitmap
    /// returned by the receiver so previously-confirmed chunks are skipped automatically.
    pub async fn send_file_resuming(
        &self,
        file_id: Uuid,
        file_path: impl Into<PathBuf>,
        filesize: u64,
        filename: impl Into<String>,
        start_chunk: u32,
        transaction_id: Option<Uuid>,
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

        let total_chunks = compute_total_chunks(filesize);

        let (decision_tx, mut decision_rx) = tokio::sync::oneshot::channel::<ReceiverDecision>();
        self.file_decision_tx
            .lock()
            .await
            .insert(file_id, decision_tx);

        info!(
            event = "send_file_metadata",
            %file_id, %filename, filesize, total_chunks, start_chunk,
            "Sending Metadata control message"
        );
        if let Err(e) = self
            .send_control(&ControlMessage::Metadata {
                file_id,
                total_chunks,
                filename: filename.clone(),
                filesize,
            })
            .await
        {
            self.file_decision_tx.lock().await.remove(&file_id);
            return Err(e);
        }

        tokio::task::yield_now().await;

        if let Ok(ReceiverDecision::Skip) = decision_rx.try_recv() {
            self.file_decision_tx.lock().await.remove(&file_id);
            info!(event = "file_send_pre_skip", %file_id, %filename, "Pre-skip: receiver already has identical file");
            if let Some(ref tx) = self.app_tx {
                let _ = tx.send(ConnectionMessage::SendComplete {
                    file_id,
                    success: true,
                });
            }
            return Ok(());
        }

        let key = *self.shared_key.read().await;
        let cipher = make_cipher(&key)?;

        // Phase 1: send all chunk hashes, build Merkle root incrementally.
        let mut merkle = IncrementalMerkleBuilder::with_capacity(total_chunks as usize);
        let mut hash_batch: Vec<[u8; 32]> = Vec::with_capacity(PIPELINE_SIZE);
        let mut hash_batch_start: u32 = 0;
        let mut phase1_wire: u64 = 0;

        let warmed_hashes = self.prewarmed_hashes.lock().await.remove(&file_id);
        if let Some(hashes) = warmed_hashes
            && hashes.len() == total_chunks as usize
        {
            info!(
                event = "sender_hash_warmup_hit",
                %file_id,
                total_chunks,
                "Using prewarmed chunk hashes for faster start"
            );
            for (seq, hash) in hashes.into_iter().enumerate() {
                merkle.add_leaf(hash);
                if hash_batch.is_empty() {
                    hash_batch_start = seq as u32;
                }
                hash_batch.push(hash);
                if hash_batch.len() >= PIPELINE_SIZE {
                    phase1_wire += self
                        .flush_hash_batch(file_id, hash_batch_start, &mut hash_batch)
                        .await?;
                }
            }
        } else {
            let mut file = tokio::fs::File::open(&file_path).await?;
            for seq in 0..total_chunks {
                if let Some(txn_id) = transaction_id
                    && self.is_transaction_cancelled(txn_id).await
                {
                    self.file_decision_tx.lock().await.remove(&file_id);
                    return Ok(());
                }

                let buf = read_chunk(&mut file, filesize, seq).await?;
                let hash = crate::core::pipeline::merkle::hash_chunk(&buf);
                merkle.add_leaf(hash);

                if hash_batch.is_empty() {
                    hash_batch_start = seq;
                }
                hash_batch.push(hash);
                if hash_batch.len() >= PIPELINE_SIZE {
                    phase1_wire += self
                        .flush_hash_batch(file_id, hash_batch_start, &mut hash_batch)
                        .await?;
                }
            }
        }

        if !hash_batch.is_empty() {
            phase1_wire += self
                .flush_hash_batch(file_id, hash_batch_start, &mut hash_batch)
                .await?;
        }

        phase1_wire += self
            .send_control_counted(&ControlMessage::AllHashesSent { file_id })
            .await?;

        // Wait for receiver decision after hash negotiation.
        let decision = match tokio::time::timeout(
            std::time::Duration::from_secs(45),
            &mut decision_rx,
        )
        .await
        {
            Ok(Ok(d)) => Some(d),
            Ok(Err(_)) => None,
            Err(_) => None,
        };
        self.file_decision_tx.lock().await.remove(&file_id);

        if matches!(decision, Some(ReceiverDecision::Skip)) {
            info!(event = "file_send_post_hash_skip", %file_id, %filename, "Receiver skipped file after hash negotiation");
            if let Some(ref tx) = self.app_tx {
                let _ = tx.send(ConnectionMessage::SendComplete {
                    file_id,
                    success: true,
                });
            }
            return Ok(());
        }

        let mut effective_have = match decision {
            Some(ReceiverDecision::HaveChunks(have_bitmap_bytes)) => {
                ChunkBitmap::from_bytes(&have_bitmap_bytes)
                    .unwrap_or_else(|| ChunkBitmap::new(total_chunks))
            }
            _ => ChunkBitmap::new(total_chunks),
        };
        for s in 0..start_chunk {
            effective_have.set(s);
        }

        // Phase 2: send only missing chunks.
        let mut file = tokio::fs::File::open(&file_path).await?;
        let mut frame_buf = chunk_frame_buf();
        let mut batch_wire: u64 = phase1_wire;
        let mut chunks_sent: u32 = 0;
        let mut ack_bytes: u64 = 0;
        let mut ack_permits: u64 = 0;
        let already_received = (0..total_chunks)
            .filter(|&i| effective_have.is_set(i))
            .count() as u32;

        for seq in 0..total_chunks {
            if let Some(txn_id) = transaction_id
                && self.is_transaction_cancelled(txn_id).await
            {
                return Ok(());
            }

            if effective_have.is_set(seq) {
                continue;
            }

            let buf = read_chunk(&mut file, filesize, seq).await?;
            let wb = self
                .send_chunk_with_retry(&dc, &cipher, &mut frame_buf, file_id, seq, &buf)
                .await? as u64;

            chunks_sent += 1;
            batch_wire += wb;
            ack_bytes += wb;

            let permits_needed = ack_bytes / DATA_ACK_INTERVAL_BYTES;
            while ack_permits < permits_needed {
                self.wait_for_file_slot().await?;
                ack_permits += 1;
            }

            self.report_progress(
                file_id,
                &filename,
                total_chunks,
                batch_wire,
                already_received + chunks_sent,
            );
            batch_wire = 0;
        }

        let merkle_root = *merkle.build().root();
        info!(
            event = "merkle_tree_built",
            %file_id, chunk_count = total_chunks,
            "Built Merkle tree during interleaved send"
        );
        self.send_control(&ControlMessage::Hash {
            file_id,
            merkle_root,
        })
        .await?;

        if batch_wire > 0 {
            self.report_progress(file_id, &filename, total_chunks, batch_wire, total_chunks);
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
        transaction_id: Option<Uuid>,
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

        let total_chunks = compute_total_chunks(filesize);

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
            if let Some(txn_id) = transaction_id
                && self.is_transaction_cancelled(txn_id).await
            {
                info!(event = "file_chunks_send_cancelled", %file_id, %filename, "Cancelled sending chunks due to transaction cancellation");
                return Ok(());
            }

            if seq >= total_chunks {
                warn!(event = "invalid_chunk_index", %file_id, seq, total_chunks, "Skipping invalid chunk index");
                continue;
            }

            let buf = read_chunk(&mut file, filesize, seq).await?;
            let wb = self
                .send_chunk_with_retry(&dc, &cipher, &mut frame_buf, file_id, seq, &buf)
                .await?;

            if let Some(tx) = &self.app_tx {
                let _ = tx.send(ConnectionMessage::SendProgress {
                    file_id,
                    filename: filename.clone(),
                    total_chunks,
                    wire_bytes: wb as u64,
                    chunks_sent: 0,
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
        transaction_id: Option<Uuid>,
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

        let total_chunks = compute_total_chunks(filesize);
        let missing: Vec<u32> = bitmap.missing_chunks().collect();
        let missing_count = missing.len() as u32;
        let already_received = total_chunks - missing_count;

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
        let mut chunks_sent: u32 = 0;
        let mut ack_bytes: u64 = 0;
        let mut ack_permits: u64 = 0;

        for seq in 0..total_chunks {
            if let Some(txn_id) = transaction_id
                && self.is_transaction_cancelled(txn_id).await
            {
                return Ok(());
            }

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
                let wb = self
                    .send_chunk_with_retry(&dc, &cipher, &mut frame_buf, file_id, seq, &buf)
                    .await? as u64;
                chunks_sent += 1;
                batch_wire += wb;
                ack_bytes += wb;

                let permits_needed = ack_bytes / DATA_ACK_INTERVAL_BYTES;
                while ack_permits < permits_needed {
                    self.wait_for_file_slot().await?;
                    ack_permits += 1;
                }

                self.report_progress(
                    file_id,
                    &filename,
                    total_chunks,
                    batch_wire,
                    already_received + chunks_sent,
                );
                batch_wire = 0;
            }
        }

        if !hash_batch.is_empty() {
            batch_wire += self
                .flush_hash_batch(file_id, hash_batch_start, &mut hash_batch)
                .await?;
        }

        let merkle_root = *merkle.build().root();

        self.send_control(&ControlMessage::Hash {
            file_id,
            merkle_root,
        })
        .await?;

        self.report_progress(file_id, &filename, total_chunks, batch_wire, total_chunks);

        info!(event = "file_send_resume_complete", %file_id, %filename, chunks_sent, "Completed file resume send");
        Ok(())
    }

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
        // Keep hashes slightly ahead of chunks on the wire.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        Ok(wb)
    }

    async fn send_chunk_with_retry(
        &self,
        dc: &Arc<webrtc::data_channel::RTCDataChannel>,
        cipher: &aes_gcm::Aes256Gcm,
        frame_buf: &mut Vec<u8>,
        file_id: Uuid,
        seq: u32,
        data: &[u8],
    ) -> Result<usize> {
        encode_chunk_frame_into(frame_buf, file_id, seq, data);
        let mut retries = 0u32;
        loop {
            match Self::send_encrypted_with_cipher(dc, cipher, frame_buf, false, &self.wire_tx)
                .await
            {
                Ok(n) => return Ok(n),
                Err(e) if e.to_string().contains("not open") && retries < 3 => {
                    retries += 1;
                    warn!(
                        event = "send_retry",
                        %file_id, seq, retry = retries, max = 3, %e,
                        "Data channel not open, waiting before retry"
                    );
                    Self::wait_for_data_channel_open(
                        dc,
                        3 - retries,
                        std::time::Duration::from_millis(250),
                    )
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

    async fn wait_for_file_slot(&self) -> Result<()> {
        let mut awake_failures: u32 = 0;
        loop {
            match tokio::time::timeout(FILE_ACK_POLL_INTERVAL, self.file_ack_semaphore.acquire())
                .await
            {
                Ok(Ok(permit)) => {
                    permit.forget();
                    return Ok(());
                }
                Ok(Err(_)) => return Err(anyhow!("File ACK semaphore closed")),
                Err(_) => {
                    warn!(
                        event = "file_ack_slot_wait",
                        pending = MAX_PENDING_FILE_ACKS,
                        timeout = ?FILE_ACK_POLL_INTERVAL,
                        "Waiting for file ACK slot - probing peer liveness"
                    );
                    match self.check_peer_alive().await {
                        Ok(()) => awake_failures = 0,
                        Err(e) => {
                            awake_failures += 1;
                            warn!(
                                event = "file_ack_liveness_probe_failed",
                                failures = awake_failures,
                                %e,
                                "Liveness probe failed while waiting for ACK slot"
                            );
                            if awake_failures >= 6 {
                                return Err(anyhow!(
                                    "Peer not responding while waiting for file ACK slot: {}",
                                    e
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    fn report_progress(
        &self,
        file_id: Uuid,
        filename: &str,
        total_chunks: u32,
        wire_bytes: u64,
        chunks_sent_total: u32,
    ) {
        if let Some(tx) = &self.app_tx {
            let _ = tx.send(ConnectionMessage::SendProgress {
                file_id,
                filename: filename.to_owned(),
                total_chunks,
                wire_bytes,
                chunks_sent: chunks_sent_total,
            });
        }
    }
}

#[inline]
fn make_cipher(key: &[u8; 32]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("Failed to create AES cipher: {}", e))
}

#[inline]
fn chunk_frame_buf() -> Vec<u8> {
    Vec::with_capacity(CHUNK_FRAME_MIN_SIZE + CHUNK_SIZE)
}

async fn read_chunk(file: &mut tokio::fs::File, filesize: u64, seq: u32) -> Result<Vec<u8>> {
    let offset = seq as u64 * CHUNK_SIZE as u64;
    let len = (CHUNK_SIZE as u64).min(filesize.saturating_sub(offset)) as usize;
    file.seek(SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).await?;
    Ok(buf)
}
