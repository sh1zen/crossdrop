//! Receiver: RX operations — file finalization, hash verification, commit.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::RTCDataChannel;

use super::{ConnectionMessage, ControlMessage, ReceiveFileState, WebRTCConnection};

impl WebRTCConnection {
    /// Finalize a fully-received file: flush, verify hash + Merkle root,
    /// send HashResult to the sender, and commit or abort.
    ///
    /// # Incremental Verification
    ///
    /// If a verifier was set on the writer, chunks were verified as they arrived.
    /// The `failed_chunks` list contains chunks that failed verification.
    /// These chunks are requested for retransmission instead of the entire file.
    ///
    /// # Async Confirmation
    ///
    /// After successfully committing the file, sends a `FileReceived` confirmation
    /// to the sender, allowing the sender to continue with the next file without
    /// waiting for the full processing to complete.
    pub(crate) async fn finalize_file_receive(
        dc: &Arc<RTCDataChannel>,
        file_id: Uuid,
        state: ReceiveFileState,
        sha3_256: Vec<u8>,
        sender_merkle_root: Option<[u8; 32]>,
        key: &[u8; 32],
        app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<()> {
        match state.writer.finalize().await {
            Ok(finalized) => {
                let result = FileVerificationResult::new(
                    &finalized.sha3_256,
                    &sha3_256,
                    sender_merkle_root,
                    &finalized.merkle_root,
                    &finalized.failed_chunks,
                );

                // Send hash result (don't let failure prevent commit)
                if let Err(e) = Self::send_control_on(
                    dc,
                    key,
                    &ControlMessage::HashResult {
                        file_id,
                        ok: result.is_valid(),
                    },
                    wire_tx,
                )
                .await
                {
                    warn!(
                        event = "hash_result_send_failed",
                        file_id = %file_id,
                        error = %e,
                        "Failed to send HashResult to sender (file will still be committed)"
                    );
                }

                if result.is_valid() {
                    Self::handle_successful_receive(
                        dc, file_id, finalized, key, app_tx, wire_tx,
                    ).await;
                } else {
                    Self::handle_failed_receive(
                        dc, file_id, finalized, result, key, app_tx, wire_tx,
                    ).await;
                }
            }
            Err(e) => {
                error!(
                    event = "file_finalize_failed",
                    file_id = %file_id,
                    error = %e,
                    "Failed to finalize received file"
                );
                if let Some(tx) = app_tx {
                    let _ = tx.send(ConnectionMessage::Error(format!(
                        "Failed to finalize file: {}",
                        e
                    )));
                }
            }
        }
        Ok(())
    }

    /// Handle a successfully verified file receive.
    async fn handle_successful_receive(
        dc: &Arc<RTCDataChannel>,
        file_id: Uuid,
        finalized: crate::core::pipeline::receiver::FinalizedFile,
        key: &[u8; 32],
        app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
        wire_tx: &Arc<AtomicU64>,
    ) {
        info!(
            event = "file_recv_verified",
            file_id = %file_id,
            filename = %finalized.filename,
            bytes = finalized.filesize,
            "File received and hash verified"
        );

        // Send FileReceived confirmation BEFORE commit (unblocks sender)
        if let Err(e) = Self::send_control_on(
            dc,
            key,
            &ControlMessage::FileReceived { file_id },
            wire_tx,
        )
        .await
        {
            warn!(
                event = "file_received_confirm_failed",
                file_id = %file_id,
                error = %e,
                "Failed to send FileReceived confirmation"
            );
        }

        let filename = finalized.filename.clone();
        let filesize = finalized.filesize;
        let merkle_root = finalized.merkle_root;
        let app_tx_clone = app_tx.clone();

        // Commit in background (don't block control channel)
        tokio::spawn(async move {
            match finalized.commit().await {
                Ok(save_path) => {
                    tracing::info!(
                        "File receive complete: {} ({} bytes)",
                        filename,
                        filesize
                    );
                    if let Some(tx) = &app_tx_clone {
                        let _ = tx.send(ConnectionMessage::FileSaved {
                            file_id,
                            filename: filename.clone(),
                            path: save_path.to_string_lossy().to_string(),
                            merkle_root,
                        });
                    }
                }
                Err(e) => {
                    error!("Failed to commit file {}: {}", filename, e);
                    if let Some(tx) = &app_tx_clone {
                        let _ = tx.send(ConnectionMessage::Error(format!(
                            "Failed to save {}: {}",
                            filename, e
                        )));
                    }
                }
            }
        });
    }

    /// Handle a failed file receive (hash mismatch).
    async fn handle_failed_receive(
        dc: &Arc<RTCDataChannel>,
        file_id: Uuid,
        finalized: crate::core::pipeline::receiver::FinalizedFile,
        result: FileVerificationResult,
        key: &[u8; 32],
        app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
        wire_tx: &Arc<AtomicU64>,
    ) {
        let failed_name = finalized.filename.clone();
        error!(
            event = "file_integrity_failure",
            file_id = %file_id,
            filename = %failed_name,
            sha3_ok = result.sha3_ok,
            merkle_ok = result.merkle_ok,
            failed_chunks = ?result.failed_chunks,
            "File integrity check failed"
        );
        finalized.abort().await;

        // Request retransmission of specific chunks if available
        let chunk_indices = if result.has_failed_chunks() {
            result.failed_chunks.clone()
        } else {
            Vec::new() // Empty means retransmit all
        };

        info!(
            event = "requesting_chunk_retransmission",
            file_id = %file_id,
            chunk_count = chunk_indices.len(),
            chunks = ?chunk_indices,
            "Requesting retransmission of failed chunks"
        );

        if let Err(e) = Self::send_control_on(
            dc,
            key,
            &ControlMessage::ChunkRetransmitRequest {
                file_id,
                chunk_indices,
            },
            wire_tx,
        )
        .await
        {
            warn!(
                event = "chunk_retransmit_request_failed",
                file_id = %file_id,
                error = %e,
                "Failed to send ChunkRetransmitRequest"
            );
        }

        if let Some(tx) = app_tx {
            let _ = tx.send(ConnectionMessage::Error(format!(
                "Hash mismatch for {}",
                failed_name
            )));
        }
    }
}

// ── Verification Result ────────────────────────────────────────────────────────

/// Result of file verification after receive.
struct FileVerificationResult {
    sha3_ok: bool,
    merkle_ok: bool,
    failed_chunks: Vec<u32>,
}

impl FileVerificationResult {
    /// Create a verification result from the finalized file data.
    fn new(
        computed_sha3: &[u8],
        expected_sha3: &[u8],
        sender_merkle_root: Option<[u8; 32]>,
        computed_merkle_root: &[u8; 32],
        failed_chunks: &[u32],
    ) -> Self {
        let sha3_ok = computed_sha3 == expected_sha3;

        let merkle_ok = sender_merkle_root
            .map(|sender_root| {
                if computed_merkle_root == &sender_root {
                    tracing::debug!(
                        event = "merkle_root_verified",
                        "Merkle root matches sender"
                    );
                    true
                } else {
                    warn!(
                        event = "merkle_root_mismatch",
                        "Sender/receiver Merkle root mismatch"
                    );
                    false
                }
            })
            .unwrap_or(true); // No Merkle root to verify against

        Self {
            sha3_ok,
            merkle_ok,
            failed_chunks: failed_chunks.to_vec(),
        }
    }

    /// Check if the file passed all verification checks.
    #[inline]
    fn is_valid(&self) -> bool {
        self.sha3_ok && self.merkle_ok
    }

    /// Check if we have specific failed chunks to request retransmission for.
    #[inline]
    fn has_failed_chunks(&self) -> bool {
        !self.failed_chunks.is_empty()
    }
}
