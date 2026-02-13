//! Receiver: RX operations — file finalization, hash verification, commit.

use anyhow::Result;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::RTCDataChannel;

use super::{ConnectionMessage, ControlMessage, ReceiveFileState, WebRTCConnection};

impl WebRTCConnection {
    // ── Finalization helper ──────────────────────────────────────────────

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
    ///
    /// Extracted so both the Hash handler (normal path) and the chunk
    /// handler (deferred path — Hash arrived before last chunk) can share
    /// the same logic.
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
                let sha3_ok = finalized.sha3_256.as_slice() == sha3_256.as_slice();

                // Check if we have failed chunks from incremental verification
                let failed_chunks = finalized.failed_chunks.clone();
                let has_failed_chunks = !failed_chunks.is_empty();

                // Verify Merkle root against sender's value if provided
                let merkle_ok = if let Some(sender_root) = sender_merkle_root {
                    if finalized.merkle_root == sender_root {
                        tracing::debug!(
                            event = "merkle_root_verified",
                            file_id = %file_id,
                            "Merkle root matches sender"
                        );
                        true
                    } else {
                        warn!(
                            event = "merkle_root_mismatch",
                            file_id = %file_id,
                            filename = %finalized.filename,
                            failed_chunks = ?failed_chunks,
                            "Sender/receiver Merkle root mismatch"
                        );
                        false
                    }
                } else {
                    true // No Merkle root to verify against
                };

                let ok = sha3_ok && merkle_ok;

                // Send hash result — but do NOT let failure prevent file commit.
                // The file save is more important than notifying the sender.
                if let Err(e) = Self::send_control_on(
                    dc,
                    key,
                    &ControlMessage::HashResult { file_id, ok },
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

                if ok {
                    info!(
                        event = "file_recv_verified",
                        file_id = %file_id,
                        filename = %finalized.filename,
                        bytes = finalized.filesize,
                        "File received and hash verified"
                    );

                    // Send FileReceived confirmation IMMEDIATELY after hash
                    // verification — BEFORE the commit (atomic rename).
                    // This unblocks the sender to proceed with the next file
                    // without waiting for the filesystem rename to complete,
                    // eliminating inter-file latency.
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

                    // Commit (atomic rename) in background so the
                    // control channel is immediately free.
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
                } else {
                    let failed_name = finalized.filename.clone();
                    error!(
                        event = "file_integrity_failure",
                        file_id = %file_id,
                        filename = %failed_name,
                        sha3_ok = sha3_ok,
                        merkle_ok = merkle_ok,
                        failed_chunks = ?failed_chunks,
                        "File integrity check failed"
                    );
                    finalized.abort().await;

                    // Request retransmission of specific failed chunks if we have them,
                    // otherwise request all chunks.
                    //
                    // With incremental verification, we know exactly which chunks failed.
                    // If failed_chunks is non-empty, request only those.
                    // If failed_chunks is empty but verification failed, request all.
                    let chunk_indices = if has_failed_chunks {
                        failed_chunks
                    } else {
                        // Empty means retransmit all chunks
                        Vec::new()
                    };

                    info!(
                        event = "requesting_chunk_retransmission",
                        file_id = %file_id,
                        chunk_count = chunk_indices.len(),
                        chunks = ?chunk_indices,
                        "Requesting retransmission of failed chunks"
                    );

                    // Request retransmission
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
}
