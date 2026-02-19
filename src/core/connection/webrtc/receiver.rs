//! Receiver: RX operations — file finalization, hash verification, commit.
use super::{ConnectionMessage, ControlMessage, ReceiveFileState, WebRTCConnection};
use anyhow::Result;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::RTCDataChannel;

// ── Verification result ───────────────────────────────────────────────────────

/// Outcome of all integrity checks run after a file is fully received.
struct FileVerificationResult {
    sha3_ok: bool,
    merkle_ok: bool,
    /// Chunks whose per-chunk hash did not match during streaming verification.
    failed_chunks: Vec<u32>,
}

impl FileVerificationResult {
    fn new(
        computed_sha3: &[u8],
        expected_sha3: &[u8],
        sender_merkle_root: Option<[u8; 32]>,
        computed_merkle_root: &[u8; 32],
        failed_chunks: &[u32],
    ) -> Self {
        let sha3_ok = computed_sha3 == expected_sha3;
        let merkle_ok = match sender_merkle_root {
            Some(sender_root) => {
                let ok = computed_merkle_root == &sender_root;
                if ok {
                    tracing::debug!(event = "merkle_root_verified", "Merkle root matches sender");
                } else {
                    warn!(
                        event = "merkle_root_mismatch",
                        "Sender/receiver Merkle root mismatch"
                    );
                }
                ok
            }
            // No sender root to compare against — treat as passing.
            None => true,
        };
        Self {
            sha3_ok,
            merkle_ok,
            failed_chunks: failed_chunks.to_vec(),
        }
    }

    #[inline]
    fn is_valid(&self) -> bool {
        self.sha3_ok && self.merkle_ok
    }

    #[inline]
    fn has_failed_chunks(&self) -> bool {
        !self.failed_chunks.is_empty()
    }
}

// ── Finalization ──────────────────────────────────────────────────────────────

impl WebRTCConnection {
    /// Finalize a fully-received file:
    ///   1. Flush the writer.
    ///   2. Verify SHA-3 + Merkle root.
    ///   3. Send `HashResult` to the sender.
    ///   4. Commit (or abort and request retransmission) accordingly.
    ///
    /// Finalization runs from a `tokio::spawn` call so it must not return
    /// before all side effects complete; errors are logged locally.
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
        let finalized = match state.writer.finalize().await {
            Ok(f) => f,
            Err(e) => {
                error!(event = "file_finalize_failed", %file_id, %e, "Failed to finalize received file");
                notify_app_err(app_tx, format!("Failed to finalize file: {e}"));
                return Ok(());
            }
        };

        let result = FileVerificationResult::new(
            &finalized.sha3_256,
            &sha3_256,
            sender_merkle_root,
            &finalized.merkle_root,
            &finalized.failed_chunks,
        );

        // Best-effort: send HashResult; a send failure should not prevent commit.
        if let Err(e) = WebRTCConnection::send_control_on(
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
            warn!(event = "hash_result_send_failed", %file_id, %e,
                "Failed to send HashResult (file will still be committed if valid)");
        }

        if result.is_valid() {
            Self::commit_received_file(dc, file_id, finalized, key, app_tx, wire_tx).await;
        } else {
            Self::reject_received_file(dc, file_id, finalized, result, key, app_tx, wire_tx).await;
        }

        Ok(())
    }

    // ── Post-verification paths ───────────────────────────────────────────

    /// Happy path: confirm receipt to sender, then commit file to disk in the background.
    async fn commit_received_file(
        dc: &Arc<RTCDataChannel>,
        file_id: Uuid,
        finalized: crate::core::pipeline::receiver::FinalizedFile,
        key: &[u8; 32],
        app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
        wire_tx: &Arc<AtomicU64>,
    ) {
        info!(
            event = "file_recv_verified",
            %file_id, filename = %finalized.filename, bytes = finalized.filesize,
            "File received and hash verified"
        );

        // Unblock the sender before the (potentially slow) disk commit.
        if let Err(e) = WebRTCConnection::send_control_on(
            dc,
            key,
            &ControlMessage::FileReceived { file_id },
            wire_tx,
        )
        .await
        {
            warn!(event = "file_received_confirm_failed", %file_id, %e,
                "Failed to send FileReceived confirmation");
        }

        let filename = finalized.filename.clone();
        let filesize = finalized.filesize;
        let merkle_root = finalized.merkle_root;
        let app_tx = app_tx.clone();

        tokio::spawn(async move {
            match finalized.commit().await {
                Ok(save_path) => {
                    info!("File receive complete: {} ({} bytes)", filename, filesize);
                    notify_app(
                        &app_tx,
                        ConnectionMessage::FileSaved {
                            file_id,
                            filename,
                            path: save_path.to_string_lossy().into_owned(),
                            merkle_root,
                        },
                    );
                }
                Err(e) => {
                    error!("Failed to commit file {}: {}", filename, e);
                    notify_app_err(&app_tx, format!("Failed to save {filename}: {e}"));
                }
            }
        });
    }

    /// Error path: abort the temp file, log the failure, request chunk retransmission.
    async fn reject_received_file(
        dc: &Arc<RTCDataChannel>,
        file_id: Uuid,
        finalized: crate::core::pipeline::receiver::FinalizedFile,
        result: FileVerificationResult,
        key: &[u8; 32],
        app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
        wire_tx: &Arc<AtomicU64>,
    ) {
        error!(
            event = "file_integrity_failure",
            %file_id, filename = %finalized.filename,
            sha3_ok = result.sha3_ok, merkle_ok = result.merkle_ok,
            failed_chunks = ?result.failed_chunks,
            "File integrity check failed"
        );

        let failed_name = finalized.filename.clone();
        finalized.abort().await;

        // An empty list signals the sender to retransmit everything.
        let chunk_indices: Vec<u32> = if result.has_failed_chunks() {
            result.failed_chunks
        } else {
            Vec::new()
        };

        info!(
            event = "requesting_chunk_retransmission",
            %file_id, count = chunk_indices.len(), chunks = ?chunk_indices,
            "Requesting retransmission of failed chunks"
        );

        if let Err(e) = WebRTCConnection::send_control_on(
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
            warn!(event = "chunk_retransmit_request_failed", %file_id, %e,
                "Failed to send ChunkRetransmitRequest");
        }

        notify_app_err(app_tx, format!("Hash mismatch for {failed_name}"));
    }
}

// ── Notification helpers ──────────────────────────────────────────────────────

fn notify_app(app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>, msg: ConnectionMessage) {
    if let Some(tx) = app_tx {
        let _ = tx.send(msg);
    }
}

fn notify_app_err(app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>, err: String) {
    notify_app(app_tx, ConnectionMessage::Error(err));
}
