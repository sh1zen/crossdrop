//! Receiver: RX operations — file finalization, hash verification, commit.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::RTCDataChannel;

use super::{
    ConnectionMessage, ControlMessage, ReceiveFileState, WebRTCConnection, WireStats,
};

impl WebRTCConnection {
    // ── Finalization helper ──────────────────────────────────────────────

    /// Finalize a fully-received file: flush, verify hash + Merkle root,
    /// send HashResult to the sender, and commit or abort.
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
        wire_stats: &Arc<WireStats>,
    ) -> Result<()> {
        match state.writer.finalize().await {
            Ok(finalized) => {
                let ok = finalized.sha3_256.as_slice() == sha3_256.as_slice();

                // Verify Merkle root against sender's value if provided
                if let Some(sender_root) = sender_merkle_root {
                    if finalized.merkle_root != sender_root {
                        warn!(
                            event = "merkle_root_mismatch",
                            file_id = %file_id,
                            filename = %finalized.filename,
                            "Sender/receiver Merkle root mismatch — possible data corruption"
                        );
                    } else {
                        tracing::debug!(
                            event = "merkle_root_verified",
                            file_id = %file_id,
                            "Merkle root matches sender"
                        );
                    }
                }

                // Send hash result — but do NOT let failure prevent file commit.
                // The file save is more important than notifying the sender.
                if let Err(e) = Self::send_control_on(
                    dc,
                    key,
                    &ControlMessage::HashResult { file_id, ok },
                    wire_stats,
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
                                        filename,
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
                        "File integrity check failed: hash mismatch"
                    );
                    finalized.abort().await;
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
