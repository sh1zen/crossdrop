//! Control channel: data channel message handler and control message dispatch.
//!
//! This module handles all incoming messages on the WebRTC data channels,
//! dispatching them to appropriate handlers based on frame type.

use super::data::{decode_frame, parse_control_message, DecodedFrame};
use super::types::ReceiverDecision;
use super::{
    decompress_data, AckContext, ConnectionMessage, ControlMessage, PendingHash, ReceiveFileState,
    WebRTCConnection,
};
use crate::core::connection::crypto::SessionKeyManager;
use crate::core::helpers::notify_app;
use crate::core::pipeline::merkle::ChunkHashVerifier;
use aes_gcm::aead::KeyInit;
use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;

mod chat;
mod file_transfer;
mod key_rotation;
mod remote_access;
mod verification;
use chat::handle_authenticated_message;
use file_transfer::{handle_chunk_frame, handle_metadata, spawn_finalization};
use key_rotation::handle_key_rotation;
use remote_access::read_dir_entries;
use verification::handle_all_hashes_sent;
// â”€â”€ Handler context â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Shared context threaded through every data-channel message handler.
///
/// All fields are cheaply cloneable (`Arc`s or `Option<Sender<â€¦>>`).
/// The struct is `Clone` so it can be captured by the `on_message` closure.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct HandlerContext {
    pub recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    pub pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
    pub accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    pub resume_bitmaps: Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    pub app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    pub shared_key: Arc<RwLock<[u8; 32]>>,
    pub key_manager: Option<SessionKeyManager>,
    pub pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    pub chat_recv_counter: Arc<RwLock<u64>>,
    pub wire_tx: Arc<AtomicU64>,
    pub wire_rx: Arc<AtomicU64>,
    pub file_ack_semaphore: Arc<Semaphore>,
    /// Whether the local peer has enabled remote-access (ls/fetch) requests.
    pub remote_access_enabled: bool,
    /// Transactions cancelled locally; checked by in-flight send tasks.
    pub cancelled_transactions: Arc<tokio::sync::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    /// Cumulative wire bytes received on the data channel; drives DataAck pacing.
    pub data_rx_bytes: Arc<AtomicU64>,
    /// One-shot channels for the two-phase file-verification handshake.
    pub file_decision_tx: Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<uuid::Uuid, tokio::sync::oneshot::Sender<ReceiverDecision>>,
        >,
    >,
    /// Files pre-determined as identical by a receiver-side background Merkle check.
    /// When Metadata arrives for one of these, we skip the writer and reply FileSkip
    /// immediately â€” zero data transfer.
    pub pre_skip_files: Arc<
        tokio::sync::Mutex<std::collections::HashMap<uuid::Uuid, (std::path::PathBuf, [u8; 32])>>,
    >,
    /// File IDs for which we already replied with `FileSkip`.
    pub skipped_files: Arc<tokio::sync::Mutex<std::collections::HashSet<uuid::Uuid>>>,
    /// Reverse index: file_id â†’ transaction_id, for O(1) lookup.
    pub file_to_transaction:
        Arc<tokio::sync::Mutex<std::collections::HashMap<uuid::Uuid, uuid::Uuid>>>,
}

// â”€â”€ Frame decryption â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Decrypt and optionally decompress an incoming wire frame.
///
/// Wire format: `[compress_flag] ++ AES-256-GCM([maybe_compressed] plaintext)`
///
/// - `0x00` â€” plaintext was encrypted directly (no compression)
/// - `0x01` â€” plaintext was compressed then encrypted
///
/// Returns `None` and logs on any error; the caller should silently drop
/// the message in that case (mimics the previous behaviour exactly).
fn decrypt_frame(
    cipher: &aes_gcm::Aes256Gcm,
    data: &[u8],
    app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
) -> Option<Vec<u8>> {
    let (&compress_flag, encrypted) = data.split_first()?;

    let decrypted = super::decrypt_with(cipher, encrypted)
        .map_err(|e| {
            error!(event = "decrypt_failure", bytes = encrypted.len(), %e, "Decryption failed");
            notify_app(
                app_tx,
                ConnectionMessage::Error(format!("Decrypt error: {e}")),
            );
            e
        })
        .ok()?;

    if compress_flag == 0x01 {
        decompress_data(&decrypted)
            .map_err(|e| {
                error!(event = "decompress_failure", bytes = decrypted.len(), %e, "Decompression failed");
                notify_app(app_tx, ConnectionMessage::Error(format!("Decompress error: {e}")));
                e
            })
            .ok()
    } else {
        Some(decrypted)
    }
}

// â”€â”€ Handler attachment â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Attach `on_open`, `on_close`, `on_error`, and `on_message` callbacks to `dc`.
pub async fn attach_dc_handlers(dc: &Arc<RTCDataChannel>, ctx: HandlerContext) {
    let label = dc.label().to_string();
    dc.on_close(Box::new(move || {
        let label = label.clone();
        Box::pin(async move {
            tracing::warn!(event = "dc_closed", channel = %label, "DataChannel closed by transport");
        })
    }));

    let label = dc.label().to_string();
    dc.on_error(Box::new(move |err| {
        let label = label.clone();
        Box::pin(async move {
            tracing::error!(event = "dc_error", channel = %label, %err, "DataChannel transport error");
        })
    }));

    let dc_ref = dc.clone();
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let ctx = ctx.clone();
        let dc = dc_ref.clone();
        Box::pin(async move { handle_incoming_message(&dc, msg, &ctx).await })
    }));
}

// â”€â”€ Top-level message dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async fn handle_incoming_message(
    dc: &Arc<RTCDataChannel>,
    msg: DataChannelMessage,
    ctx: &HandlerContext,
) {
    ctx.wire_rx
        .fetch_add(msg.data.len() as u64, Ordering::Relaxed);

    if msg.data.is_empty() {
        return;
    }

    let key = *ctx.shared_key.read().await;
    let cipher = match aes_gcm::Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(e) => {
            error!(event = "cipher_init_failure", %e, "Failed to init AES cipher");
            return;
        }
    };

    let decrypted = match decrypt_frame(&cipher, &msg.data, &ctx.app_tx) {
        Some(d) => d,
        None => return,
    };

    match decode_frame(&decrypted) {
        Ok(DecodedFrame::Control(payload)) => match parse_control_message(payload) {
            Ok(ctrl) => {
                if let Err(e) = handle_control(dc, ctrl, ctx).await {
                    error!(event = "control_handle_error", %e, "Error handling control message");
                    notify_app(
                        &ctx.app_tx,
                        ConnectionMessage::Error(format!("Control error: {e}")),
                    );
                }
            }
            Err(e) => {
                error!(event = "control_decode_error", bytes = payload.len(), %e, "Failed to decode control message");
                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::Error(format!("Control decode error: {e}")),
                );
            }
        },
        Ok(DecodedFrame::Chunk {
            file_id,
            seq,
            payload,
        }) => {
            let wire_bytes = msg.data.len() as u64;
            handle_chunk_frame(dc, file_id, seq, payload, wire_bytes, ctx).await;
        }
        Err(e) => {
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::Debug(format!("Frame decode error: {e}")),
            );
        }
    }
}

// â”€â”€ Chunk frame handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ Control message dispatch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async fn handle_control(
    dc: &Arc<RTCDataChannel>,
    msg: ControlMessage,
    ctx: &HandlerContext,
) -> Result<()> {
    let key = *ctx.shared_key.read().await;

    macro_rules! send_ctrl {
        ($msg:expr) => {
            WebRTCConnection::send_control_on(dc, &key, $msg, &ctx.wire_tx).await
        };
    }

    match msg {
        // â”€â”€ Chat â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ControlMessage::Text(data) => {
            notify_app(&ctx.app_tx, ConnectionMessage::TextReceived(data))
        }
        ControlMessage::DirectMessage(data) => {
            notify_app(&ctx.app_tx, ConnectionMessage::DmReceived(data))
        }
        ControlMessage::Typing => notify_app(&ctx.app_tx, ConnectionMessage::TypingReceived),
        ControlMessage::DisplayName(name) => {
            notify_app(&ctx.app_tx, ConnectionMessage::DisplayNameReceived(name))
        }
        ControlMessage::AuthenticatedText(env) => {
            handle_authenticated_message(&env, &key, ctx, true).await
        }
        ControlMessage::AuthenticatedDm(env) => {
            handle_authenticated_message(&env, &key, ctx, false).await
        }

        // â”€â”€ Liveness â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ControlMessage::AreYouAwake => {
            if let Err(e) = send_ctrl!(&ControlMessage::ImAwake) {
                warn!(event = "awake_reply_failed", %e, "Failed to send ImAwake reply");
            }
        }
        ControlMessage::ImAwake => notify_app(&ctx.app_tx, ConnectionMessage::AwakeReceived),

        // â”€â”€ File transfer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ControlMessage::Metadata {
            file_id,
            total_chunks,
            filename,
            filesize,
        } => {
            // Fast path: receiver pre-determined this file is identical to a local copy.
            // Send FileSkip immediately and emit FileSaved â€” no writer, no data transfer.
            if let Some((final_path, merkle_root)) =
                ctx.pre_skip_files.lock().await.remove(&file_id)
            {
                // Remove from accepted_destinations too (it was registered as a safety net).
                ctx.accepted_destinations.write().await.remove(&file_id);
                info!(
                    event = "metadata_pre_skip",
                    %file_id, %filename,
                    "Pre-skip: receiver already has identical file â€” sending FileSkip immediately"
                );
                ctx.skipped_files.lock().await.insert(file_id);
                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::FileSaved {
                        file_id,
                        filename,
                        path: final_path.to_string_lossy().into_owned(),
                        merkle_root,
                    },
                );
                send_ctrl!(&ControlMessage::FileSkip { file_id })?;
            } else {
                handle_metadata(file_id, total_chunks, filename, filesize, dc, &key, ctx).await?;
            }
        }

        ControlMessage::MerkleTree {
            file_id,
            chunk_hashes,
            merkle_root: _,
        } => {
            tracing::info!(
                event = "merkle_tree_received", %file_id,
                chunk_count = chunk_hashes.len(), "Received Merkle tree"
            );
            let mut map = ctx.recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                state
                    .writer
                    .set_verifier(ChunkHashVerifier::new(chunk_hashes));
                tracing::debug!(event = "verifier_set", %file_id, "Chunk hash verifier set");
            } else {
                warn!(event = "merkle_tree_before_metadata", %file_id, "MerkleTree before Metadata â€” ignoring");
            }
        }

        ControlMessage::ChunkHashBatch {
            file_id,
            start_index,
            chunk_hashes,
        } => {
            tracing::debug!(
                event = "chunk_hash_batch_received", %file_id,
                start_index, count = chunk_hashes.len(), "Received chunk hash batch"
            );
            let mut map = ctx.recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                state.writer.add_chunk_hashes(start_index, chunk_hashes);
            } else {
                warn!(event = "chunk_hash_batch_before_metadata", %file_id, "ChunkHashBatch before Metadata â€” ignoring");
            }
        }

        ControlMessage::Hash {
            file_id,
            merkle_root: sender_merkle_root,
        } => {
            let mut map = ctx.recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                if state.writer.received_chunks() == state.writer.total_chunks() {
                    // All chunks already in â€” finalize immediately in background.
                    let state = map.remove(&file_id).unwrap();
                    drop(map);
                    spawn_finalization(
                        dc,
                        file_id,
                        state,
                        sender_merkle_root,
                        key,
                        ctx.app_tx.clone(),
                        ctx.wire_tx.clone(),
                    );
                } else {
                    // Chunks still in-flight â€” buffer hash for the chunk handler.
                    tracing::debug!(
                        event = "hash_buffered", %file_id,
                        received = state.writer.received_chunks(),
                        total = state.writer.total_chunks(),
                        "Hash arrived before all chunks â€” buffering"
                    );
                    state.pending_hash = Some(PendingHash {
                        merkle_root: sender_merkle_root,
                    });
                }
            }
        }

        ControlMessage::HashResult { file_id, ok } => {
            if ok {
                info!(event = "file_send_verified", %file_id, "File send complete: hash verified");
            } else {
                error!(event = "file_integrity_failure", %file_id, "File send failed: hash mismatch");
            }
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::SendComplete {
                    file_id,
                    success: ok,
                },
            );
        }

        // â”€â”€ Remote access â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ControlMessage::LsRequest { path } => {
            tracing::info!("Remote ls request: {path}");
            if !ctx.remote_access_enabled {
                warn!(event = "remote_ls_denied", path = %path, "Remote ls denied: remote access not enabled");
                send_ctrl!(&ControlMessage::RemoteAccessDisabled)?;
            } else {
                let entries = read_dir_entries(&path).await;
                send_ctrl!(&ControlMessage::LsResponse { path, entries })?;
            }
        }
        ControlMessage::LsResponse { path, entries } => {
            notify_app(&ctx.app_tx, ConnectionMessage::LsResponse { path, entries })
        }

        ControlMessage::FetchRequest { path, is_folder } => {
            tracing::info!("Remote fetch request: {path} (folder: {is_folder})");
            if !ctx.remote_access_enabled {
                warn!(event = "remote_fetch_denied", path = %path, "Remote fetch denied: remote access not enabled");
                send_ctrl!(&ControlMessage::RemoteAccessDisabled)?;
            } else {
                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::RemoteFetchRequest { path, is_folder },
                );
            }
        }
        ControlMessage::RemoteAccessDisabled => {
            notify_app(&ctx.app_tx, ConnectionMessage::RemoteAccessDisabled)
        }

        // â”€â”€ Remote key listener â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // When we receive a RemoteKeyEvent, the sender has already decided to share
        // their keystrokes. We always accept and display them.
        ControlMessage::RemoteKeyEvent { key } => {
            tracing::info!("Remote key event received: {key}");
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::RemoteKeyEventReceived { key },
            );
        }
        ControlMessage::RemoteKeyListenerDisabled => {
            notify_app(&ctx.app_tx, ConnectionMessage::RemoteKeyListenerDisabled)
        }

        // â”€â”€ Transactions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ControlMessage::TransactionRequest {
            transaction_id,
            display_name,
            manifest,
            total_size,
        } => {
            // Register all files in this transaction with the file-to-transaction map
            let mut file_map = ctx.file_to_transaction.lock().await;
            for entry in &manifest.files {
                file_map.insert(entry.file_id, transaction_id);
            }
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::TransactionRequested {
                    transaction_id,
                    display_name,
                    manifest,
                    total_size,
                },
            );
        }

        ControlMessage::TransactionResponse {
            transaction_id,
            accepted,
            dest_path,
            reject_reason,
        } => {
            let msg = if accepted {
                ConnectionMessage::TransactionAccepted {
                    transaction_id,
                    dest_path,
                }
            } else {
                ConnectionMessage::TransactionRejected {
                    transaction_id,
                    reason: reject_reason,
                }
            };
            notify_app(&ctx.app_tx, msg);
        }

        ControlMessage::TransactionComplete { transaction_id } => notify_app(
            &ctx.app_tx,
            ConnectionMessage::TransactionCompleted { transaction_id },
        ),

        ControlMessage::TransactionCancel {
            transaction_id,
            reason,
        } => {
            // Mark locally so any in-flight send task for this transaction stops.
            ctx.cancelled_transactions
                .lock()
                .await
                .insert(transaction_id);
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::TransactionCancelled {
                    transaction_id,
                    reason,
                },
            );
        }

        ControlMessage::TransactionResumeRequest { resume_info } => notify_app(
            &ctx.app_tx,
            ConnectionMessage::TransactionResumeRequested { resume_info },
        ),

        ControlMessage::TransactionResumeResponse {
            transaction_id,
            accepted,
        } => {
            let msg = if accepted {
                ConnectionMessage::TransactionResumeAccepted { transaction_id }
            } else {
                ConnectionMessage::TransactionResumeRejected {
                    transaction_id,
                    reason: Some("Sender declined resume".to_string()),
                }
            };
            notify_app(&ctx.app_tx, msg);
        }
        ControlMessage::TransactionManifest {
            transaction_id,
            manifest,
            total_size,
        } => {
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::TransactionManifestReceived {
                    transaction_id,
                    manifest,
                    total_size,
                },
            );
        }
        ControlMessage::FilePullRequest {
            transaction_id,
            file_id,
        } => {
            info!(
                event = "file_pull_requested",
                %transaction_id,
                %file_id,
                "Receiver requested file transfer"
            );
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::FilePullRequested {
                    transaction_id,
                    file_id,
                },
            );
        }
        ControlMessage::FilePullBatchRequest {
            transaction_id,
            requests,
        } => {
            info!(
                event = "file_pull_batch_requested",
                %transaction_id,
                request_count = requests.len(),
                "Receiver requested batch file/chunk transfer"
            );
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::FilePullBatchRequested {
                    transaction_id,
                    requests,
                },
            );
        }

        ControlMessage::ChunkRetransmitRequest {
            file_id,
            chunk_indices,
        } => {
            info!(
                event = "chunk_retransmit_requested",
                %file_id, chunk_count = chunk_indices.len(), chunks = ?chunk_indices,
                "Peer requested retransmission of specific chunks"
            );
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::ChunkRetransmitRequested {
                    file_id,
                    chunk_indices,
                },
            );
        }

        ControlMessage::Ack { context } => {
            match context {
                AckContext::TransactionComplete { transaction_id } => {
                    info!(event = "transaction_complete_ack", %transaction_id, "Peer acknowledged transaction completion");
                    notify_app(
                        &ctx.app_tx,
                        ConnectionMessage::AckReceived {
                            context: AckContext::TransactionComplete { transaction_id },
                        },
                    );
                }
                AckContext::FileReceived { file_id } => {
                    info!(event = "file_received_confirmation", %file_id, "Receiver confirmed file saved");
                    notify_app(
                        &ctx.app_tx,
                        ConnectionMessage::AckReceived {
                            context: AckContext::FileReceived { file_id },
                        },
                    );
                    // Permit is now restored by DataAck (per 20 MB), not per file.
                }
            }
        }

        // â”€â”€ Flow control â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ControlMessage::DataAck { bytes_received } => {
            // Receiver confirmed receipt of another DATA_ACK_INTERVAL_BYTES;
            // restore one flow-control permit so the sender can continue.
            ctx.file_ack_semaphore.add_permits(1);
            debug!(
                event = "data_ack_received",
                bytes_received, "DataAck: released one flow-control permit"
            );
        }

        // â”€â”€ File verification (two-phase protocol) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ControlMessage::AllHashesSent { file_id } => {
            handle_all_hashes_sent(dc, file_id, ctx).await?;
        }

        ControlMessage::FileSkip { file_id } => {
            // The remote receiver already has this file â€” fire the sender's waiting channel.
            if let Some(tx) = ctx.file_decision_tx.lock().await.remove(&file_id) {
                let _ = tx.send(ReceiverDecision::Skip);
            }
        }

        ControlMessage::FileHaveChunks {
            file_id,
            have_bitmap,
        } => {
            // Receiver told us which chunks it already has â€” fire the sender's waiting channel.
            if let Some(tx) = ctx.file_decision_tx.lock().await.remove(&file_id) {
                let _ = tx.send(ReceiverDecision::HaveChunks(have_bitmap));
            }
        }

        // â”€â”€ Key rotation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ControlMessage::KeyRotation { ephemeral_pub } => {
            handle_key_rotation(dc, ephemeral_pub, &key, ctx).await?
        }
    }

    Ok(())
}
