//! Control channel: data channel message handler and control message dispatch.
//!
//! This module handles all incoming messages on the WebRTC data channels,
//! dispatching them to appropriate handlers based on frame type.

use super::data::{decode_frame, parse_control_message, DecodedFrame};
use super::{
    decompress_data, derive_chat_hmac_key, notify_app, sanitize_relative_path, ConnectionMessage,
    ControlMessage, PendingHash, ReceiveFileState, WebRTCConnection,
};
use crate::core::config::{MAX_PENDING_CHUNKS_PER_FILE, MAX_PENDING_FILE_IDS};
use crate::core::connection::crypto::SessionKeyManager;
use crate::core::pipeline::merkle::ChunkHashVerifier;
use crate::core::pipeline::receiver::StreamingFileWriter;
use crate::core::security::message_auth::{AuthenticatedMessage, MessageAuthenticator};
use aes_gcm::aead::KeyInit;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;

// ── Handler context ───────────────────────────────────────────────────────────

/// Shared context threaded through every data-channel message handler.
///
/// All fields are cheaply cloneable (`Arc`s or `Option<Sender<…>>`).
/// The struct is `Clone` so it can be captured by the `on_message` closure.
pub struct HandlerContext {
    pub recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    pub pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
    pub accepted_destinations: Arc<RwLock<HashMap<Uuid, PathBuf>>>,
    pub resume_bitmaps: Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    pub app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    pub shared_key: Arc<RwLock<[u8; 32]>>,
    pub remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    pub key_manager: Option<SessionKeyManager>,
    pub pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    pub chat_recv_counter: Arc<RwLock<u64>>,
    pub wire_tx: Arc<AtomicU64>,
    pub wire_rx: Arc<AtomicU64>,
    pub file_ack_semaphore: Arc<Semaphore>,
}

impl Clone for HandlerContext {
    fn clone(&self) -> Self {
        Self {
            recv_state: self.recv_state.clone(),
            pending_chunks: self.pending_chunks.clone(),
            accepted_destinations: self.accepted_destinations.clone(),
            resume_bitmaps: self.resume_bitmaps.clone(),
            app_tx: self.app_tx.clone(),
            shared_key: self.shared_key.clone(),
            remote_access: self.remote_access.clone(),
            key_manager: self.key_manager.clone(),
            pending_rotation: self.pending_rotation.clone(),
            chat_recv_counter: self.chat_recv_counter.clone(),
            wire_tx: self.wire_tx.clone(),
            wire_rx: self.wire_rx.clone(),
            file_ack_semaphore: self.file_ack_semaphore.clone(),
        }
    }
}

// ── Frame decryption ──────────────────────────────────────────────────────────

/// Decrypt and optionally decompress an incoming wire frame.
///
/// Wire format: `[compress_flag] ++ AES-256-GCM([maybe_compressed] plaintext)`
///
/// - `0x00` — plaintext was encrypted directly (no compression)
/// - `0x01` — plaintext was compressed then encrypted
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

// ── Handler attachment ────────────────────────────────────────────────────────

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

// ── Top-level message dispatch ────────────────────────────────────────────────

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

// ── Chunk frame handler ───────────────────────────────────────────────────────

async fn handle_chunk_frame(
    dc: &Arc<RTCDataChannel>,
    file_id: Uuid,
    seq: u32,
    chunk_data: &[u8],
    wire_bytes: u64,
    ctx: &HandlerContext,
) {
    let mut map = ctx.recv_state.write().await;

    let Some(state) = map.get_mut(&file_id) else {
        // Chunk arrived before its Metadata — buffer with DoS bounds.
        drop(map);
        buffer_pre_metadata_chunk(file_id, seq, chunk_data, wire_bytes, ctx).await;
        return;
    };

    match state.writer.write_chunk(seq, chunk_data).await {
        Ok(write_result) => {
            use crate::core::pipeline::receiver::{ChunkVerificationStatus, ChunkWriteResult};
            if let ChunkWriteResult::Written(ChunkVerificationStatus::HashMismatch) = write_result {
                warn!(event = "chunk_hash_mismatch", %file_id, seq,
                    "Chunk hash mismatch detected - will request retransmission");
            }

            if let Some(tx) = &ctx.app_tx {
                let _ = tx.send(ConnectionMessage::FileProgress {
                    file_id,
                    filename: state.writer.filename().to_string(),
                    received_chunks: state.writer.received_chunks(),
                    total_chunks: state.writer.total_chunks(),
                    wire_bytes,
                    chunk_bitmap_bytes: Some(state.writer.bitmap().to_bytes()),
                });
            }

            // If all chunks are in and the Hash message already arrived, finalize now.
            let all_received = state.writer.received_chunks() == state.writer.total_chunks();
            if all_received {
                if let Some(pending) = state.pending_hash.take() {
                    let state = map.remove(&file_id).unwrap();
                    drop(map);
                    spawn_finalization(dc, file_id, state, pending, ctx);
                }
            }
        }
        Err(e) => {
            error!("Chunk {} for {} write error: {}", seq, file_id, e);
        }
    }
}

/// Buffer a chunk that arrived before its Metadata message.
async fn buffer_pre_metadata_chunk(
    file_id: Uuid,
    seq: u32,
    chunk_data: &[u8],
    wire_bytes: u64,
    ctx: &HandlerContext,
) {
    let mut pending = ctx.pending_chunks.write().await;

    if !pending.contains_key(&file_id) && pending.len() >= MAX_PENDING_FILE_IDS {
        warn!("Dropping pre-metadata chunk for {file_id}: too many pending file IDs");
        return;
    }

    let entry = pending.entry(file_id).or_default();
    if entry.len() >= MAX_PENDING_CHUNKS_PER_FILE {
        warn!("Dropping pre-metadata chunk {seq} for {file_id}: pending buffer full");
        return;
    }

    tracing::debug!("Chunk {seq} for file {file_id} buffered — Metadata not yet received");
    entry.push((seq, chunk_data.to_vec(), wire_bytes));
}

/// Spawn `WebRTCConnection::finalize_file_receive` in the background.
fn spawn_finalization(
    dc: &Arc<RTCDataChannel>,
    file_id: Uuid,
    state: ReceiveFileState,
    pending: PendingHash,
    ctx: &HandlerContext,
) {
    let dc = dc.clone();
    let app_tx = ctx.app_tx.clone();
    let wire_tx = ctx.wire_tx.clone();
    let key = ctx.shared_key.clone();
    tokio::spawn(async move {
        let key = *key.read().await;
        if let Err(e) = WebRTCConnection::finalize_file_receive(
            &dc,
            file_id,
            state,
            pending.merkle_root,
            &key,
            &app_tx,
            &wire_tx,
        )
        .await
        {
            error!(event = "deferred_finalize_error", %file_id, %e, "Error in deferred file finalization");
            notify_app(
                &app_tx,
                ConnectionMessage::Error(format!("Deferred finalize error: {e}")),
            );
        }
    });
}

// ── Metadata handler ──────────────────────────────────────────────────────────

async fn handle_metadata(
    file_id: Uuid,
    total_chunks: u32,
    filename: String,
    filesize: u64,
    ctx: &HandlerContext,
) -> Result<()> {
    let safe_name = sanitize_relative_path(&filename);
    let dest_dir = ctx.accepted_destinations.write().await.remove(&file_id);
    let save_path = dest_dir
        .map(|d| d.join(&safe_name))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default().join(&safe_name));

    tracing::info!(
        "Receiving file '{filename}' ({filesize} bytes, {total_chunks} chunks) to: {}",
        save_path.display()
    );

    let resume_bitmap = ctx.resume_bitmaps.write().await.remove(&file_id);

    let writer = match resume_bitmap {
        Some(bm) => {
            StreamingFileWriter::resume(filename.clone(), filesize, total_chunks, save_path, bm)
                .await
                .map_err(|e| {
                    error!(event = "streaming_writer_resume_failed", %file_id, %filename, %e);
                    anyhow!("Failed to resume file writer: {e}")
                })?
        }
        None => StreamingFileWriter::new(filename.clone(), filesize, total_chunks, save_path)
            .await
            .map_err(|e| {
                error!(event = "streaming_writer_create_failed", %file_id, %filename, %e);
                anyhow!("Failed to create file writer: {e}")
            })?,
    };

    ctx.recv_state.write().await.insert(
        file_id,
        ReceiveFileState {
            writer,
            pending_hash: None,
        },
    );

    // Replay any chunks that arrived before this Metadata.
    let buffered = ctx
        .pending_chunks
        .write()
        .await
        .remove(&file_id)
        .unwrap_or_default();
    if !buffered.is_empty() {
        tracing::debug!(
            "Processing {} buffered chunks for file {file_id}",
            buffered.len()
        );
        let mut map = ctx.recv_state.write().await;
        if let Some(state) = map.get_mut(&file_id) {
            for (seq, chunk_data, wb) in &buffered {
                match state.writer.write_chunk(*seq, chunk_data).await {
                    Ok(_) => {
                        if let Some(tx) = &ctx.app_tx {
                            let _ = tx.send(ConnectionMessage::FileProgress {
                                file_id,
                                filename: state.writer.filename().to_string(),
                                received_chunks: state.writer.received_chunks(),
                                total_chunks: state.writer.total_chunks(),
                                wire_bytes: *wb,
                                chunk_bitmap_bytes: Some(state.writer.bitmap().to_bytes()),
                            });
                        }
                    }
                    Err(e) => error!("Buffered chunk {seq} for {file_id} write error: {e}"),
                }
            }
        }
    }

    if let Some(tx) = &ctx.app_tx {
        let _ = tx.send(ConnectionMessage::Debug(format!(
            "Receiving: {filename} ({filesize} bytes, {total_chunks} chunks)"
        )));
    }

    Ok(())
}

// ── Authenticated chat helper ─────────────────────────────────────────────────

async fn handle_authenticated_message(
    envelope: &[u8],
    key: &[u8; 32],
    ctx: &HandlerContext,
    is_room_chat: bool,
) {
    let hmac_key = derive_chat_hmac_key(key);

    let auth_msg = match serde_json::from_slice::<AuthenticatedMessage>(envelope) {
        Ok(m) => m,
        Err(e) => {
            warn!(
                event = if is_room_chat { "chat_auth_decode_error" } else { "dm_auth_decode_error" },
                %e, "Failed to decode authenticated {}", if is_room_chat { "room chat" } else { "DM" }
            );
            return;
        }
    };

    if !MessageAuthenticator::verify(&hmac_key, &auth_msg) {
        warn!(
            event = if is_room_chat {
                "chat_hmac_invalid"
            } else {
                "dm_hmac_invalid"
            },
            "Rejected {}: HMAC verification failed",
            if is_room_chat { "room chat" } else { "DM" }
        );
        return;
    }

    let mut counter = ctx.chat_recv_counter.write().await;
    if auth_msg.counter <= *counter {
        warn!(
            event = if is_room_chat {
                "chat_replay_detected"
            } else {
                "dm_replay_detected"
            },
            counter = auth_msg.counter,
            last_seen = *counter,
            "Rejected {}: replay detected",
            if is_room_chat { "room chat" } else { "DM" }
        );
        return;
    }
    *counter = auth_msg.counter;
    drop(counter);

    let msg = if is_room_chat {
        ConnectionMessage::TextReceived(auth_msg.payload)
    } else {
        ConnectionMessage::DmReceived(auth_msg.payload)
    };
    notify_app(&ctx.app_tx, msg);
}

// ── Control message dispatch ──────────────────────────────────────────────────

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
        // ── Chat ──────────────────────────────────────────────────────────
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

        // ── Liveness ──────────────────────────────────────────────────────
        ControlMessage::AreYouAwake => {
            if let Err(e) = send_ctrl!(&ControlMessage::ImAwake) {
                warn!(event = "awake_reply_failed", %e, "Failed to send ImAwake reply");
            }
        }
        ControlMessage::ImAwake => notify_app(&ctx.app_tx, ConnectionMessage::AwakeReceived),

        // ── File transfer ─────────────────────────────────────────────────
        ControlMessage::Metadata {
            file_id,
            total_chunks,
            filename,
            filesize,
        } => handle_metadata(file_id, total_chunks, filename, filesize, ctx).await?,

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
                warn!(event = "merkle_tree_before_metadata", %file_id, "MerkleTree before Metadata — ignoring");
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
                warn!(event = "chunk_hash_batch_before_metadata", %file_id, "ChunkHashBatch before Metadata — ignoring");
            }
        }

        ControlMessage::Hash {
            file_id,
            merkle_root: sender_merkle_root,
        } => {
            let mut map = ctx.recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                if state.writer.received_chunks() == state.writer.total_chunks() {
                    // All chunks already in — finalize immediately in background.
                    let state = map.remove(&file_id).unwrap();
                    drop(map);
                    let dc = dc.clone();
                    let app_tx = ctx.app_tx.clone();
                    let wire_tx = ctx.wire_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = WebRTCConnection::finalize_file_receive(
                            &dc,
                            file_id,
                            state,
                            sender_merkle_root,
                            &key,
                            &app_tx,
                            &wire_tx,
                        )
                        .await
                        {
                            error!(event = "finalize_error", %file_id, %e, "Error in file finalization");
                            notify_app(
                                &app_tx,
                                ConnectionMessage::Error(format!("Finalize error: {e}")),
                            );
                        }
                    });
                } else {
                    // Chunks still in-flight — buffer hash for the chunk handler.
                    tracing::debug!(
                        event = "hash_buffered", %file_id,
                        received = state.writer.received_chunks(),
                        total = state.writer.total_chunks(),
                        "Hash arrived before all chunks — buffering"
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

        // ── Remote access ─────────────────────────────────────────────────
        ControlMessage::LsRequest { path } => {
            tracing::info!("Remote ls request: {path}");
            if !*ctx.remote_access.borrow() {
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
            if !*ctx.remote_access.borrow() {
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

        // ── Transactions ──────────────────────────────────────────────────
        ControlMessage::TransactionRequest {
            transaction_id,
            display_name,
            manifest,
            total_size,
        } => notify_app(
            &ctx.app_tx,
            ConnectionMessage::TransactionRequested {
                transaction_id,
                display_name,
                manifest,
                total_size,
            },
        ),

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
        } => notify_app(
            &ctx.app_tx,
            ConnectionMessage::TransactionCancelled {
                transaction_id,
                reason,
            },
        ),

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

        ControlMessage::TransactionCompleteAck { transaction_id } => {
            info!(event = "transaction_complete_ack", %transaction_id, "Peer acknowledged transaction completion");
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::TransactionCompleteAcked { transaction_id },
            );
        }

        // ── File acknowledgement ──────────────────────────────────────────
        ControlMessage::FileReceived { file_id } => {
            info!(event = "file_received_confirmation", %file_id, "Receiver confirmed file saved");
            notify_app(&ctx.app_tx, ConnectionMessage::FileReceivedAck { file_id });
            ctx.file_ack_semaphore.add_permits(1);
        }

        // ── Key rotation ──────────────────────────────────────────────────
        ControlMessage::KeyRotation { ephemeral_pub } => {
            handle_key_rotation(dc, ephemeral_pub, &key, ctx).await?
        }
    }

    Ok(())
}

// ── Key-rotation helper ───────────────────────────────────────────────────────

async fn handle_key_rotation(
    dc: &Arc<RTCDataChannel>,
    ephemeral_pub: Vec<u8>,
    current_key: &[u8; 32],
    ctx: &HandlerContext,
) -> Result<()> {
    use crate::core::connection::crypto;

    let peer_pub: [u8; 32] = ephemeral_pub
        .try_into()
        .map_err(|_| anyhow!("Invalid ephemeral public key length for rotation"))?;

    let Some(ref km) = ctx.key_manager else {
        warn!(
            event = "key_rotation_no_manager",
            "Received KeyRotation but no SessionKeyManager is available"
        );
        return Ok(());
    };

    let our_eph = ctx.pending_rotation.write().await.take();

    let new_key = if let Some(local_eph) = our_eph {
        // We initiated the rotation.
        let k = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
        info!(event = "key_rotated_initiator", new_key_prefix = ?&k[..4], "Session key rotated (initiator)");
        k
    } else {
        // Peer initiated — generate our ephemeral, reply, then derive new key.
        let local_eph = crypto::prepare_rotation();
        WebRTCConnection::send_control_on(
            dc,
            current_key,
            &ControlMessage::KeyRotation {
                ephemeral_pub: local_eph.public.to_vec(),
            },
            &ctx.wire_tx,
        )
        .await?;
        let k = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
        info!(event = "key_rotated_responder", new_key_prefix = ?&k[..4], "Session key rotated (responder)");
        k
    };

    let _ = new_key; // key is committed inside complete_rotation via the key manager
    notify_app(
        &ctx.app_tx,
        ConnectionMessage::Debug("Session key rotated successfully".into()),
    );
    Ok(())
}

// ── Remote-access helper ──────────────────────────────────────────────────────

/// Read a directory and collect its entries, ignoring entries that fail to stat.
async fn read_dir_entries(path: &str) -> Vec<crate::workers::app::RemoteEntry> {
    let mut entries = Vec::new();
    if let Ok(mut read_dir) = fs::read_dir(path).await {
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            if let Ok(meta) = entry.metadata().await {
                entries.push(crate::workers::app::RemoteEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    is_dir: meta.is_dir(),
                    size: meta.len(),
                });
            }
        }
    }
    entries
}
