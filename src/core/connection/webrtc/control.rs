//! Control channel: data channel message handler and control message dispatch.
//!
//! This module handles all incoming messages on the WebRTC data channels,
//! dispatching them to appropriate handlers based on frame type.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aes_gcm::aead::KeyInit;
use anyhow::{anyhow, Result};
use tokio::fs;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;

use crate::core::config::{MAX_PENDING_CHUNKS_PER_FILE, MAX_PENDING_FILE_IDS};
use crate::core::connection::crypto::SessionKeyManager;
use crate::core::pipeline::merkle::ChunkHashVerifier;
use crate::core::pipeline::receiver::StreamingFileWriter;
use crate::core::security::message_auth::{AuthenticatedMessage, MessageAuthenticator};

use super::data::{decode_frame, parse_control_message, DecodedFrame};
use super::{
    decompress_data, derive_chat_hmac_key, notify_app, sanitize_relative_path, ConnectionMessage,
    ControlMessage, PendingHash, ReceiveFileState, WebRTCConnection,
};

// ── Handler Context ───────────────────────────────────────────────────────

/// Shared context for data channel message handlers.
/// Reduces parameter count and centralizes state access.
pub(crate) struct HandlerContext {
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

// ── Frame Decryption ─────────────────────────────────────────────────────────

/// Decrypt and optionally decompress an incoming frame.
///
/// Wire format: `[compress_flag] + [encrypted([maybe_compressed_plaintext])]`
///
/// - `compress_flag = 0x00`: Just encrypted plaintext
/// - `compress_flag = 0x01`: Encrypted compressed plaintext
fn decrypt_frame(
    cipher: &aes_gcm::Aes256Gcm,
    data: &[u8],
    app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }

    let compress_flag = data[0];
    let encrypted_payload = &data[1..];

    // Decrypt the payload
    let decrypted = super::decrypt_with(cipher, encrypted_payload).map_err(|e| {
        error!(
            event = "decrypt_failure",
            bytes = encrypted_payload.len(),
            error = %e,
            "Decryption failed on incoming frame"
        );
        notify_app(app_tx, ConnectionMessage::Error(format!("Decrypt error: {}", e)));
        e
    }).ok()?;

    // Decompress if needed
    if compress_flag == 0x01 {
        decompress_data(&decrypted).map_err(|e| {
            error!(
                event = "decompress_failure",
                bytes = decrypted.len(),
                error = %e,
                "Decompression failed on incoming frame"
            );
            notify_app(app_tx, ConnectionMessage::Error(format!("Decompress error: {}", e)));
            e
        }).ok()
    } else {
        Some(decrypted)
    }
}

// ── Data Channel Handler Attachment ──────────────────────────────────────────

/// Attach message handlers to a data channel.
///
/// Sets up handlers for:
/// - `on_message`: Process incoming frames (control and chunk)
/// - `on_close`: Log when the channel closes
/// - `on_error`: Log transport errors
pub(crate) async fn attach_dc_handlers(dc: &Arc<RTCDataChannel>, ctx: HandlerContext) {
    // Register diagnostic handlers for close/error events
    let label = dc.label().to_string();
    dc.on_close(Box::new(move || {
        let label = label.clone();
        Box::pin(async move {
            tracing::warn!(
                event = "dc_closed",
                channel = %label,
                "DataChannel closed by transport"
            );
        })
    }));

    let label = dc.label().to_string();
    dc.on_error(Box::new(move |err| {
        let label = label.clone();
        Box::pin(async move {
            tracing::error!(
                event = "dc_error",
                channel = %label,
                error = %err,
                "DataChannel transport error"
            );
        })
    }));

    // Main message handler
    let dc_clone = dc.clone();
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let ctx = ctx.clone();
        let dc = dc_clone.clone();

        Box::pin(async move {
            handle_incoming_message(&dc, msg, &ctx).await;
        })
    }));
}

/// Handle an incoming data channel message.
async fn handle_incoming_message(
    dc: &Arc<RTCDataChannel>,
    msg: DataChannelMessage,
    ctx: &HandlerContext,
) {
    // Track wire bytes
    let wire_bytes = msg.data.len() as u64;
    ctx.wire_rx.fetch_add(wire_bytes, Ordering::Relaxed);

    if msg.data.is_empty() {
        return;
    }

    // Build cipher once per message (optimization: ~1µs saved per message)
    let key = *ctx.shared_key.read().await;
    let cipher = match aes_gcm::Aes256Gcm::new_from_slice(&key) {
        Ok(c) => c,
        Err(e) => {
            error!(event = "cipher_init_failure", error = %e, "Failed to init AES cipher");
            return;
        }
    };

    // Decrypt the frame
    let decrypted = match decrypt_frame(&cipher, &msg.data, &ctx.app_tx) {
        Some(d) => d,
        None => return,
    };

    // Decode the frame type and dispatch
    match decode_frame(&decrypted) {
        Ok(DecodedFrame::Control(payload)) => {
            match parse_control_message(payload) {
                Ok(ctrl) => {
                    if let Err(e) = handle_control(dc, ctrl, ctx).await {
                        error!(event = "control_handle_error", error = %e, "Error handling control message");
                        notify_app(&ctx.app_tx, ConnectionMessage::Error(format!("Control error: {}", e)));
                    }
                }
                Err(e) => {
                    error!(event = "control_decode_error", bytes = payload.len(), error = %e, "Failed to decode control message");
                    notify_app(&ctx.app_tx, ConnectionMessage::Error(format!("Control decode error: {}", e)));
                }
            }
        }
        Ok(DecodedFrame::Chunk { file_id, seq, payload }) => {
            handle_chunk_frame(dc, file_id, seq, payload, wire_bytes, ctx).await;
        }
        Err(e) => {
            notify_app(&ctx.app_tx, ConnectionMessage::Debug(format!("Frame decode error: {}", e)));
        }
    }
}

/// Handle an incoming chunk frame.
async fn handle_chunk_frame(
    dc: &Arc<RTCDataChannel>,
    file_id: Uuid,
    seq: u32,
    chunk_data: &[u8],
    wire_bytes: u64,
    ctx: &HandlerContext,
) {
    let mut map = ctx.recv_state.write().await;

    if let Some(state) = map.get_mut(&file_id) {
        match state.writer.write_chunk(seq, chunk_data).await {
            Ok(write_result) => {
                use crate::core::pipeline::receiver::{ChunkVerificationStatus, ChunkWriteResult};

                // Log verification failures (hot path — no per-chunk debug logs)
                if let ChunkWriteResult::Written(ChunkVerificationStatus::HashMismatch) = write_result {
                    warn!(
                        event = "chunk_hash_mismatch",
                        file_id = %file_id,
                        seq = seq,
                        "Chunk hash mismatch detected - will request retransmission"
                    );
                }

                // Send progress update
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

                // Check if this was the last chunk AND the Hash message already arrived
                if state.writer.received_chunks() == state.writer.total_chunks() {
                    if let Some(pending) = state.pending_hash.take() {
                        let state = map.remove(&file_id).unwrap();
                        drop(map);
                        let key = *ctx.shared_key.read().await;

                        // Spawn finalization in background
                        let dc = dc.clone();
                        let app_tx = ctx.app_tx.clone();
                        let wire_tx = ctx.wire_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = WebRTCConnection::finalize_file_receive(
                                &dc, file_id, state, pending.sha3_256, pending.merkle_root,
                                &key, &app_tx, &wire_tx,
                            ).await {
                                error!(
                                    event = "deferred_finalize_error",
                                    file_id = %file_id,
                                    error = %e,
                                    "Error in deferred file finalization"
                                );
                                notify_app(&app_tx, ConnectionMessage::Error(format!(
                                    "Deferred finalize error: {}", e
                                )));
                            }
                        });
                        return;
                    }
                }
            }
            Err(e) => {
                error!("Chunk {} for {} write error: {}", seq, file_id, e);
            }
        }
    } else {
        // Chunk arrived before Metadata — buffer with DoS bounds
        drop(map);
        buffer_pre_metadata_chunk(file_id, seq, chunk_data, wire_bytes, ctx).await;
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

    // Limit pending file IDs (DoS protection)
    if !pending.contains_key(&file_id) && pending.len() >= MAX_PENDING_FILE_IDS {
        warn!(
            "Dropping pre-metadata chunk for {}: too many pending file IDs",
            file_id
        );
        return;
    }

    let entry = pending.entry(file_id).or_default();

    // Limit chunks per file (DoS protection)
    if entry.len() >= MAX_PENDING_CHUNKS_PER_FILE {
        warn!(
            "Dropping pre-metadata chunk {} for {}: pending buffer full",
            seq, file_id
        );
        return;
    }

    tracing::debug!(
        "Chunk {} for file {} buffered — Metadata not yet received",
        seq, file_id
    );
    entry.push((seq, chunk_data.to_vec(), wire_bytes));
}

// ── Helper Functions ──────────────────────────────────────────────────────────

/// Handle an authenticated message (room chat or DM).
///
/// Verifies HMAC and checks for replay attacks before forwarding to the app.
async fn handle_authenticated_message(
    envelope: &[u8],
    key: &[u8; 32],
    ctx: &HandlerContext,
    is_room_chat: bool,
) {
    let hmac_key = derive_chat_hmac_key(key);
    let msg_type = if is_room_chat { "room chat" } else { "DM" };

    match serde_json::from_slice::<AuthenticatedMessage>(envelope) {
        Ok(auth_msg) => {
            if !MessageAuthenticator::verify(&hmac_key, &auth_msg) {
                warn!(
                    event = if is_room_chat { "chat_hmac_invalid" } else { "dm_hmac_invalid" },
                    "Rejected {}: HMAC verification failed", msg_type
                );
                return;
            }

            let mut counter = ctx.chat_recv_counter.write().await;
            if auth_msg.counter <= *counter {
                warn!(
                    event = if is_room_chat { "chat_replay_detected" } else { "dm_replay_detected" },
                    counter = auth_msg.counter,
                    last_seen = *counter,
                    "Rejected {}: replay detected", msg_type
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
        Err(e) => {
            warn!(
                event = if is_room_chat { "chat_auth_decode_error" } else { "dm_auth_decode_error" },
                error = %e,
                "Failed to decode authenticated {}", msg_type
            );
        }
    }
}

/// Handle incoming file metadata message.
///
/// Creates or resumes a file writer and processes any buffered chunks.
async fn handle_metadata(
    file_id: Uuid,
    total_chunks: u32,
    filename: String,
    filesize: u64,
    ctx: &HandlerContext,
) -> Result<()> {
    // Compute save path
    let dest_dir = ctx.accepted_destinations.write().await.remove(&file_id);
    let safe_name = sanitize_relative_path(&filename);
    let save_path = dest_dir
        .as_ref()
        .map(|d| d.join(&safe_name))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default().join(&safe_name));

    tracing::info!(
        "Receiving file '{}' ({} bytes, {} chunks) to: {}",
        filename, filesize, total_chunks, save_path.display()
    );

    // Check for resume bitmap
    let resume_bitmap = ctx.resume_bitmaps.write().await.remove(&file_id);

    let writer = match resume_bitmap {
        Some(bitmap) => {
            StreamingFileWriter::resume(filename.clone(), filesize, total_chunks, save_path, bitmap)
                .await
                .map_err(|e| {
                    error!(
                        event = "streaming_writer_resume_failed",
                        file_id = %file_id,
                        filename = %filename,
                        error = %e,
                        "Failed to resume streaming file writer"
                    );
                    anyhow!("Failed to resume file writer: {}", e)
                })?
        }
        None => {
            StreamingFileWriter::new(filename.clone(), filesize, total_chunks, save_path)
                .await
                .map_err(|e| {
                    error!(
                        event = "streaming_writer_create_failed",
                        file_id = %file_id,
                        filename = %filename,
                        error = %e,
                        "Failed to create streaming file writer"
                    );
                    anyhow!("Failed to create file writer: {}", e)
                })?
        }
    };

    let state = ReceiveFileState {
        writer,
        pending_hash: None,
    };
    ctx.recv_state.write().await.insert(file_id, state);

    // Process any chunks that arrived before this Metadata frame
    let buffered = ctx
        .pending_chunks
        .write()
        .await
        .remove(&file_id)
        .unwrap_or_default();

    if !buffered.is_empty() {
        tracing::debug!(
            "Processing {} buffered chunks for file {}",
            buffered.len(),
            file_id
        );
        let mut map = ctx.recv_state.write().await;
        if let Some(state) = map.get_mut(&file_id) {
            for (seq, chunk_data, wire_bytes) in &buffered {
                if let Err(e) = state.writer.write_chunk(*seq, chunk_data).await {
                    error!("Buffered chunk {} for {} write error: {}", seq, file_id, e);
                    continue;
                }
                if let Some(tx) = &ctx.app_tx {
                    let _ = tx.send(ConnectionMessage::FileProgress {
                        file_id,
                        filename: state.writer.filename().to_string(),
                        received_chunks: state.writer.received_chunks(),
                        total_chunks: state.writer.total_chunks(),
                        wire_bytes: *wire_bytes,
                        chunk_bitmap_bytes: Some(state.writer.bitmap().to_bytes()),
                    });
                }
            }
        }
    }

    if let Some(tx) = &ctx.app_tx {
        let _ = tx.send(ConnectionMessage::Debug(format!(
            "Receiving: {} ({} bytes, {} chunks)",
            filename, filesize, total_chunks
        )));
    }

    Ok(())
}

// ── Control Message Handler ──────────────────────────────────────────────────

async fn handle_control(dc: &Arc<RTCDataChannel>, msg: ControlMessage, ctx: &HandlerContext) -> Result<()> {
    let key = *ctx.shared_key.read().await;
    match msg {
        // ── Chat Messages ─────────────────────────────────────────────────────
        ControlMessage::Text(data) => {
            notify_app(&ctx.app_tx, ConnectionMessage::TextReceived(data));
        }
        ControlMessage::DirectMessage(data) => {
            notify_app(&ctx.app_tx, ConnectionMessage::DmReceived(data));
        }
        ControlMessage::Typing => {
            notify_app(&ctx.app_tx, ConnectionMessage::TypingReceived);
        }
        ControlMessage::DisplayName(name) => {
            notify_app(&ctx.app_tx, ConnectionMessage::DisplayNameReceived(name));
        }
        ControlMessage::AuthenticatedText(envelope) => {
            handle_authenticated_message(&envelope, &key, ctx, true).await;
        }
        ControlMessage::AuthenticatedDm(envelope) => {
            handle_authenticated_message(&envelope, &key, ctx, false).await;
        }

        // ── Liveness ───────────────────────────────────────────────────────────
        ControlMessage::AreYouAwake => {
            let key = *ctx.shared_key.read().await;
            if let Err(e) =
                WebRTCConnection::send_control_on(dc, &key, &ControlMessage::ImAwake, &ctx.wire_tx)
                    .await
            {
                warn!(event = "awake_reply_failed", error = %e, "Failed to send ImAwake reply");
            }
        }
        ControlMessage::ImAwake => {
            notify_app(&ctx.app_tx, ConnectionMessage::AwakeReceived);
        }

        // ── File Transfer ──────────────────────────────────────────────────────
        ControlMessage::Metadata {
            file_id,
            total_chunks,
            filename,
            filesize,
        } => {
            handle_metadata(file_id, total_chunks, filename, filesize, ctx).await?;
        }
        ControlMessage::MerkleTree {
            file_id,
            chunk_hashes,
            merkle_root: _,
        } => {
            tracing::info!(
                event = "merkle_tree_received",
                file_id = %file_id,
                chunk_count = chunk_hashes.len(),
                "Received Merkle tree for incremental verification"
            );

            let mut map = ctx.recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                let verifier = ChunkHashVerifier::new(chunk_hashes);
                state.writer.set_verifier(verifier);
                tracing::debug!(
                    event = "verifier_set",
                    file_id = %file_id,
                    "Chunk hash verifier set for incremental verification"
                );
            } else {
                warn!(
                    event = "merkle_tree_before_metadata",
                    file_id = %file_id,
                    "Received MerkleTree before Metadata - ignoring"
                );
            }
        }
        ControlMessage::ChunkHashBatch {
            file_id,
            start_index,
            chunk_hashes,
        } => {
            tracing::debug!(
                event = "chunk_hash_batch_received",
                file_id = %file_id,
                start_index = start_index,
                count = chunk_hashes.len(),
                "Received incremental chunk hash batch"
            );

            let mut map = ctx.recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                state.writer.add_chunk_hashes(start_index, chunk_hashes);
            } else {
                warn!(
                    event = "chunk_hash_batch_before_metadata",
                    file_id = %file_id,
                    "Received ChunkHashBatch before Metadata - ignoring"
                );
            }
        }
        ControlMessage::Hash {
            file_id,
            sha3_256,
            merkle_root: sender_merkle_root,
        } => {
            let mut map = ctx.recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                if state.writer.received_chunks() == state.writer.total_chunks() {
                    // All chunks already received — spawn finalization in
                    // background so the control handler returns immediately
                    // and can process the next file's metadata/hashes.
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
                            sha3_256,
                            sender_merkle_root,
                            &key,
                            &app_tx,
                            &wire_tx,
                        )
                        .await
                        {
                            error!(
                                event = "finalize_error",
                                file_id = %file_id,
                                error = %e,
                                "Error in file finalization"
                            );
                            notify_app(
                                &app_tx,
                                ConnectionMessage::Error(format!(
                                    "Finalize error: {}",
                                    e
                                )),
                            );
                        }
                    });
                } else {
                    // Chunks still in-flight on the data channel.
                    // Buffer the hash; the chunk handler will finalize
                    // when the last chunk arrives.
                    tracing::debug!(
                        event = "hash_buffered",
                        file_id = %file_id,
                        received = state.writer.received_chunks(),
                        total = state.writer.total_chunks(),
                        "Hash arrived before all chunks — buffering"
                    );
                    state.pending_hash = Some(PendingHash {
                        sha3_256,
                        merkle_root: sender_merkle_root,
                    });
                }
            }
        }
        ControlMessage::HashResult { file_id, ok } => {
            if ok {
                info!(event = "file_send_verified", file_id = %file_id, "File send complete: hash verified");
            } else {
                error!(event = "file_integrity_failure", file_id = %file_id, "File send failed: hash mismatch");
            }
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::SendComplete {
                    file_id,
                    success: ok,
                },
            );
        }
        ControlMessage::LsRequest { path } => {
            tracing::info!("Remote ls request: {}", path);
            if !*ctx.remote_access.borrow() {
                WebRTCConnection::send_control_on(
                    dc,
                    &key,
                    &ControlMessage::RemoteAccessDisabled,
                    &ctx.wire_tx,
                )
                .await?;
            } else {
                let mut entries = Vec::new();
                if let Ok(mut read_dir) = fs::read_dir(&path).await {
                    while let Ok(Some(entry)) = read_dir.next_entry().await {
                        if let Ok(meta) = entry.metadata().await {
                            entries.push(crate::workers::app::RemoteEntry {
                                name: entry.file_name().to_string_lossy().to_string(),
                                is_dir: meta.is_dir(),
                                size: meta.len(),
                            });
                        }
                    }
                }
                WebRTCConnection::send_control_on(
                    dc,
                    &key,
                    &ControlMessage::LsResponse { path, entries },
                    &ctx.wire_tx,
                )
                .await?;
            }
        }
        ControlMessage::LsResponse { path, entries } => {
            notify_app(&ctx.app_tx, ConnectionMessage::LsResponse { path, entries });
        }
        ControlMessage::FetchRequest { path, is_folder } => {
            tracing::info!("Remote fetch request: {} (folder: {})", path, is_folder);
            if !*ctx.remote_access.borrow() {
                WebRTCConnection::send_control_on(
                    dc,
                    &key,
                    &ControlMessage::RemoteAccessDisabled,
                    &ctx.wire_tx,
                )
                .await?;
            } else {
                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::RemoteFetchRequest { path, is_folder },
                );
            }
        }
        ControlMessage::RemoteAccessDisabled => {
            notify_app(&ctx.app_tx, ConnectionMessage::RemoteAccessDisabled);
        }
        // ── Transaction-level protocol ───────────────────────────────────
        ControlMessage::TransactionRequest {
            transaction_id,
            display_name,
            manifest,
            total_size,
        } => {
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
            if accepted {
                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::TransactionAccepted {
                        transaction_id,
                        dest_path,
                    },
                );
            } else {
                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::TransactionRejected {
                        transaction_id,
                        reason: reject_reason,
                    },
                );
            }
        }
        ControlMessage::TransactionComplete { transaction_id } => {
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::TransactionCompleted { transaction_id },
            );
        }
        ControlMessage::TransactionCancel {
            transaction_id,
            reason,
        } => {
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::TransactionCancelled {
                    transaction_id,
                    reason,
                },
            );
        }
        ControlMessage::TransactionResumeRequest { resume_info } => {
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::TransactionResumeRequested { resume_info },
            );
        }
        ControlMessage::TransactionResumeResponse {
            transaction_id,
            accepted,
        } => {
            if accepted {
                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::TransactionResumeAccepted { transaction_id },
                );
            } else {
                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::TransactionResumeRejected {
                        transaction_id,
                        reason: Some("Sender declined resume".to_string()),
                    },
                );
            }
        }
        ControlMessage::ChunkRetransmitRequest {
            file_id,
            chunk_indices,
        } => {
            info!(
                event = "chunk_retransmit_requested",
                file_id = %file_id,
                chunk_count = chunk_indices.len(),
                chunks = ?chunk_indices,
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
            info!(
                event = "transaction_complete_ack",
                transaction_id = %transaction_id,
                "Peer acknowledged transaction completion"
            );
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::TransactionCompleteAcked { transaction_id },
            );
        }
        ControlMessage::KeyRotation { ephemeral_pub } => {
            use crate::core::connection::crypto;

            let peer_pub: [u8; 32] = ephemeral_pub
                .try_into()
                .map_err(|_| anyhow!("Invalid ephemeral public key length for rotation"))?;

            if let Some(ref km) = ctx.key_manager {
                // Check if we have a pending rotation (we initiated)
                let our_eph = ctx.pending_rotation.write().await.take();

                if let Some(local_eph) = our_eph {
                    // We initiated the rotation — complete it with peer's response
                    let new_key = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
                    info!(event = "key_rotated_initiator", new_key_prefix = ?&new_key[..4], "Session key rotated (initiator side)");
                } else {
                    // Peer initiated — generate our own ephemeral, respond, then rotate
                    let local_eph = crypto::prepare_rotation();
                    let response_key = *ctx.shared_key.read().await;
                    WebRTCConnection::send_control_on(
                        dc,
                        &response_key,
                        &ControlMessage::KeyRotation {
                            ephemeral_pub: local_eph.public.to_vec(),
                        },
                        &ctx.wire_tx,
                    )
                    .await?;
                    let new_key = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
                    info!(event = "key_rotated_responder", new_key_prefix = ?&new_key[..4], "Session key rotated (responder side)");
                }

                notify_app(
                    &ctx.app_tx,
                    ConnectionMessage::Debug("Session key rotated successfully".into()),
                );
            } else {
                warn!(
                    event = "key_rotation_no_manager",
                    "Received KeyRotation but no SessionKeyManager is available"
                );
            }
        }
        ControlMessage::FileReceived { file_id } => {
            info!(
                event = "file_received_confirmation",
                file_id = %file_id,
                "Receiver confirmed file received and saved"
            );
            notify_app(
                &ctx.app_tx,
                ConnectionMessage::FileReceivedAck { file_id },
            );
            // Release one permit so the sender can proceed with the next file
            ctx.file_ack_semaphore.add_permits(1);
        }
    }
    Ok(())
}
