//! Control channel: data channel message handler and control message dispatch.

use crate::core::config::{MAX_PENDING_CHUNKS_PER_FILE, MAX_PENDING_FILE_IDS};
use crate::core::connection::crypto::SessionKeyManager;
use crate::core::pipeline::merkle::ChunkHashVerifier;
use crate::core::pipeline::receiver::StreamingFileWriter;
use crate::core::security::message_auth::{AuthenticatedMessage, MessageAuthenticator};
use aes_gcm::aead::KeyInit;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;

use super::{
    decompress_data, derive_chat_hmac_key, notify_app, sanitize_relative_path, ConnectionMessage,
    ControlMessage, PendingHash, ReceiveFileState, WebRTCConnection, FRAME_CHUNK,
    FRAME_CONTROL,
};

// ── Data channel message handler ─────────────────────────────────────────

pub(crate) async fn attach_dc_handlers(
    dc: &Arc<RTCDataChannel>,
    recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
    accepted_destinations: Arc<RwLock<HashMap<Uuid, std::path::PathBuf>>>,
    resume_bitmaps: Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    shared_key: Arc<RwLock<[u8; 32]>>,
    remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    key_manager: Option<SessionKeyManager>,
    pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    chat_recv_counter: Arc<RwLock<u64>>,
    wire_tx: Arc<AtomicU64>,
    wire_rx: Arc<AtomicU64>,
    file_ack_semaphore: Arc<tokio::sync::Semaphore>,
) {
    // Register diagnostic handlers for close/error events.
    // These fire when the underlying SCTP stream closes or encounters an
    // error, giving visibility into why data channels transition to Closed.
    {
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
    }
    {
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
    }

    let dc_clone = dc.clone();
    let rs = recv_state;
    let pc = pending_chunks;
    let ad = accepted_destinations;
    let rb = resume_bitmaps;
    let atx = app_tx;
    let sk = shared_key;
    let km = key_manager;
    let pr = pending_rotation;
    let ra = remote_access;
    let crc = chat_recv_counter;
    let wrx = wire_rx;
    let wtx_clone = wire_tx;
    let fas = file_ack_semaphore;

    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let rs = rs.clone();
        let pc = pc.clone();
        let ad = ad.clone();
        let rb = rb.clone();
        let atx = atx.clone();
        let dc = dc_clone.clone();
        let sk = sk.clone();
        let km = km.clone();
        let pr = pr.clone();
        let ra = ra.clone();
        let crc = crc.clone();
        let wrx = wrx.clone();
        let wtx = wtx_clone.clone();
        let fas = fas.clone();

        Box::pin(async move {
            // Track every byte arriving on the wire
            let wire_bytes = msg.data.len() as u64;
            wrx.fetch_add(wire_bytes, Ordering::Relaxed);

            // Wire format:
            // - 0x00: [flag] + encrypted([payload])
            // - 0x01: [flag] + encrypted(compressed([payload]))  -- compress before encrypt
            if msg.data.is_empty() {
                return;
            }
            let compress_flag = msg.data[0];
            let inner = &msg.data[1..];

            let key = *sk.read().await;

            // Build cipher once per message instead of per-call to decrypt().
            // This avoids re-initializing AES-256-GCM state for every incoming
            // chunk, saving ~1µs per message on the hot path.
            let cipher = match aes_gcm::Aes256Gcm::new_from_slice(&key) {
                Ok(c) => c,
                Err(e) => {
                    error!(event = "cipher_init_failure", error = %e, "Failed to init AES cipher for decrypt");
                    return;
                }
            };

            let decrypted = if compress_flag == 0x01 {
                // Compressed before encryption: decrypt first, then decompress
                let decrypted_inner = match super::decrypt_with(&cipher, inner) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(event = "decrypt_failure", bytes = inner.len(), error = %e, "Decryption failed on incoming frame");
                        notify_app(
                            &atx,
                            ConnectionMessage::Error(format!("Decrypt error: {}", e)),
                        );
                        return;
                    }
                };
                match decompress_data(&decrypted_inner) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(event = "decompress_failure", bytes = decrypted_inner.len(), error = %e, "Decompression failed on incoming frame");
                        notify_app(
                            &atx,
                            ConnectionMessage::Error(format!("Decompress error: {}", e)),
                        );
                        return;
                    }
                }
            } else {
                // No compression (0x00): just decrypt
                match super::decrypt_with(&cipher, inner) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(event = "decrypt_failure", bytes = inner.len(), error = %e, "Decryption failed on incoming frame");
                        notify_app(
                            &atx,
                            ConnectionMessage::Error(format!("Decrypt error: {}", e)),
                        );
                        return;
                    }
                }
            };

            if decrypted.is_empty() {
                return;
            }

            let frame_type = decrypted[0];
            let payload = &decrypted[1..];

            match frame_type {
                FRAME_CONTROL => match serde_json::from_slice::<ControlMessage>(payload) {
                    Ok(ctrl) => {
                        if let Err(e) = handle_control(
                            &dc,
                            ctrl,
                            rs,
                            pc,
                            ad,
                            rb,
                            atx.clone(),
                            sk.clone(),
                            ra.clone(),
                            km.clone(),
                            pr.clone(),
                            crc.clone(),
                            wtx.clone(),
                            fas.clone(),
                        )
                            .await
                        {
                            error!(event = "control_handle_error", error = %e, "Error handling control message");
                            notify_app(
                                &atx,
                                ConnectionMessage::Error(format!("Control error: {}", e)),
                            );
                        }
                    }
                    Err(e) => {
                        error!(event = "control_decode_error", bytes = payload.len(), error = %e, "Failed to decode control message");
                        notify_app(
                            &atx,
                            ConnectionMessage::Error(format!("Control decode error: {}", e)),
                        );
                    }
                },
                FRAME_CHUNK => {
                    // Binary: 16 bytes uuid + 4 bytes seq + payload
                    if payload.len() < 20 {
                        notify_app(
                            &atx,
                            ConnectionMessage::Error("Chunk frame too short".into()),
                        );
                        return;
                    }
                    let file_id = Uuid::from_bytes(payload[..16].try_into().unwrap());
                    let seq = u32::from_be_bytes(payload[16..20].try_into().unwrap());
                    let chunk_data = &payload[20..];

                    let mut map = rs.write().await;
                    if let Some(state) = map.get_mut(&file_id) {
                        match state.writer.write_chunk(seq, chunk_data).await {
                            Ok(write_result) => {
                                use crate::core::pipeline::receiver::{ChunkVerificationStatus, ChunkWriteResult};

                                // Log only verification failures (hot path — no per-chunk debug logs)
                                if let ChunkWriteResult::Written(ChunkVerificationStatus::HashMismatch) = write_result {
                                    warn!(
                                        event = "chunk_hash_mismatch",
                                        file_id = %file_id,
                                        seq = seq,
                                        "Chunk hash mismatch detected - will request retransmission"
                                    );
                                }

                                if let Some(tx) = &atx {
                                    let _ = tx.send(ConnectionMessage::FileProgress {
                                        file_id,
                                        filename: state.writer.filename().to_string(),
                                        received_chunks: state.writer.received_chunks(),
                                        total_chunks: state.writer.total_chunks(),
                                        wire_bytes,
                                        chunk_bitmap_bytes: Some(state.writer.bitmap().to_bytes()),
                                    });
                                }

                                // Check if this was the last chunk AND the
                                // Hash control message already arrived
                                if state.writer.received_chunks() == state.writer.total_chunks() {
                                    if let Some(pending) = state.pending_hash.take() {
                                        let state = map.remove(&file_id).unwrap();
                                        drop(map);
                                        let key = *sk.read().await;
                                        // Spawn finalization in a background task so the
                                        // data channel on_message handler returns immediately
                                        // and can process the next file's chunks/metadata
                                        // without waiting for finalize + hash readback.
                                        let dc = dc.clone();
                                        let atx = atx.clone();
                                        let wtx = wtx.clone();
                                        tokio::spawn(async move {
                                            if let Err(e) =
                                                WebRTCConnection::finalize_file_receive(
                                                    &dc,
                                                    file_id,
                                                    state,
                                                    pending.sha3_256,
                                                    pending.merkle_root,
                                                    &key,
                                                    &atx,
                                                    &wtx,
                                                ).await
                                            {
                                                error!(
                                                    event = "deferred_finalize_error",
                                                    file_id = %file_id,
                                                    error = %e,
                                                    "Error in deferred file finalization"
                                                );
                                                notify_app(
                                                    &atx,
                                                    ConnectionMessage::Error(format!(
                                                        "Deferred finalize error: {}",
                                                        e
                                                    )),
                                                );
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
                        let mut pending = pc.write().await;
                        // Limit pending file IDs
                        if !pending.contains_key(&file_id)
                            && pending.len() >= MAX_PENDING_FILE_IDS
                        {
                            warn!(
                                "Dropping pre-metadata chunk for {}: too many pending file IDs",
                                file_id
                            );
                            return;
                        }
                        let entry = pending.entry(file_id).or_default();
                        if entry.len() >= MAX_PENDING_CHUNKS_PER_FILE {
                            warn!(
                                "Dropping pre-metadata chunk {} for {}: pending buffer full",
                                seq, file_id
                            );
                            return;
                        }
                        tracing::debug!(
                            "Chunk {} for file {} buffered — Metadata not yet received",
                            seq,
                            file_id
                        );
                        entry.push((seq, chunk_data.to_vec(), wire_bytes));
                    }
                }
                _ => {
                    notify_app(
                        &atx,
                        ConnectionMessage::Debug(format!(
                            "Unknown frame type: 0x{:02x}",
                            frame_type
                        )),
                    );
                }
            }
        })
    }));
}

#[allow(clippy::too_many_arguments)]
async fn handle_control(
    dc: &Arc<RTCDataChannel>,
    msg: ControlMessage,
    recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
    accepted_destinations: Arc<RwLock<HashMap<Uuid, std::path::PathBuf>>>,
    resume_bitmaps: Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    shared_key: Arc<RwLock<[u8; 32]>>,
    remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    key_manager: Option<SessionKeyManager>,
    pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    chat_recv_counter: Arc<RwLock<u64>>,
    wire_tx: Arc<AtomicU64>,
    file_ack_semaphore: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    let key = *shared_key.read().await;
    match msg {
        ControlMessage::Text(data) => {
            notify_app(&app_tx, ConnectionMessage::TextReceived(data));
        }
        ControlMessage::DirectMessage(data) => {
            notify_app(&app_tx, ConnectionMessage::DmReceived(data));
        }
        ControlMessage::Typing => {
            notify_app(&app_tx, ConnectionMessage::TypingReceived);
        }
        ControlMessage::AuthenticatedText(envelope) => {
            let hmac_key = derive_chat_hmac_key(&key);
            match serde_json::from_slice::<AuthenticatedMessage>(&envelope) {
                Ok(auth_msg) => {
                    if !MessageAuthenticator::verify(&hmac_key, &auth_msg) {
                        warn!(
                            event = "chat_hmac_invalid",
                            "Rejected room chat: HMAC verification failed"
                        );
                        return Ok(());
                    }
                    let mut counter = chat_recv_counter.write().await;
                    if auth_msg.counter <= *counter {
                        warn!(
                            event = "chat_replay_detected",
                            counter = auth_msg.counter,
                            last_seen = *counter,
                            "Rejected room chat: replay detected"
                        );
                        return Ok(());
                    }
                    *counter = auth_msg.counter;
                    drop(counter);
                    notify_app(&app_tx, ConnectionMessage::TextReceived(auth_msg.payload));
                }
                Err(e) => {
                    warn!(event = "chat_auth_decode_error", error = %e, "Failed to decode authenticated room chat");
                }
            }
        }
        ControlMessage::AuthenticatedDm(envelope) => {
            let hmac_key = derive_chat_hmac_key(&key);
            match serde_json::from_slice::<AuthenticatedMessage>(&envelope) {
                Ok(auth_msg) => {
                    if !MessageAuthenticator::verify(&hmac_key, &auth_msg) {
                        warn!(
                            event = "dm_hmac_invalid",
                            "Rejected DM: HMAC verification failed"
                        );
                        return Ok(());
                    }
                    let mut counter = chat_recv_counter.write().await;
                    if auth_msg.counter <= *counter {
                        warn!(
                            event = "dm_replay_detected",
                            counter = auth_msg.counter,
                            last_seen = *counter,
                            "Rejected DM: replay detected"
                        );
                        return Ok(());
                    }
                    *counter = auth_msg.counter;
                    drop(counter);
                    notify_app(&app_tx, ConnectionMessage::DmReceived(auth_msg.payload));
                }
                Err(e) => {
                    warn!(event = "dm_auth_decode_error", error = %e, "Failed to decode authenticated DM");
                }
            }
        }
        ControlMessage::DisplayName(name) => {
            notify_app(&app_tx, ConnectionMessage::DisplayNameReceived(name));
        }
        ControlMessage::AreYouAwake => {
            // Auto-reply with ImAwake
            let key = *shared_key.read().await;
            if let Err(e) =
                WebRTCConnection::send_control_on(dc, &key, &ControlMessage::ImAwake, &wire_tx)
                    .await
            {
                warn!(event = "awake_reply_failed", error = %e, "Failed to send ImAwake reply");
            }
        }
        ControlMessage::ImAwake => {
            notify_app(&app_tx, ConnectionMessage::AwakeReceived);
        }
        ControlMessage::Metadata {
            file_id,
            total_chunks,
            filename,
            filesize,
        } => {
            // Compute save path
            let dest_dir = accepted_destinations.write().await.remove(&file_id);
            let safe_name = sanitize_relative_path(&filename);
            let save_path = if let Some(dir) = &dest_dir {
                dir.join(&safe_name)
            } else {
                std::env::current_dir().unwrap_or_default().join(&safe_name)
            };

            tracing::info!(
                "Receiving file '{}' ({} bytes, {} chunks) to: {}",
                filename,
                filesize,
                total_chunks,
                save_path.display()
            );

            // Check if we have a resume bitmap for this file (from a prior
            // resume request).  If so, open the existing temp file without
            // truncating — the sender will skip already-received chunks.
            let resume_bitmap = resume_bitmaps.write().await.remove(&file_id);

            let writer = if let Some(bitmap) = resume_bitmap {
                match StreamingFileWriter::resume(
                    filename.clone(), filesize, total_chunks, save_path, bitmap,
                ).await {
                    Ok(w) => w,
                    Err(e) => {
                        error!(
                            event = "streaming_writer_resume_failed",
                            file_id = %file_id,
                            filename = %filename,
                            error = %e,
                            "Failed to resume streaming file writer"
                        );
                        return Err(anyhow!("Failed to resume file writer: {}", e));
                    }
                }
            } else {
                match StreamingFileWriter::new(
                    filename.clone(), filesize, total_chunks, save_path,
                ).await {
                    Ok(w) => w,
                    Err(e) => {
                        error!(
                            event = "streaming_writer_create_failed",
                            file_id = %file_id,
                            filename = %filename,
                            error = %e,
                            "Failed to create streaming file writer"
                        );
                        return Err(anyhow!("Failed to create file writer: {}", e));
                    }
                }
            };

            let st = ReceiveFileState {
                writer,
                pending_hash: None,
            };
            recv_state.write().await.insert(file_id, st);

            // Process any chunks that arrived before this Metadata frame
            let buffered = {
                let mut pending = pending_chunks.write().await;
                pending.remove(&file_id).unwrap_or_default()
            };
            if !buffered.is_empty() {
                tracing::debug!(
                    "Processing {} buffered chunks for file {}",
                    buffered.len(),
                    file_id
                );
                let mut map = recv_state.write().await;
                if let Some(state) = map.get_mut(&file_id) {
                    for (seq, chunk_data, buffered_wire_bytes) in &buffered {
                        match state.writer.write_chunk(*seq, chunk_data).await {
                            Ok(_write_result) => {
                                if let Some(tx) = &app_tx {
                                    let _ = tx.send(ConnectionMessage::FileProgress {
                                        file_id,
                                        filename: state.writer.filename().to_string(),
                                        received_chunks: state.writer.received_chunks(),
                                        total_chunks: state.writer.total_chunks(),
                                        wire_bytes: *buffered_wire_bytes,
                                        chunk_bitmap_bytes: Some(state.writer.bitmap().to_bytes()),
                                    });
                                }
                            }
                            Err(e) => {
                                error!("Buffered chunk {} for {} write error: {}", seq, file_id, e);
                            }
                        }
                    }
                }
                drop(map);
            }

            if let Some(tx) = &app_tx {
                let _ = tx.send(ConnectionMessage::Debug(format!(
                    "Receiving: {} ({} bytes, {} chunks)",
                    filename, filesize, total_chunks
                )));
            }
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

            let mut map = recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                // Create verifier and set it on the writer
                let verifier = ChunkHashVerifier::new(chunk_hashes);
                state.writer.set_verifier(verifier);

                tracing::debug!(
                    event = "verifier_set",
                    file_id = %file_id,
                    "Chunk hash verifier set for incremental verification"
                );
            } else {
                // MerkleTree arrived before Metadata - this shouldn't happen
                // in normal operation, but we log it
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
            let hash_count = chunk_hashes.len();
            tracing::debug!(
                event = "chunk_hash_batch_received",
                file_id = %file_id,
                start_index = start_index,
                count = hash_count,
                "Received incremental chunk hash batch"
            );

            let mut map = recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                // Add hashes to the incremental verifier
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
            let mut map = recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                if state.writer.received_chunks() == state.writer.total_chunks() {
                    // All chunks already received — spawn finalization in
                    // background so the control handler returns immediately
                    // and can process the next file's metadata/hashes.
                    let state = map.remove(&file_id).unwrap();
                    drop(map);
                    let dc = dc.clone();
                    let app_tx = app_tx.clone();
                    let wire_tx = wire_tx.clone();
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
                &app_tx,
                ConnectionMessage::SendComplete {
                    file_id,
                    success: ok,
                },
            );
        }
        ControlMessage::LsRequest { path } => {
            tracing::info!("Remote ls request: {}", path);
            if !*remote_access.borrow() {
                WebRTCConnection::send_control_on(
                    dc,
                    &key,
                    &ControlMessage::RemoteAccessDisabled,
                    &wire_tx,
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
                    &wire_tx,
                )
                .await?;
            }
        }
        ControlMessage::LsResponse { path, entries } => {
            notify_app(&app_tx, ConnectionMessage::LsResponse { path, entries });
        }
        ControlMessage::FetchRequest { path, is_folder } => {
            tracing::info!("Remote fetch request: {} (folder: {})", path, is_folder);
            if !*remote_access.borrow() {
                WebRTCConnection::send_control_on(
                    dc,
                    &key,
                    &ControlMessage::RemoteAccessDisabled,
                    &wire_tx,
                )
                .await?;
            } else {
                notify_app(
                    &app_tx,
                    ConnectionMessage::RemoteFetchRequest { path, is_folder },
                );
            }
        }
        ControlMessage::RemoteAccessDisabled => {
            notify_app(&app_tx, ConnectionMessage::RemoteAccessDisabled);
        }
        // ── Transaction-level protocol ───────────────────────────────────
        ControlMessage::TransactionRequest {
            transaction_id,
            display_name,
            manifest,
            total_size,
        } => {
            notify_app(
                &app_tx,
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
                    &app_tx,
                    ConnectionMessage::TransactionAccepted {
                        transaction_id,
                        dest_path,
                    },
                );
            } else {
                notify_app(
                    &app_tx,
                    ConnectionMessage::TransactionRejected {
                        transaction_id,
                        reason: reject_reason,
                    },
                );
            }
        }
        ControlMessage::TransactionComplete { transaction_id } => {
            notify_app(
                &app_tx,
                ConnectionMessage::TransactionCompleted { transaction_id },
            );
        }
        ControlMessage::TransactionCancel {
            transaction_id,
            reason,
        } => {
            notify_app(
                &app_tx,
                ConnectionMessage::TransactionCancelled {
                    transaction_id,
                    reason,
                },
            );
        }
        ControlMessage::TransactionResumeRequest { resume_info } => {
            notify_app(
                &app_tx,
                ConnectionMessage::TransactionResumeRequested { resume_info },
            );
        }
        ControlMessage::TransactionResumeResponse {
            transaction_id,
            accepted,
        } => {
            if accepted {
                notify_app(
                    &app_tx,
                    ConnectionMessage::TransactionResumeAccepted { transaction_id },
                );
            } else {
                notify_app(
                    &app_tx,
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
                &app_tx,
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
                &app_tx,
                ConnectionMessage::TransactionCompleteAcked { transaction_id },
            );
        }
        ControlMessage::KeyRotation { ephemeral_pub } => {
            use crate::core::connection::crypto;

            let peer_pub: [u8; 32] = ephemeral_pub
                .try_into()
                .map_err(|_| anyhow!("Invalid ephemeral public key length for rotation"))?;

            if let Some(ref km) = key_manager {
                // Check if we have a pending rotation (we initiated)
                let our_eph = pending_rotation.write().await.take();

                if let Some(local_eph) = our_eph {
                    // We initiated the rotation — complete it with peer's response
                    let new_key = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
                    info!(event = "key_rotated_initiator", new_key_prefix = ?&new_key[..4], "Session key rotated (initiator side)");
                } else {
                    // Peer initiated — generate our own ephemeral, respond, then rotate
                    let local_eph = crypto::prepare_rotation();
                    let response_key = *shared_key.read().await;
                    WebRTCConnection::send_control_on(
                        dc,
                        &response_key,
                        &ControlMessage::KeyRotation {
                            ephemeral_pub: local_eph.public.to_vec(),
                        },
                        &wire_tx,
                    )
                    .await?;
                    let new_key = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
                    info!(event = "key_rotated_responder", new_key_prefix = ?&new_key[..4], "Session key rotated (responder side)");
                }

                notify_app(
                    &app_tx,
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
                &app_tx,
                ConnectionMessage::FileReceivedAck { file_id },
            );
            // Release one permit so the sender can proceed with the next file
            file_ack_semaphore.add_permits(1);
        }
    }
    Ok(())
}
