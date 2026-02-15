//! Control channel: data channel message handler and control message dispatch.

use crate::core::config::{MAX_PENDING_CHUNKS_PER_FILE, MAX_PENDING_FILE_IDS};
use crate::core::connection::crypto::SessionKeyManager;
use crate::core::pipeline::receiver::StreamingFileWriter;
use crate::core::security::message_auth::{AuthenticatedMessage, MessageAuthenticator};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;

use super::{
    decompress_data, decrypt, derive_chat_hmac_key, notify_app, sanitize_relative_path,
    ConnectionMessage, ControlMessage, PendingHash, ReceiveFileState, WebRTCConnection, WireStats,
    FRAME_CHUNK, FRAME_CONTROL,
};

// ── Data channel message handler ─────────────────────────────────────────

pub(crate) async fn attach_dc_handlers(
    dc: &Arc<RTCDataChannel>,
    recv_state: Arc<RwLock<HashMap<Uuid, ReceiveFileState>>>,
    pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
    accepted_destinations: Arc<RwLock<HashMap<Uuid, std::path::PathBuf>>>,
    app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    shared_key: Arc<RwLock<[u8; 32]>>,
    remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    key_manager: Option<SessionKeyManager>,
    pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    chat_recv_counter: Arc<RwLock<u64>>,
    wire_stats: Arc<WireStats>,
) {
    let dc_clone = dc.clone();
    let rs = recv_state;
    let pc = pending_chunks;
    let ad = accepted_destinations;
    let atx = app_tx;
    let sk = shared_key;
    let km = key_manager;
    let pr = pending_rotation;
    let ra = remote_access;
    let crc = chat_recv_counter;
    let ws = wire_stats;

    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let rs = rs.clone();
        let pc = pc.clone();
        let ad = ad.clone();
        let atx = atx.clone();
        let dc = dc_clone.clone();
        let sk = sk.clone();
        let km = km.clone();
        let pr = pr.clone();
        let ra = ra.clone();
        let crc = crc.clone();
        let ws = ws.clone();

        Box::pin(async move {
            // Track every byte arriving on the wire
            let wire_bytes = msg.data.len() as u64;
            ws.add_rx(wire_bytes);

            // Decrypt
            let key = *sk.read().await;
            let decrypted = match decrypt(&key, &msg.data) {
                Ok(p) => p,
                Err(e) => {
                    error!(event = "decrypt_failure", bytes = msg.data.len(), error = %e, "Decryption failed on incoming frame");
                    notify_app(
                        &atx,
                        ConnectionMessage::Error(format!("Decrypt error: {}", e)),
                    );
                    return;
                }
            };

            // Envelope: [1-byte compress flag] + [payload]
            if decrypted.is_empty() {
                return;
            }
            let compress_flag = decrypted[0];
            let inner = &decrypted[1..];

            let plaintext = if compress_flag == 0x01 {
                match decompress_data(inner) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(event = "decompress_failure", bytes = inner.len(), error = %e, "Decompression failed on incoming frame");
                        notify_app(
                            &atx,
                            ConnectionMessage::Error(format!("Decompress error: {}", e)),
                        );
                        return;
                    }
                }
            } else {
                inner.to_vec()
            };

            if plaintext.is_empty() {
                return;
            }

            let frame_type = plaintext[0];
            let payload = &plaintext[1..];

            match frame_type {
                FRAME_CONTROL => match serde_json::from_slice::<ControlMessage>(payload) {
                    Ok(ctrl) => {
                        if let Err(e) = handle_control(
                            &dc,
                            ctrl,
                            rs,
                            pc,
                            ad,
                            atx.clone(),
                            sk.clone(),
                            ra.clone(),
                            km.clone(),
                            pr.clone(),
                            crc.clone(),
                            ws.clone(),
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
                            Ok(()) => {
                                if let Some(tx) = &atx {
                                    let _ = tx.send(ConnectionMessage::FileProgress {
                                        file_id,
                                        filename: state.writer.filename().to_string(),
                                        received_chunks: state.writer.received_chunks(),
                                        total_chunks: state.writer.total_chunks(),
                                        wire_bytes,
                                    });
                                }

                                // Check if this was the last chunk AND the
                                // Hash control message already arrived
                                if state.writer.received_chunks() == state.writer.total_chunks() {
                                    if let Some(pending) = state.pending_hash.take() {
                                        let state = map.remove(&file_id).unwrap();
                                        drop(map);
                                        let key = *sk.read().await;
                                        if let Err(e) =
                                            WebRTCConnection::finalize_file_receive(
                                                &dc,
                                                file_id,
                                                state,
                                                pending.sha3_256,
                                                pending.merkle_root,
                                                &key,
                                                &atx,
                                                &ws,
                                            )
                                            .await
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
    app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    shared_key: Arc<RwLock<[u8; 32]>>,
    remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
    key_manager: Option<SessionKeyManager>,
    pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    chat_recv_counter: Arc<RwLock<u64>>,
    wire_stats: Arc<WireStats>,
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
        ControlMessage::Ping => {
            // Auto-reply with Pong
            let key = *shared_key.read().await;
            if let Err(e) =
                WebRTCConnection::send_control_on(dc, &key, &ControlMessage::Pong, &wire_stats)
                    .await
            {
                warn!(event = "pong_send_failed", error = %e, "Failed to send pong");
            }
        }
        ControlMessage::Pong => {
            notify_app(&app_tx, ConnectionMessage::PongReceived);
        }
        ControlMessage::Metadata {
            file_id,
            total_chunks,
            filename,
            filesize,
        } => {
            if filesize == 0 {
                warn!(event = "zero_size_file", file_id = %file_id, filename = %filename, "Rejected file with zero size");
                return Err(anyhow!("Cannot receive file with zero size"));
            }
            // Compute save path
            let dest_dir = accepted_destinations.write().await.remove(&file_id);
            let safe_name = sanitize_relative_path(&filename);
            let save_path = if let Some(dir) = &dest_dir {
                dir.join(&safe_name)
            } else {
                std::env::current_dir()
                    .unwrap_or_default()
                    .join(&safe_name)
            };

            tracing::info!(
                "Receiving file '{}' ({} bytes, {} chunks) to: {}",
                filename,
                filesize,
                total_chunks,
                save_path.display()
            );

            // Create streaming writer — writes chunks directly to disk
            let writer = match StreamingFileWriter::new(
                filename.clone(),
                filesize,
                total_chunks,
                save_path,
            )
            .await
            {
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
                            Ok(()) => {
                                if let Some(tx) = &app_tx {
                                    let _ = tx.send(ConnectionMessage::FileProgress {
                                        file_id,
                                        filename: state.writer.filename().to_string(),
                                        received_chunks: state.writer.received_chunks(),
                                        total_chunks: state.writer.total_chunks(),
                                        wire_bytes: *buffered_wire_bytes,
                                    });
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Buffered chunk {} for {} write error: {}",
                                    seq, file_id, e
                                );
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
        ControlMessage::Hash {
            file_id,
            sha3_256,
            merkle_root: sender_merkle_root,
        } => {
            let mut map = recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                if state.writer.received_chunks() == state.writer.total_chunks() {
                    // All chunks already received — finalize immediately.
                    let state = map.remove(&file_id).unwrap();
                    drop(map);
                    WebRTCConnection::finalize_file_receive(
                        dc,
                        file_id,
                        state,
                        sha3_256,
                        sender_merkle_root,
                        &key,
                        &app_tx,
                        &wire_stats,
                    )
                    .await?;
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
                    &wire_stats,
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
                    &wire_stats,
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
                    &wire_stats,
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
            }
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
                        &wire_stats,
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
    }
    Ok(())
}
