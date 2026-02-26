use super::HandlerContext;
use crate::core::config::{
    DATA_ACK_INTERVAL_BYTES, MAX_PENDING_CHUNKS_PER_FILE, MAX_PENDING_FILE_IDS,
};
use crate::core::connection::webrtc::{
    ConnectionMessage, ControlMessage, ReceiveFileState, WebRTCConnection,
};
use crate::core::helpers::notify_app;
use crate::core::pipeline::receiver::{detect_existing_progress, StreamingFileWriter};
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::RTCDataChannel;

pub(super) async fn handle_chunk_frame(
    dc: &Arc<RTCDataChannel>,
    file_id: Uuid,
    seq: u32,
    chunk_data: &[u8],
    wire_bytes: u64,
    ctx: &HandlerContext,
) {
    if ctx.skipped_files.lock().await.contains(&file_id) {
        tracing::debug!(
            event = "skipped_file_chunk_ignored",
            %file_id,
            seq,
            "Ignoring late chunk for file already marked as FileSkip"
        );
        return;
    }

    let txn_id = {
        let file_map = ctx.file_to_transaction.lock().await;
        file_map.get(&file_id).copied()
    };
    if let Some(txn_id) = txn_id
        && ctx.cancelled_transactions.lock().await.contains(&txn_id)
    {
        tracing::debug!(
            event = "cancelled_chunk_dropped",
            %file_id, seq, transaction_id = %txn_id,
            "Chunk dropped - belongs to cancelled transaction"
        );
        return;
    }

    let mut map = ctx.recv_state.write().await;
    let Some(state) = map.get_mut(&file_id) else {
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

            let prev_rx = ctx.data_rx_bytes.fetch_add(wire_bytes, Ordering::Relaxed);
            let new_rx = prev_rx + wire_bytes;
            if new_rx / DATA_ACK_INTERVAL_BYTES > prev_rx / DATA_ACK_INTERVAL_BYTES {
                let ack_key = *ctx.shared_key.read().await;
                if let Err(e) = WebRTCConnection::send_control_on(
                    dc,
                    &ack_key,
                    &ControlMessage::DataAck {
                        bytes_received: new_rx,
                    },
                    &ctx.wire_tx,
                )
                .await
                {
                    warn!(event = "data_ack_send_failed", %e, "Failed to send DataAck");
                }
            }

            let all_received = state.writer.received_chunks() == state.writer.total_chunks();
            if all_received && let Some(pending) = state.pending_hash.take() {
                let state = map.remove(&file_id).unwrap();
                drop(map);
                let key = *ctx.shared_key.read().await;
                spawn_finalization(
                    dc,
                    file_id,
                    state,
                    pending.merkle_root,
                    key,
                    ctx.app_tx.clone(),
                    ctx.wire_tx.clone(),
                );
            }
        }
        Err(e) => {
            error!("Chunk {} for {} write error: {}", seq, file_id, e);
        }
    }
}

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

    tracing::debug!("Chunk {seq} for file {file_id} buffered - Metadata not yet received");
    entry.push((seq, chunk_data.to_vec(), wire_bytes));
}

pub(super) fn spawn_finalization(
    dc: &Arc<RTCDataChannel>,
    file_id: Uuid,
    state: ReceiveFileState,
    merkle_root: [u8; 32],
    key: [u8; 32],
    app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
    wire_tx: Arc<AtomicU64>,
) {
    let dc = dc.clone();
    tokio::spawn(async move {
        if let Err(e) = WebRTCConnection::finalize_file_receive(
            &dc,
            file_id,
            state,
            merkle_root,
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
}

pub(super) async fn handle_metadata(
    file_id: Uuid,
    total_chunks: u32,
    filename: String,
    filesize: u64,
    dc: &Arc<RTCDataChannel>,
    key: &[u8; 32],
    ctx: &HandlerContext,
) -> Result<()> {
    ctx.skipped_files.lock().await.remove(&file_id);

    {
        let dests = ctx.accepted_destinations.read().await;
        let keys: Vec<Uuid> = dests.keys().copied().collect();
        tracing::info!(
            event = "handle_metadata_lookup",
            %file_id,
            %filename,
            registered_ids = ?keys,
            "Looking up file_id in accepted_destinations"
        );
    }

    let save_path = match ctx.accepted_destinations.write().await.remove(&file_id) {
        Some(path) => path,
        None => {
            tracing::warn!(
                %file_id, %filename,
                "No destination registered for file - skipping (cancelled or unexpected file_id)"
            );
            return Ok(());
        }
    };

    tracing::info!(
        "Receiving file '{filename}' ({filesize} bytes, {total_chunks} chunks) to: {}",
        save_path.display()
    );

    let engine_bitmap = ctx.resume_bitmaps.write().await.remove(&file_id);
    let disk_bitmap = detect_existing_progress(&save_path, total_chunks);

    let bitmap = match (disk_bitmap, engine_bitmap) {
        (Some(db), _) => {
            info!(
                event = "resuming_from_disk_bitmap",
                %file_id,
                %filename,
                received_chunks = (0..total_chunks).filter(|&i| db.is_set(i)).count(),
                "Resuming from on-disk bitmap (persisted per-flush)"
            );
            Some(db)
        }
        (None, Some(eb)) => {
            info!(
                event = "resuming_from_engine_bitmap",
                %file_id,
                %filename,
                "Resuming from engine bitmap (no disk bitmap found)"
            );
            Some(eb)
        }
        (None, None) => None,
    };

    let writer = match bitmap {
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

    let have_bitmap = {
        let map = ctx.recv_state.read().await;
        map.get(&file_id).map(|s| {
            let bm = s.writer.bitmap().to_bytes();
            let received = s.writer.received_chunks();
            (bm, received)
        })
    };
    if let Some((have_bitmap, received)) = have_bitmap
        && received > 0
    {
        if let Err(e) = WebRTCConnection::send_control_on(
            dc,
            key,
            &ControlMessage::FileHaveChunks {
                file_id,
                have_bitmap,
            },
            &ctx.wire_tx,
        )
        .await
        {
            warn!(
                event = "file_have_chunks_send_failed",
                %file_id,
                %e,
                "Failed to send early FileHaveChunks hint"
            );
        } else {
            tracing::info!(
                event = "file_have_chunks_sent_early",
                %file_id,
                received_chunks = received,
                total_chunks,
                "Sent early FileHaveChunks hint to sender"
            );
        }
    }

    Ok(())
}
