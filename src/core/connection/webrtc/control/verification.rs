use super::HandlerContext;
use crate::core::connection::webrtc::{ConnectionMessage, ControlMessage, WebRTCConnection};
use crate::core::helpers::notify_app;
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::pipeline::merkle::MerkleTree;
use anyhow::Result;
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;
use webrtc::data_channel::RTCDataChannel;

pub(super) async fn handle_all_hashes_sent(
    dc: &Arc<RTCDataChannel>,
    file_id: Uuid,
    ctx: &HandlerContext,
) -> Result<()> {
    let (final_path, sender_hashes, total_chunks, filename) = {
        let map = ctx.recv_state.read().await;
        let Some(state) = map.get(&file_id) else {
            return Ok(());
        };
        (
            state.writer.final_path().to_path_buf(),
            state.writer.chunk_hashes().to_vec(),
            state.writer.total_chunks(),
            state.writer.filename().to_string(),
        )
    };

    let all_hashes_present = sender_hashes.iter().all(|h| h.is_some());

    if !all_hashes_present || !final_path.exists() {
        let have_bitmap = ChunkBitmap::new(total_chunks).to_bytes();
        let key = *ctx.shared_key.read().await;
        WebRTCConnection::send_control_on(
            dc,
            &key,
            &ControlMessage::FileHaveChunks {
                file_id,
                have_bitmap,
            },
            &ctx.wire_tx,
        )
        .await?;
        return Ok(());
    }

    let recv_state = Arc::clone(&ctx.recv_state);
    let app_tx = ctx.app_tx.clone();
    let wire_tx = Arc::clone(&ctx.wire_tx);
    let dc_clone = dc.clone();
    let shared_key = Arc::clone(&ctx.shared_key);

    tokio::spawn(async move {
        let compare_result = {
            let mut map = recv_state.write().await;
            if let Some(state) = map.get_mut(&file_id) {
                state.writer.load_from_existing_file(&final_path).await
            } else {
                return;
            }
        };

        let key = *shared_key.read().await;
        match compare_result {
            Ok(matched) => {
                let matched_count = (0..total_chunks).filter(|&i| matched.is_set(i)).count() as u32;

                if matched_count == total_chunks {
                    let leaves: Vec<[u8; 32]> = sender_hashes.into_iter().flatten().collect();
                    let merkle_root = MerkleTree::compute_root(&leaves);

                    // Identical file: no transfer needed.
                    // Drop receiver state and clean temporary artifacts created for bitmap/probing.
                    let temp_paths = {
                        let mut map = recv_state.write().await;
                        map.remove(&file_id).map(|state| {
                            (
                                state.writer.temp_path_ref().to_path_buf(),
                                state.writer.bitmap_path_ref().to_path_buf(),
                            )
                        })
                    };
                    if let Some((temp_path, bitmap_path)) = temp_paths {
                        if let Err(e) = tokio::fs::remove_file(&temp_path).await
                            && e.kind() != std::io::ErrorKind::NotFound
                        {
                            warn!(
                                event = "identical_file_tmp_cleanup_failed",
                                %file_id,
                                path = %temp_path.display(),
                                %e,
                                "Failed to remove identical-file temp artifact"
                            );
                        }
                        if let Err(e) = tokio::fs::remove_file(&bitmap_path).await
                            && e.kind() != std::io::ErrorKind::NotFound
                        {
                            warn!(
                                event = "identical_file_bitmap_cleanup_failed",
                                %file_id,
                                path = %bitmap_path.display(),
                                %e,
                                "Failed to remove identical-file bitmap artifact"
                            );
                        }
                    }

                    notify_app(
                        &app_tx,
                        ConnectionMessage::FileSaved {
                            file_id,
                            filename,
                            path: final_path.to_string_lossy().into_owned(),
                            merkle_root,
                        },
                    );
                    let _ = WebRTCConnection::send_control_on(
                        &dc_clone,
                        &key,
                        &ControlMessage::FileSkip { file_id },
                        &wire_tx,
                    )
                    .await;
                } else {
                    let have_bitmap = {
                        let map = recv_state.read().await;
                        map.get(&file_id)
                            .map(|s| s.writer.bitmap().to_bytes())
                            .unwrap_or_else(|| ChunkBitmap::new(total_chunks).to_bytes())
                    };
                    let _ = WebRTCConnection::send_control_on(
                        &dc_clone,
                        &key,
                        &ControlMessage::FileHaveChunks {
                            file_id,
                            have_bitmap,
                        },
                        &wire_tx,
                    )
                    .await;
                }
            }
            Err(e) => {
                warn!(
                    event = "existing_file_check_failed",
                    %file_id, %e,
                    "Failed to compare existing file - requesting all chunks"
                );
                let have_bitmap = ChunkBitmap::new(total_chunks).to_bytes();
                let _ = WebRTCConnection::send_control_on(
                    &dc_clone,
                    &key,
                    &ControlMessage::FileHaveChunks {
                        file_id,
                        have_bitmap,
                    },
                    &wire_tx,
                )
                .await;
            }
        }
    });

    Ok(())
}
