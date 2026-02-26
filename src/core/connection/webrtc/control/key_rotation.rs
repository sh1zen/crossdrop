use super::HandlerContext;
use crate::core::connection::webrtc::{ConnectionMessage, ControlMessage, WebRTCConnection};
use crate::core::helpers::notify_app;
use anyhow::{anyhow, Result};
use std::sync::Arc;
use tracing::{info, warn};
use webrtc::data_channel::RTCDataChannel;

pub(super) async fn handle_key_rotation(
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
        let k = crypto::complete_rotation(km, &local_eph, &peer_pub).await;
        info!(event = "key_rotated_initiator", new_key_prefix = ?&k[..4], "Session key rotated (initiator)");
        k
    } else {
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

    let _ = new_key;
    notify_app(
        &ctx.app_tx,
        ConnectionMessage::Debug("Session key rotated successfully".into()),
    );
    Ok(())
}
