use super::HandlerContext;
use crate::core::connection::webrtc::ConnectionMessage;
use crate::core::helpers::notify_app;
use crate::core::security::message_auth::{AuthenticatedMessage, MessageAuthenticator};
use tracing::warn;

pub(super) async fn handle_authenticated_message(
    envelope: &[u8],
    key: &[u8; 32],
    ctx: &HandlerContext,
    is_room_chat: bool,
) {
    let hmac_key = super::super::derive_chat_hmac_key(key);

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
