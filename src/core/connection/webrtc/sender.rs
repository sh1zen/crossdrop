//! Sender: TX operations - messaging, control frames, and transport primitives.

use super::{
    compress_data, derive_chat_hmac_key, encrypt_with, ControlMessage, WebRTCConnection,
    CHAT_HMAC_CHANNEL,
};
use crate::core::config::{
    DC_BACKPRESSURE_MAX_WAIT, DC_BACKPRESSURE_POLL_INTERVAL, DC_BUFFERED_AMOUNT_HIGH,
};
use crate::core::connection::webrtc::data::encode_control_frame;
use crate::core::connection::webrtc::types::FilePullRequestItem;
use crate::core::pipeline::chunk::ChunkBitmap;
use crate::core::security::message_auth::MessageAuthenticator;
use crate::core::transaction::TransactionManifest;
use aes_gcm::{aead::KeyInit, Aes256Gcm};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;

/// Outcome of a single encrypted send: wire bytes written.
type WireBytes = usize;

struct SendTarget<'a> {
    dc: &'a Arc<RTCDataChannel>,
    wire_tx: &'a Arc<AtomicU64>,
}

impl<'a> SendTarget<'a> {
    fn new(dc: &'a Arc<RTCDataChannel>, wire_tx: &'a Arc<AtomicU64>) -> Self {
        Self { dc, wire_tx }
    }

    fn assert_open(&self) -> Result<()> {
        let state = self.dc.ready_state();
        if state == RTCDataChannelState::Open {
            Ok(())
        } else {
            warn!(
                event = "send_channel_not_open",
                ?state,
                "Attempted send on non-open data channel"
            );
            Err(anyhow!("Data channel not open: {:?}", state))
        }
    }

    fn record(&self, n: usize) {
        self.wire_tx.fetch_add(n as u64, Ordering::Relaxed);
    }
}

fn build_wire_frame_cipher(
    cipher: &Aes256Gcm,
    plaintext: &[u8],
    compress: bool,
) -> Result<Vec<u8>> {
    let (flag, ciphertext) = if compress {
        let compressed = compress_data(plaintext).map_err(|e| {
            error!(event = "compress_failure", bytes = plaintext.len(), %e);
            e
        })?;
        let ct = encrypt_with(cipher, &compressed).map_err(|e| {
            error!(event = "encrypt_failure", bytes = compressed.len(), %e);
            e
        })?;
        (0x01u8, ct)
    } else {
        let ct = encrypt_with(cipher, plaintext).map_err(|e| {
            error!(event = "encrypt_failure", bytes = plaintext.len(), %e);
            e
        })?;
        (0x00u8, ct)
    };
    Ok(prepend_flag(flag, &ciphertext))
}

#[inline]
fn prepend_flag(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(1 + payload.len());
    frame.push(flag);
    frame.extend_from_slice(payload);
    frame
}

async fn wait_for_buffer_space(dc: &Arc<RTCDataChannel>, next_msg_size: usize) -> Result<()> {
    let state = dc.ready_state();
    if state != RTCDataChannelState::Open {
        return Err(anyhow!("Data channel not open: {:?}", state));
    }

    let buffered = dc.buffered_amount().await as usize;
    if buffered + next_msg_size <= DC_BUFFERED_AMOUNT_HIGH {
        return Ok(());
    }

    info!(
        channel = %dc.label(),
        buffered,
        next_msg = next_msg_size,
        high_watermark = DC_BUFFERED_AMOUNT_HIGH,
        "Applying backpressure - waiting for buffer to drain"
    );

    let deadline = std::time::Instant::now() + DC_BACKPRESSURE_MAX_WAIT;

    loop {
        if dc.ready_state() != RTCDataChannelState::Open {
            return Err(anyhow!(
                "DataChannel '{}' closed during backpressure wait",
                dc.label()
            ));
        }
        if dc.buffered_amount().await as usize + next_msg_size <= DC_BUFFERED_AMOUNT_HIGH {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(DC_BACKPRESSURE_POLL_INTERVAL).await;
    }

    if dc.ready_state() == RTCDataChannelState::Open {
        let buffered_amount = dc.buffered_amount().await;
        warn!(channel = %dc.label(), buffered = buffered_amount, "Buffer drain timeout - proceeding anyway");
        Ok(())
    } else {
        Err(anyhow!(
            "DataChannel '{}' closed during backpressure wait",
            dc.label()
        ))
    }
}

impl WebRTCConnection {
    pub async fn send_encrypted(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        plaintext: &[u8],
        compress: bool,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<WireBytes> {
        let cipher = make_cipher(key)?;
        let target = SendTarget::new(dc, wire_tx);
        target.assert_open()?;
        let frame = build_wire_frame_cipher(&cipher, plaintext, compress)?;
        let n = frame.len();
        dc.send(&Bytes::from(frame)).await?;
        target.record(n);
        Ok(n)
    }

    pub async fn send_encrypted_with_cipher(
        dc: &Arc<RTCDataChannel>,
        cipher: &Aes256Gcm,
        plaintext: &[u8],
        compress: bool,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<WireBytes> {
        let target = SendTarget::new(dc, wire_tx);
        target.assert_open()?;
        let frame = build_wire_frame_cipher(cipher, plaintext, compress)?;
        wait_for_buffer_space(dc, frame.len()).await?;
        let n = frame.len();
        dc.send(&Bytes::from(frame)).await?;
        target.record(n);
        Ok(n)
    }

    pub async fn wait_for_data_channel_open(
        dc: &Arc<RTCDataChannel>,
        max_retries: u32,
        retry_delay: Duration,
    ) -> Result<()> {
        for attempt in 0..=max_retries {
            match dc.ready_state() {
                RTCDataChannelState::Open => return Ok(()),
                RTCDataChannelState::Closed => {
                    return Err(anyhow!(
                        "DataChannel '{}' is permanently closed",
                        dc.label()
                    ));
                }
                state => {
                    if attempt < max_retries {
                        debug!(
                            channel = %dc.label(),
                            attempt = attempt + 1,
                            max_retries,
                            ?state,
                            "Waiting for data channel to open"
                        );
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }
        match dc.ready_state() {
            RTCDataChannelState::Open => Ok(()),
            RTCDataChannelState::Closed => Err(anyhow!(
                "DataChannel '{}' is permanently closed",
                dc.label()
            )),
            state => Err(anyhow!(
                "DataChannel '{}' not open after {} retries (state: {:?})",
                dc.label(),
                max_retries,
                state
            )),
        }
    }

    pub async fn send_control_counted(&self, msg: &ControlMessage) -> Result<u64> {
        let dc = self
            .control_channel
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Control channel not available"))?;
        let frame = encode_control_frame(msg)?;
        let key = *self.shared_key.read().await;
        Self::send_encrypted(&dc, &key, &frame, true, &self.wire_tx)
            .await
            .map(|n| n as u64)
    }

    pub async fn send_control(&self, msg: &ControlMessage) -> Result<()> {
        self.send_control_counted(msg).await.map(|_| ())
    }

    pub async fn send_control_on(
        dc: &Arc<RTCDataChannel>,
        key: &[u8; 32],
        msg: &ControlMessage,
        wire_tx: &Arc<AtomicU64>,
    ) -> Result<()> {
        let frame = encode_control_frame(msg)?;
        Self::send_encrypted(dc, key, &frame, true, wire_tx).await?;
        Ok(())
    }

    pub async fn send_message(&self, bytes: Vec<u8>) -> Result<()> {
        let envelope = self.build_authenticated_envelope(bytes).await?;
        self.send_control(&ControlMessage::AuthenticatedText(envelope))
            .await
    }

    pub async fn send_dm(&self, bytes: Vec<u8>) -> Result<()> {
        let envelope = self.build_authenticated_envelope(bytes).await?;
        self.send_control(&ControlMessage::AuthenticatedDm(envelope))
            .await
    }

    async fn build_authenticated_envelope(&self, payload: Vec<u8>) -> Result<Vec<u8>> {
        let key = *self.shared_key.read().await;
        let hmac_key = derive_chat_hmac_key(&key);
        let counter = {
            let mut c = self.chat_send_counter.write().await;
            *c += 1;
            *c
        };
        let auth_msg = MessageAuthenticator::create(&hmac_key, CHAT_HMAC_CHANNEL, counter, payload);
        Ok(serde_json::to_vec(&auth_msg)?)
    }

    pub async fn send_typing(&self) -> Result<()> {
        self.send_control(&ControlMessage::Typing).await
    }

    pub async fn send_display_name(&self, name: String) -> Result<()> {
        self.send_control(&ControlMessage::DisplayName(name)).await
    }

    pub async fn send_transaction_request(
        &self,
        transaction_id: Uuid,
        display_name: String,
        manifest: TransactionManifest,
        total_size: u64,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionRequest {
            transaction_id,
            display_name,
            manifest,
            total_size,
        })
        .await
    }

    pub async fn send_transaction_response(
        &self,
        transaction_id: Uuid,
        accepted: bool,
        dest_path: Option<String>,
        reject_reason: Option<String>,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionResponse {
            transaction_id,
            accepted,
            dest_path,
            reject_reason,
        })
        .await
    }

    pub async fn send_transaction_resume_response(
        &self,
        transaction_id: Uuid,
        accepted: bool,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionResumeResponse {
            transaction_id,
            accepted,
        })
        .await
    }

    pub async fn send_transaction_manifest(
        &self,
        transaction_id: Uuid,
        manifest: TransactionManifest,
        total_size: u64,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionManifest {
            transaction_id,
            manifest,
            total_size,
        })
        .await
    }

    pub async fn send_file_pull_batch_request(
        &self,
        transaction_id: Uuid,
        requests: Vec<FilePullRequestItem>,
    ) -> Result<()> {
        self.send_control(&ControlMessage::FilePullBatchRequest {
            transaction_id,
            requests,
        })
        .await
    }

    pub async fn send_transaction_cancel(
        &self,
        transaction_id: Uuid,
        reason: Option<String>,
    ) -> Result<()> {
        self.send_control(&ControlMessage::TransactionCancel {
            transaction_id,
            reason,
        })
        .await
    }

    pub async fn close(&self) -> Result<()> {
        self.peer_connection.close().await?;
        Ok(())
    }

    pub async fn register_file_destination(&self, file_id: Uuid, dest_path: PathBuf) {
        info!(
            event = "register_file_destination",
            %file_id,
            dest = %dest_path.display(),
            "Registering file destination in accepted_destinations"
        );
        self.accepted_destinations
            .write()
            .await
            .insert(file_id, dest_path);
    }

    pub async fn register_resume_bitmap(&self, file_id: Uuid, bitmap: ChunkBitmap) {
        self.resume_bitmaps.write().await.insert(file_id, bitmap);
    }

    pub async fn initiate_key_rotation(&self) -> Result<()> {
        use crate::core::connection::crypto;

        if self.key_manager.is_none() {
            return Err(anyhow!("No SessionKeyManager - cannot rotate keys"));
        }
        let eph = crypto::prepare_rotation();
        let pub_bytes = eph.public.to_vec();
        *self.pending_rotation.write().await = Some(eph);
        self.send_control(&ControlMessage::KeyRotation {
            ephemeral_pub: pub_bytes,
        })
        .await?;
        info!(
            event = "key_rotation_initiated",
            "Sent ephemeral public key for rotation"
        );
        Ok(())
    }
}

#[inline]
fn make_cipher(key: &[u8; 32]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("Failed to create AES cipher: {}", e))
}
