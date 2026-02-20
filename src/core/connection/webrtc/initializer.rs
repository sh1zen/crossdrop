//! WebRTC connection initialization: offer/answer, ICE gathering, waiting.

use super::control::{attach_dc_handlers, HandlerContext};
use super::{ConnectionMessage, SignalingMessage, WebRTCConnection};
use crate::core::config::{
    CONNECTION_TIMEOUT, DATA_CHANNEL_TIMEOUT, ICE_GATHER_TIMEOUT, MAX_PENDING_FILE_ACKS,
    SCTP_MAX_MESSAGE_SIZE, SCTP_USE_LOOPBACK,
};
use crate::core::connection::crypto::SessionKeyManager;
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock, Semaphore};
use tokio::time::timeout;
use tracing::{error, info, warn};
use uuid::Uuid;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::{SctpMaxMessageSize, SettingEngine};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_gatherer_state::RTCIceGathererState;
use webrtc::ice_transport::ice_gathering_state::RTCIceGatheringState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

// ── Type Aliases ──────────────────────────────────────────────────────────────

type SharedDc = Arc<RwLock<Option<Arc<RTCDataChannel>>>>;

// ── Connection State Shared Resources ────────────────────────────────────────

/// Shared state for a WebRTC connection being initialized.
struct ConnectionState {
    control_channel: SharedDc,
    data_channel: SharedDc,
    recv_state: Arc<RwLock<HashMap<Uuid, super::ReceiveFileState>>>,
    pending_chunks: Arc<RwLock<HashMap<Uuid, Vec<(u32, Vec<u8>, u64)>>>>,
    accepted_destinations: Arc<RwLock<HashMap<Uuid, std::path::PathBuf>>>,
    resume_bitmaps: Arc<RwLock<HashMap<Uuid, crate::core::pipeline::chunk::ChunkBitmap>>>,
    pending_rotation: Arc<RwLock<Option<crate::core::connection::crypto::EphemeralKeypair>>>,
    chat_send_counter: Arc<RwLock<u64>>,
    chat_recv_counter: Arc<RwLock<u64>>,
    file_ack_semaphore: Arc<Semaphore>,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            control_channel: Arc::new(RwLock::new(None)),
            data_channel: Arc::new(RwLock::new(None)),
            recv_state: Arc::new(RwLock::new(HashMap::new())),
            pending_chunks: Arc::new(RwLock::new(HashMap::new())),
            accepted_destinations: Arc::new(RwLock::new(HashMap::new())),
            resume_bitmaps: Arc::new(RwLock::new(HashMap::new())),
            pending_rotation: Arc::new(RwLock::new(None)),
            chat_send_counter: Arc::new(RwLock::new(0)),
            chat_recv_counter: Arc::new(RwLock::new(0)),
            file_ack_semaphore: Arc::new(Semaphore::new(MAX_PENDING_FILE_ACKS)),
        }
    }

    fn build_context(
        &self,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        remote_access: Arc<tokio::sync::watch::Receiver<bool>>,
        remote_key_listener: Arc<tokio::sync::watch::Receiver<bool>>,
        key_manager: Option<SessionKeyManager>,
        wire_tx: Arc<AtomicU64>,
        wire_rx: Arc<AtomicU64>,
    ) -> HandlerContext {
        HandlerContext {
            recv_state: Arc::clone(&self.recv_state),
            pending_chunks: Arc::clone(&self.pending_chunks),
            accepted_destinations: Arc::clone(&self.accepted_destinations),
            resume_bitmaps: Arc::clone(&self.resume_bitmaps),
            app_tx,
            shared_key,
            remote_access,
            remote_key_listener,
            key_manager,
            pending_rotation: Arc::clone(&self.pending_rotation),
            chat_recv_counter: Arc::clone(&self.chat_recv_counter),
            wire_tx,
            wire_rx,
            file_ack_semaphore: Arc::clone(&self.file_ack_semaphore),
        }
    }

    /// Destructure into a `WebRTCConnection`, consuming self.
    fn into_connection(
        self,
        peer_connection: Arc<RTCPeerConnection>,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        key_manager: Option<SessionKeyManager>,
        wire_tx: Arc<AtomicU64>,
        awake_notify: Arc<tokio::sync::Notify>,
    ) -> WebRTCConnection {
        WebRTCConnection {
            peer_connection,
            control_channel: self.control_channel,
            data_channel: self.data_channel,
            app_tx,
            accepted_destinations: self.accepted_destinations,
            resume_bitmaps: self.resume_bitmaps,
            shared_key,
            key_manager,
            pending_rotation: self.pending_rotation,
            chat_send_counter: self.chat_send_counter,
            wire_tx,
            awake_notify,
            file_ack_semaphore: self.file_ack_semaphore,
        }
    }
}

// ── WebRTC API Configuration ─────────────────────────────────────────────────

impl WebRTCConnection {
    fn default_ice_servers() -> Vec<RTCIceServer> {
        vec![
            RTCIceServer {
                urls: vec!["stun:stun.l.google.com:19302".into()],
                username: String::new(),
                credential: String::new(),
            },
            RTCIceServer {
                urls: vec!["turn:openrelay.metered.ca:80".into()],
                username: "openrelayproject".into(),
                credential: "openrelayproject".into(),
            },
        ]
    }

    async fn create_webrtc_api() -> Result<webrtc::api::API> {
        let mut me = MediaEngine::default();
        let reg = register_default_interceptors(Registry::new(), &mut me)?;

        let mut se = SettingEngine::default();
        se.set_sctp_max_message_size_can_send(SctpMaxMessageSize::Bounded(SCTP_MAX_MESSAGE_SIZE));
        se.set_include_loopback_candidate(SCTP_USE_LOOPBACK);

        Ok(APIBuilder::new()
            .with_setting_engine(se)
            .with_media_engine(me)
            .with_interceptor_registry(reg)
            .build())
    }

    /// Inject `a=max-message-size:SIZE` into SDP if not already present.
    fn inject_max_message_size(mut desc: RTCSessionDescription) -> RTCSessionDescription {
        if !desc.sdp.contains("a=max-message-size:") {
            desc.sdp
                .push_str(&format!("a=max-message-size:{}\r\n", SCTP_MAX_MESSAGE_SIZE));
        }
        desc
    }

    /// Create a new peer connection with default ICE servers.
    async fn new_peer_connection(api: &webrtc::api::API) -> Result<Arc<RTCPeerConnection>> {
        Ok(Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers: Self::default_ice_servers(),
                ..Default::default()
            })
            .await?,
        ))
    }
}

// ── ICE Gathering ─────────────────────────────────────────────────────────────

impl WebRTCConnection {
    pub async fn gather_local_description(pc: &Arc<RTCPeerConnection>) -> Result<String> {
        // Fast path: already complete.
        if pc.ice_gathering_state() == RTCIceGatheringState::Complete {
            return Self::get_serialized_local_description(pc).await;
        }

        let (tx, rx) = oneshot::channel::<()>();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));

        pc.on_ice_gathering_state_change(Box::new(move |state| {
            let tx = Arc::clone(&tx);
            Box::pin(async move {
                if state == RTCIceGathererState::Complete {
                    if let Ok(mut guard) = tx.lock() {
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(());
                        }
                    }
                }
            })
        }));

        // Double-check after registering handler to avoid a race.
        if pc.ice_gathering_state() == RTCIceGatheringState::Complete {
            return Self::get_serialized_local_description(pc).await;
        }

        timeout(ICE_GATHER_TIMEOUT, rx)
            .await
            .context("ICE gathering timeout")?
            .context("ICE gathering channel closed")?;

        Self::get_serialized_local_description(pc).await
    }

    async fn get_serialized_local_description(pc: &Arc<RTCPeerConnection>) -> Result<String> {
        let desc = pc
            .local_description()
            .await
            .ok_or_else(|| anyhow!("No local description after ICE gathering"))?;
        Ok(serde_json::to_string(&Self::inject_max_message_size(desc))?)
    }
}

// ── Connection State Change Handler ──────────────────────────────────────────

fn setup_connection_state_monitor(
    pc: &Arc<RTCPeerConnection>,
    app_tx: &Option<mpsc::UnboundedSender<ConnectionMessage>>,
    role: &'static str,
) {
    let Some(tx) = app_tx.clone() else { return };

    pc.on_peer_connection_state_change(Box::new(move |s| {
        let tx = tx.clone();
        Box::pin(async move {
            match s {
                RTCPeerConnectionState::Connected => {
                    info!(
                        event = "webrtc_connected",
                        role, "WebRTC connection established"
                    );
                }
                RTCPeerConnectionState::Failed => {
                    error!(event = "webrtc_failed", role, "WebRTC connection failed");
                    let _ = tx.send(ConnectionMessage::Disconnected);
                }
                RTCPeerConnectionState::Disconnected => {
                    warn!(
                        event = "webrtc_disconnected",
                        role, "WebRTC transient disconnect (ICE may recover)"
                    );
                }
                RTCPeerConnectionState::Closed => {
                    info!(
                        event = "webrtc_closed",
                        role, "WebRTC connection closed (locally initiated)"
                    );
                }
                _ => {}
            }
        })
    }));
}

// ── Data Channel Helpers ──────────────────────────────────────────────────────

/// Ordered, reliable data channel init (shared by both channels).
fn ordered_dc_init() -> RTCDataChannelInit {
    RTCDataChannelInit {
        ordered: Some(true),
        ..Default::default()
    }
}

/// Decode a `SignalingMessage` variant into its inner SDP string.
fn expect_sdp(msg: SignalingMessage, expected: &'static str) -> Result<RTCSessionDescription> {
    let sdp = match (&msg, expected) {
        (SignalingMessage::Offer(_), "Offer") => {
            let SignalingMessage::Offer(s) = msg else {
                unreachable!()
            };
            s
        }
        (SignalingMessage::Answer(_), "Answer") => {
            let SignalingMessage::Answer(s) = msg else {
                unreachable!()
            };
            s
        }
        _ => return Err(anyhow!("Expected {}", expected)),
    };
    Ok(serde_json::from_str(&sdp)?)
}

// ── Offer / Answer ────────────────────────────────────────────────────────────

impl WebRTCConnection {
    pub async fn create_offer(
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        key_manager: Option<SessionKeyManager>,
        remote_access: tokio::sync::watch::Receiver<bool>,
        remote_key_listener: tokio::sync::watch::Receiver<bool>,
        awake_notify: Arc<tokio::sync::Notify>,
        wire_tx: Arc<AtomicU64>,
        wire_rx: Arc<AtomicU64>,
    ) -> Result<(Self, SignalingMessage)> {
        let api = Self::create_webrtc_api().await?;
        let pc = Self::new_peer_connection(&api).await?;

        setup_connection_state_monitor(&pc, &app_tx, "offerer");

        let state = ConnectionState::new();
        let ra = Arc::new(remote_access);
        let rkl = Arc::new(remote_key_listener);
        let ctx = state.build_context(
            app_tx.clone(),
            Arc::clone(&shared_key),
            Arc::clone(&ra),
            Arc::clone(&rkl),
            key_manager.clone(),
            Arc::clone(&wire_tx),
            Arc::clone(&wire_rx),
        );

        let dc_init = ordered_dc_init();
        let cdc = pc
            .create_data_channel("control", Some(dc_init.clone()))
            .await?;
        attach_dc_handlers(&cdc, ctx.clone()).await;
        *state.control_channel.write().await = Some(cdc);

        let ddc = pc.create_data_channel("data", Some(dc_init)).await?;
        attach_dc_handlers(&ddc, ctx).await;
        *state.data_channel.write().await = Some(ddc);

        let offer = pc.create_offer(None).await?;
        pc.set_local_description(offer).await?;
        let gathered_sdp = Self::gather_local_description(&pc).await?;

        let conn =
            state.into_connection(pc, app_tx, shared_key, key_manager, wire_tx, awake_notify);
        Ok((conn, SignalingMessage::Offer(gathered_sdp)))
    }

    pub async fn accept_offer(
        offer: SignalingMessage,
        app_tx: Option<mpsc::UnboundedSender<ConnectionMessage>>,
        shared_key: Arc<RwLock<[u8; 32]>>,
        key_manager: Option<SessionKeyManager>,
        remote_access: tokio::sync::watch::Receiver<bool>,
        remote_key_listener: tokio::sync::watch::Receiver<bool>,
        awake_notify: Arc<tokio::sync::Notify>,
        wire_tx: Arc<AtomicU64>,
        wire_rx: Arc<AtomicU64>,
    ) -> Result<(Self, SignalingMessage)> {
        let api = Self::create_webrtc_api().await?;
        let pc = Self::new_peer_connection(&api).await?;

        setup_connection_state_monitor(&pc, &app_tx, "answerer");

        let state = ConnectionState::new();
        let ra = Arc::new(remote_access);
        let rkl = Arc::new(remote_key_listener);
        let ctx = state.build_context(
            app_tx.clone(),
            Arc::clone(&shared_key),
            Arc::clone(&ra),
            Arc::clone(&rkl),
            key_manager.clone(),
            Arc::clone(&wire_tx),
            Arc::clone(&wire_rx),
        );

        // Answerer receives data channels created by the offerer.
        {
            let control_channel = Arc::clone(&state.control_channel);
            let data_channel = Arc::clone(&state.data_channel);
            pc.on_data_channel(Box::new(move |dc| {
                let control_channel = Arc::clone(&control_channel);
                let data_channel = Arc::clone(&data_channel);
                let ctx = ctx.clone();
                Box::pin(async move {
                    attach_dc_handlers(&dc, ctx).await;
                    match dc.label() {
                        "control" => *control_channel.write().await = Some(dc),
                        "data" => *data_channel.write().await = Some(dc),
                        _ => {}
                    }
                })
            }));
        }

        let desc = expect_sdp(offer, "Offer")?;
        pc.set_remote_description(desc).await?;

        let answer = pc.create_answer(None).await?;
        pc.set_local_description(answer).await?;
        let gathered_sdp = Self::gather_local_description(&pc).await?;

        let conn =
            state.into_connection(pc, app_tx, shared_key, key_manager, wire_tx, awake_notify);
        Ok((conn, SignalingMessage::Answer(gathered_sdp)))
    }

    pub async fn set_answer(&self, answer: SignalingMessage) -> Result<()> {
        let desc = expect_sdp(answer, "Answer")?;
        self.peer_connection.set_remote_description(desc).await?;
        Ok(())
    }
}

// ── Wait Helpers ──────────────────────────────────────────────────────────────

impl WebRTCConnection {
    pub async fn wait_connected(&self) -> Result<()> {
        if self.peer_connection.connection_state() == RTCPeerConnectionState::Connected {
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel(1);
        self.peer_connection
            .on_peer_connection_state_change(Box::new(move |s| {
                let tx = tx.clone();
                Box::pin(async move {
                    if s == RTCPeerConnectionState::Connected {
                        let _ = tx.send(()).await;
                    }
                })
            }));

        timeout(CONNECTION_TIMEOUT, rx.recv())
            .await
            .context("Connection timeout")?;
        Ok(())
    }

    pub async fn wait_data_channels_open(&self) -> Result<()> {
        let (cdc, ddc) = self.wait_for_channels().await?;
        self.wait_channel_open(&cdc).await?;
        self.wait_channel_open(&ddc).await?;
        Ok(())
    }

    async fn wait_for_channels(&self) -> Result<(Arc<RTCDataChannel>, Arc<RTCDataChannel>)> {
        let deadline = std::time::Instant::now() + DATA_CHANNEL_TIMEOUT;
        loop {
            {
                let cdc = self.control_channel.read().await.clone();
                let ddc = self.data_channel.read().await.clone();
                if let (Some(c), Some(d)) = (cdc, ddc) {
                    return Ok((c, d));
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(anyhow!("Data channels not created within timeout"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_channel_open(&self, dc: &Arc<RTCDataChannel>) -> Result<()> {
        /// Check the current state, returning `Ok(true)` if open, `Ok(false)`
        /// if still connecting, or `Err` if permanently closed.
        fn check_state(dc: &Arc<RTCDataChannel>) -> Result<bool> {
            match dc.ready_state() {
                RTCDataChannelState::Open => Ok(true),
                RTCDataChannelState::Closed => Err(anyhow!(
                    "DataChannel '{}' is permanently closed",
                    dc.label()
                )),
                _ => Ok(false),
            }
        }

        if check_state(dc)? {
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel(1);
        dc.on_open(Box::new(move || {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(()).await;
            })
        }));

        // Re-check after registering to close the TOCTOU window.
        if check_state(dc)? {
            return Ok(());
        }

        match timeout(DATA_CHANNEL_TIMEOUT, rx.recv()).await {
            Ok(_) => Ok(()),
            Err(_) => match dc.ready_state() {
                RTCDataChannelState::Open => Ok(()),
                RTCDataChannelState::Closed => Err(anyhow!(
                    "DataChannel '{}' is permanently closed",
                    dc.label()
                )),
                state => Err(anyhow!(
                    "DataChannel '{}' open timeout (state: {:?})",
                    dc.label(),
                    state
                )),
            },
        }
    }
}
