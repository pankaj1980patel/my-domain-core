//! UI-bound events and the sink that delivers them. This unifies the two very
//! different delivery models:
//!   * desktop bridges each event to a Tauri `app.emit(...)` (push),
//!   * android records events into an inbox/snapshot drained by JNI poll calls.
//!
//! The Engine only ever calls `EventSink::emit`; the adapter decides how it
//! reaches the UI.

use crate::model::{IncomingMessage, Peer};
use crate::transport::TransportKind;

#[derive(Clone)]
pub enum CoreEvent {
    /// The peer list changed (discovery, registry refresh, manual add/remove).
    PeersUpdated { peers: Vec<Peer> },
    /// A decrypted (or undecryptable) chat message arrived.
    MessageReceived(IncomingMessage),
    /// A WebSocket connection to a peer was established.
    WsConnected { node_id: String },
    /// A WebSocket connection to a peer closed.
    WsDisconnected { node_id: String },
    /// A live peer-to-peer connection came up (over any transport). This is the
    /// single source of truth for the UI "connected" (green) indicator.
    PeerConnected { node_id: String, transport: TransportKind },
    /// A live peer-to-peer connection went away (closed or went stale).
    PeerDisconnected { node_id: String },
    /// Progress of an in-flight `connect()` ladder, for UI feedback.
    ConnectProgress { node_id: String, stage: String, detail: Option<String> },
    /// A clipboard value was synced from a peer (active mode).
    Clipboard {
        from: String,
        ip: String,
        protocol: String,
        action: String,
    },
    /// A peer shared an OS notification.
    Notification {
        from: String,
        title: String,
        body: String,
        app: Option<String>,
    },
    /// A peer shared an incoming/missed/ended call notification.
    CallNotification {
        from: String,
        caller: String,
        number: Option<String>,
        /// "ringing" | "missed" | "ended" | …
        state: String,
    },
    /// A peer shared call-history entries (opaque JSON payload).
    CallHistory {
        from: String,
        entries: serde_json::Value,
    },
    /// A producer device returned its shareable app list + which of them this
    /// device is currently subscribed to.
    AppsList {
        from: String,
        apps: serde_json::Value,       // [{ "pkg": ..., "label": ... }]
        subscribed: serde_json::Value, // [ "pkg", ... ]
    },
}

pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, ev: CoreEvent);
}
