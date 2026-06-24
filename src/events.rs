//! UI-bound events and the sink that delivers them. This unifies the two very
//! different delivery models:
//!   * desktop bridges each event to a Tauri `app.emit(...)` (push),
//!   * android records events into an inbox/snapshot drained by JNI poll calls.
//!
//! The Engine only ever calls `EventSink::emit`; the adapter decides how it
//! reaches the UI.

use crate::model::{IncomingMessage, Peer};

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
}

pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, ev: CoreEvent);
}
