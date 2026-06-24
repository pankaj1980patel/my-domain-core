//! Service framework scaffolding.
//!
//! Every shareable feature (messaging, clipboard, notifications, call history,
//! and later audio/video + remote control) is a `Service` plugged into a peer
//! `Connection`. A Service asks the connection for a channel of the reliability
//! class it needs and never touches transports directly.
//!
//! NOTE: this is the seam only. The channel-mux `Connection` + binary framing
//! (protocol v2) and the concrete service impls land in a later focused pass;
//! today's messaging/clipboard still run through the v1 pipeline in `transport`.

/// Stable on-the-wire identifier for a service (one byte in the v2 frame header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceId {
    Messaging = 0,
    Clipboard = 1,
    Notification = 2,
    CallHistory = 3,
    Av = 4,
    RemoteControl = 5,
}

/// Channel delivery class. Reliable rides WS/TCP; datagram rides UDP and is
/// drop-tolerant (audio/video frames).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reliability {
    Reliable,
    Datagram,
}

/// Opaque per-connection channel handle (assigned by the mux).
pub type ChannelId = u16;

/// A feature plugged into the engine. Implementors handle their own framed
/// payloads and may open channels back to the peer.
pub trait Service: Send + Sync {
    fn id(&self) -> ServiceId;
    /// Handle a decrypted payload addressed to this service on `chan`.
    fn on_frame(&self, node_id: &str, chan: ChannelId, data: &[u8]);
}
