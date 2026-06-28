//! Signaling protocol exchanged between a user's devices via the server's
//! FCM-backed `/signal` relay. These messages coordinate connection setup when
//! a direct path isn't already available; the resulting data channel still uses
//! the existing E2EE transports (the server never sees message content or keys).
//!
//! `sid` correlates a negotiation; punch timing is relative (`start_in_ms`) to
//! avoid wall-clock skew.

use serde::{Deserialize, Serialize};

/// An ICE-style connection candidate.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Candidate {
    pub ip: String,
    pub port: u16,
    /// "host" (LAN) | "srflx" (STUN reflexive)
    pub kind: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Signal {
    /// "open your WS server and tell me when it's reachable".
    StartWs { sid: String },
    /// Sent after `ws_open` is live; the initiator dials this endpoint.
    WsReady { sid: String, ip: String, ws_port: u16 },
    /// Couldn't open a reachable WS (e.g. also firewalled).
    WsUnavailable { sid: String, reason: String },

    /// UDP hole punch: exchange candidates and a relative start time.
    PunchOffer { sid: String, candidates: Vec<Candidate>, start_in_ms: u64 },
    PunchAnswer { sid: String, candidates: Vec<Candidate>, start_in_ms: u64 },
    /// Both sides saw each other's probes; promote to the data channel.
    PunchReady { sid: String },
    /// Punch failed → escalate to TURN.
    PunchFailed { sid: String, reason: String },

    /// TURN relay fallback with ephemeral credentials.
    RelayOffer { sid: String, turn_uri: String, username: String, credential: String },
    RelayAnswer { sid: String },

    /// WebRTC data-channel offer/answer. The `sdp` is a serialized str0m
    /// SdpOffer/SdpAnswer that already embeds the host + reflexive candidates
    /// (no trickle ICE), so the exchange is one message each way.
    SdpOffer { sid: String, sdp: String },
    SdpAnswer { sid: String, sdp: String },

    /// Abort / teardown.
    Bye { sid: String },
}
