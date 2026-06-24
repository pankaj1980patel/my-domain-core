//! Wire protocol + shared data model. These structs are serialized to JSON and
//! must stay byte-compatible across desktop, android, and the registry server.

use serde::{Deserialize, Serialize};

/// This device's own endpoints, advertised to peers and the registry.
#[derive(Clone, Serialize)]
pub struct Identity {
    pub node_id: String,
    pub name: String,
    pub ip: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub ws_port: u16,
}

/// LAN discovery beacon (UDP datagram body).
#[derive(Serialize, Deserialize)]
pub struct Beacon {
    pub node_id: String,
    pub name: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub ws_port: u16,
    #[serde(default)]
    pub reply: bool,
}

/// Where a peer entry came from. Serializes to "registry" | "lan" | "manual"
/// to stay compatible with the existing frontend / Kotlin JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Registry,
    Lan,
    Manual,
}

/// A known peer device.
#[derive(Clone, Serialize)]
pub struct Peer {
    pub node_id: String,
    pub name: String,
    pub ip: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub ws_port: u16,
    pub source: Source,
}

/// Decrypted message body.
#[derive(Serialize, Deserialize)]
pub struct Plaintext {
    pub from: String,
    pub text: String,
}

/// Encrypted on-the-wire envelope (TCP/UDP body, and WS `msg` frames).
#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub nonce: String,
    pub ciphertext: String,
}

/// A message surfaced to the UI.
#[derive(Clone, Serialize)]
pub struct IncomingMessage {
    pub from: String,
    pub ip: String,
    pub protocol: String,
    pub text: String,
    pub ts: u64,
    pub ok: bool,
}

/// WebSocket frames (legacy protocol v1; v2 framing lives in `wire::frame`).
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsFrame {
    #[serde(rename = "hello")]
    Hello { node_id: String, name: String },
    #[serde(rename = "msg")]
    Msg { nonce: String, ciphertext: String },
}
