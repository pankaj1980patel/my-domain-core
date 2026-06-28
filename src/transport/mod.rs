//! Direct messaging transports (UDP / TCP) plus the shared incoming-message
//! pipeline and the clipboard control-message handling. WebSocket lives in the
//! `ws` submodule.
//!
//! Wire format here is protocol v1 (JSON `Envelope` carrying `Plaintext`); the
//! binary multiplexed framing (v2) is layered on later in `wire::`.

pub mod punch;
#[cfg(feature = "webrtc")]
pub mod rtc;
pub mod ws;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::crypto::{decrypt, encrypt};
use crate::engine::{KeyHolder, NetCtx, WsConns};
use crate::events::CoreEvent;
use crate::model::{Envelope, IncomingMessage, Plaintext, WsFrame};
use crate::platform::Platform;
use crate::discovery::PeerMap;

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Unified live-connection model — the single source of truth for "who is
// connected, over what transport". The UI green dot reads ONLY this.
// ---------------------------------------------------------------------------

/// Which transport a live P2P link is using. Serializes lowercase for the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Ws,
    Udp,
    Punch,
    WebRtc,
}

/// A live peer-to-peer link. `last_seen` drives heartbeat staleness for the
/// connectionless transports (UDP/Punch/WebRtc); WS is event-driven.
#[derive(Clone)]
pub struct P2pConn {
    pub kind: TransportKind,
    pub last_seen: u64,
    pub addr: Option<SocketAddr>,
}

/// node_id -> live link.
pub type P2pConns = Arc<Mutex<HashMap<String, P2pConn>>>;

/// Mark a peer live (first time) or refresh an existing link. The transport is
/// fixed at establishment by whoever created the link (ws/punch/webrtc); a
/// refresh (e.g. a heartbeat ping) only bumps `last_seen` and never downgrades
/// the kind. Emits `PeerConnected` only on first appearance. Never emits under
/// the lock.
pub fn mark_live<P: Platform>(ctx: &NetCtx<P>, node_id: &str, kind: TransportKind, addr: Option<SocketAddr>) {
    let newly = {
        let mut m = ctx.p2p_conns.lock().unwrap();
        match m.get_mut(node_id) {
            Some(c) => {
                c.last_seen = now_secs();
                if addr.is_some() {
                    c.addr = addr;
                }
                false
            }
            None => {
                m.insert(node_id.to_string(), P2pConn { kind, last_seen: now_secs(), addr });
                true
            }
        }
    };
    if newly {
        ctx.sink.emit(CoreEvent::PeerConnected { node_id: node_id.to_string(), transport: kind });
    }
}

/// Refresh `last_seen` for an existing live peer (e.g. on pong/keepalive).
pub fn touch_live<P: Platform>(ctx: &NetCtx<P>, node_id: &str) {
    if let Some(c) = ctx.p2p_conns.lock().unwrap().get_mut(node_id) {
        c.last_seen = now_secs();
    }
}

/// Drop a peer's live link. Emits `PeerDisconnected` if it was present.
pub fn drop_live<P: Platform>(ctx: &NetCtx<P>, node_id: &str) {
    let removed = ctx.p2p_conns.lock().unwrap().remove(node_id).is_some();
    if removed {
        ctx.sink.emit(CoreEvent::PeerDisconnected { node_id: node_id.to_string() });
    }
}

/// Snapshot of live peers and their transports.
pub fn live_peers<P: Platform>(ctx: &NetCtx<P>) -> Vec<(String, TransportKind, Option<SocketAddr>)> {
    ctx.p2p_conns
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.kind, v.addr))
        .collect()
}

/// Snapshot of live peers with their `last_seen` — for heartbeat staleness checks.
pub fn live_snapshot<P: Platform>(ctx: &NetCtx<P>) -> Vec<(String, TransportKind, u64)> {
    ctx.p2p_conns
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.kind, v.last_seen))
        .collect()
}

/// Decrypt an envelope into a UI message; undecryptable messages are surfaced
/// (not silently dropped).
fn envelope_to_message(key: &KeyHolder, env: &Envelope, ip: String, protocol: &str) -> IncomingMessage {
    if let Some(k) = key.lock().unwrap().as_ref() {
        if let Some(pt) = decrypt(k, env) {
            if let Ok(msg) = serde_json::from_slice::<Plaintext>(&pt) {
                return IncomingMessage {
                    from: msg.from,
                    ip,
                    protocol: protocol.into(),
                    text: msg.text,
                    ts: now_secs(),
                    ok: true,
                };
            }
        }
    }
    IncomingMessage {
        from: "(unknown)".into(),
        ip,
        protocol: protocol.into(),
        text: "🔒 message could not be decrypted (wrong encryption key)".into(),
        ts: now_secs(),
        ok: false,
    }
}

/// Pick the transport for a message to `node_id`. Any live persistent channel —
/// WebSocket, UDP hole-punch, or WebRTC, all of which register in `ws_conns` and
/// share its `"WS"` framed send path — is always preferred so exchanges ride the
/// active connection. With no such channel, fall back to the user's directed
/// transport preference (`UDP` default, or `TCP`). This is the single chooser
/// used by chat send and every discrete feature.
pub fn best_proto(ws_conns: &WsConns, directed: &str, node_id: &str) -> &'static str {
    if ws_conns.lock().unwrap().contains_key(node_id) {
        "WS"
    } else if directed.trim().eq_ignore_ascii_case("tcp") {
        "TCP"
    } else {
        "UDP"
    }
}

/// `best_proto` for a `NetCtx` (reads the engine's directed-transport setting).
fn clip_proto<P: Platform>(ctx: &NetCtx<P>, node_id: &str) -> &'static str {
    let directed = ctx.directed_transport.lock().unwrap().clone();
    best_proto(&ctx.ws_conns, &directed, node_id)
}

/// Send an already-built control-message JSON to one peer over the active
/// connection (live WS/punch/WebRTC), else the directed transport. Shared by
/// every discrete feature.
pub(crate) fn send_control_to<P: Platform>(ctx: &NetCtx<P>, node_id: &str, text: &str) {
    let from = ctx.identity.lock().unwrap().name.clone();
    let proto = clip_proto(ctx, node_id);
    let _ = send_payload(&ctx.peers, &ctx.ws_conns, &ctx.key, &from, node_id, proto, text);
}

/// Broadcast a control-message JSON to all known peers.
pub fn broadcast_control<P: Platform>(ctx: &NetCtx<P>, text: &str) {
    let ids: Vec<String> = ctx.peers.lock().unwrap().keys().cloned().collect();
    for id in ids {
        send_control_to(ctx, &id, text);
    }
}

/// Decrypt and dispatch an incoming envelope. Clipboard control messages are
/// handled in-band (never shown as chat); everything else is emitted as a
/// normal `MessageReceived`.
pub fn handle_incoming<P: Platform>(ctx: &NetCtx<P>, env: &Envelope, ip: String, protocol: &str) {
    let pt = {
        let guard = ctx.key.lock().unwrap();
        guard.as_ref().and_then(|k| decrypt(k, env))
    };
    let Some(pt) = pt else {
        ctx.sink
            .emit(CoreEvent::MessageReceived(envelope_to_message(&ctx.key, env, ip, protocol)));
        return;
    };
    let Ok(msg) = serde_json::from_slice::<Plaintext>(&pt) else {
        return;
    };

    // Discrete-feature control message? (clipboard / notification / call / …)
    let control = ctx.control.clone();
    if control.dispatch(ctx, &msg.from, &ip, protocol, &msg.text) {
        return;
    }

    ctx.sink.emit(CoreEvent::MessageReceived(IncomingMessage {
        from: msg.from,
        ip,
        protocol: protocol.into(),
        text: msg.text,
        ts: now_secs(),
        ok: true,
    }));
}

/// Encrypt `text` and send it to `node_id` over the given transport. Shared by
/// the chat send command and the clipboard helpers.
pub fn send_payload(
    peers: &PeerMap,
    ws_conns: &WsConns,
    key: &KeyHolder,
    from: &str,
    node_id: &str,
    protocol: &str,
    text: &str,
) -> Result<(), String> {
    let k = key.lock().unwrap().ok_or("set your encryption key first")?;
    let plaintext = serde_json::to_vec(&Plaintext { from: from.to_string(), text: text.to_string() })
        .map_err(|e| e.to_string())?;
    let env = encrypt(&k, &plaintext).ok_or("encryption failed")?;
    let body = serde_json::to_vec(&env).map_err(|e| e.to_string())?;

    let proto = protocol.to_uppercase();
    if proto == "WS" {
        let frame = serde_json::to_string(&WsFrame::Msg {
            nonce: env.nonce.clone(),
            ciphertext: env.ciphertext.clone(),
        })
        .map_err(|e| e.to_string())?;
        let sender = ws_conns
            .lock()
            .unwrap()
            .get(node_id)
            .map(|(_, s)| s.clone())
            .ok_or("no WebSocket connection — trigger 'Connect (WS)' first")?;
        sender.send(frame).map_err(|_| "WebSocket connection closed".to_string())?;
        return Ok(());
    }

    let peer = peers.lock().unwrap().get(node_id).cloned().ok_or("peer not found")?;
    let ip: Ipv4Addr = peer.ip.parse().map_err(|_| "bad peer ip")?;
    match proto.as_str() {
        "TCP" => {
            let addr = SocketAddr::new(ip.into(), peer.tcp_port);
            let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("TCP connect failed: {e}"))?;
            stream.write_all(&body).map_err(|e| format!("TCP send failed: {e}"))?;
            stream.shutdown(std::net::Shutdown::Write).map_err(|e| e.to_string())?;
            Ok(())
        }
        "UDP" => {
            let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
            socket
                .send_to(&body, SocketAddr::new(ip.into(), peer.udp_port))
                .map_err(|e| format!("UDP send failed: {e}"))?;
            Ok(())
        }
        other => Err(format!("unknown protocol: {other}")),
    }
}

pub fn tcp_recv_loop<P: Platform>(listener: TcpListener, ctx: NetCtx<P>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let ip = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
            let mut buf = Vec::new();
            if stream.read_to_end(&mut buf).is_err() {
                return;
            }
            if let Ok(env) = serde_json::from_slice::<Envelope>(&buf) {
                handle_incoming(&ctx, &env, ip, "TCP");
            }
        });
    }
}

pub fn udp_recv_loop<P: Platform>(socket: UdpSocket, ctx: NetCtx<P>) {
    let mut buf = [0u8; 65535];
    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Ok(env) = serde_json::from_slice::<Envelope>(&buf[..len]) {
            handle_incoming(&ctx, &env, src.ip().to_string(), "UDP");
        }
    }
}
