//! UDP hole-punch data path. Builds on the `nat::stun` + `nat::punch`
//! primitives: gather host + reflexive candidates on a dedicated socket,
//! exchange them via FCM signaling (`PunchOffer`/`PunchAnswer`), punch, then run
//! a driver thread that ferries the very same encrypted `WsFrame::Msg` frames
//! the WS path uses. We register the punched peer in `ws_conns`, so the rest of
//! the engine (send_payload's "WS" branch, send_control_to, the green dot)
//! treats a punched link exactly like a WebSocket — no special-casing.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crate::engine::NetCtx;
use crate::model::{Envelope, WsFrame};
use crate::nat::{punch::hole_punch, stun::stun_binding};
use crate::platform::Platform;
use crate::signal::Candidate;

use super::{drop_live, handle_incoming, mark_live, TransportKind};

const PUNCH_MAGIC: &[u8] = b"mdpunch1";
/// Public STUN server for reflexive-candidate discovery.
const STUN_SERVER: &str = "stun.l.google.com:19302";
/// Punch-connection ids live in a high range so they never collide with WS ids.
static PUNCH_CONN_SEQ: AtomicU64 = AtomicU64::new(1_000_000);

/// Bind a fresh UDP socket and gather this device's candidates on it: a host
/// candidate (our LAN ip + that socket's port) plus a STUN reflexive candidate.
/// The SAME socket must be used to punch so the NAT mapping matches.
pub fn gather_candidates<P: Platform>(ctx: &NetCtx<P>) -> Option<(UdpSocket, Vec<Candidate>)> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let port = socket.local_addr().ok()?.port();
    let my_ip = ctx.identity.lock().unwrap().ip.clone();
    let mut cands = Vec::new();
    if !my_ip.is_empty() && my_ip != "0.0.0.0" {
        cands.push(Candidate { ip: my_ip, port, kind: "host".into() });
    }
    if let Some(server) = resolve_stun() {
        if let Some(refl) = stun_binding(&socket, server) {
            cands.push(Candidate { ip: refl.ip().to_string(), port: refl.port(), kind: "srflx".into() });
        }
    }
    if cands.is_empty() {
        None
    } else {
        Some((socket, cands))
    }
}

fn resolve_stun() -> Option<SocketAddr> {
    STUN_SERVER.to_socket_addrs().ok()?.find(|a| a.is_ipv4())
}

fn to_addrs(cands: &[Candidate]) -> Vec<SocketAddr> {
    cands
        .iter()
        .filter_map(|c| format!("{}:{}", c.ip, c.port).parse().ok())
        .collect()
}

/// Spawn a thread that punches toward `peer_cands` on `socket` and, on success,
/// runs the driver loop. Returns immediately; the link appears as a
/// `PeerConnected` event when it comes up.
pub fn punch_and_run<P: Platform>(ctx: NetCtx<P>, socket: UdpSocket, peer_cands: Vec<Candidate>, node_id: String) {
    std::thread::spawn(move || {
        let addrs = to_addrs(&peer_cands);
        if addrs.is_empty() {
            return;
        }
        if let Some(addr) = hole_punch(&socket, &addrs, PUNCH_MAGIC, Duration::from_secs(8)) {
            run_punch_conn(ctx, socket, addr, node_id);
        }
    });
}

/// Driver loop for an established punched link. Registers an outgoing sender in
/// `ws_conns` and ferries `WsFrame::Msg` frames over the bound UDP path. Exits
/// (and cleans up) when the heartbeat evicts the peer or a newer link replaces it.
fn run_punch_conn<P: Platform>(ctx: NetCtx<P>, socket: UdpSocket, peer_addr: SocketAddr, node_id: String) {
    let (tx, rx) = mpsc::channel::<String>();
    let my_conn_id = PUNCH_CONN_SEQ.fetch_add(1, Ordering::Relaxed);
    {
        let mut g = ctx.ws_conns.lock().unwrap();
        if g.contains_key(&node_id) {
            return; // a link already exists (e.g. WS) — don't clobber it
        }
        g.insert(node_id.clone(), (my_conn_id, tx));
    }
    mark_live(&ctx, &node_id, TransportKind::Punch, Some(peer_addr));
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
    let mut buf = [0u8; 65535];
    loop {
        // Flush queued outgoing frames.
        let mut dead = false;
        while let Ok(frame) = rx.try_recv() {
            if socket.send_to(frame.as_bytes(), peer_addr).is_err() {
                dead = true;
                break;
            }
        }
        if dead {
            break;
        }
        if let Ok((n, src)) = socket.recv_from(&mut buf) {
            if let Ok(WsFrame::Msg { nonce, ciphertext }) = serde_json::from_slice::<WsFrame>(&buf[..n]) {
                let env = Envelope { nonce, ciphertext };
                handle_incoming(&ctx, &env, src.ip().to_string(), "UDP");
            }
        }
        // Stop if a newer link replaced our ws_conns slot, or the heartbeat
        // evicted us for staleness.
        let still_ours = ctx
            .ws_conns
            .lock()
            .unwrap()
            .get(&node_id)
            .map(|(id, _)| *id == my_conn_id)
            .unwrap_or(false);
        if !still_ours || !ctx.p2p_conns.lock().unwrap().contains_key(&node_id) {
            break;
        }
    }
    {
        let mut g = ctx.ws_conns.lock().unwrap();
        if g.get(&node_id).map(|(id, _)| *id == my_conn_id).unwrap_or(false) {
            g.remove(&node_id);
        }
    }
    drop_live(&ctx, &node_id);
}
