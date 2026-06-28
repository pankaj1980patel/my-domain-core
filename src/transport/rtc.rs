//! WebRTC data-channel rung via `str0m` (sans-IO, pure-Rust crypto). The final
//! fallback when even UDP punch fails. Each connection is one `Rtc` + one
//! dedicated `UdpSocket`, driven by a thread that runs the canonical str0m loop.
//! On `ChannelOpen` we register the peer in `ws_conns` with an outgoing sender —
//! so the rest of the engine (send_payload, send_control_to, the green dot)
//! treats it exactly like a WebSocket. The app's encrypted `WsFrame::Msg` rides
//! the channel verbatim; str0m's DTLS is just transport security underneath.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Once;
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

use crate::engine::NetCtx;
use crate::model::{Envelope, WsFrame};
use crate::nat::stun::stun_binding;
use crate::platform::Platform;

use super::{drop_live, handle_incoming, mark_live, TransportKind};

const STUN_SERVER: &str = "stun.l.google.com:19302";
static RTC_CONN_SEQ: AtomicU64 = AtomicU64::new(2_000_000);
static CRYPTO_INIT: Once = Once::new();

fn ensure_crypto() {
    CRYPTO_INIT.call_once(|| {
        str0m::crypto::from_feature_flags().install_process_default();
    });
}

fn resolve(s: &str) -> Option<SocketAddr> {
    s.to_socket_addrs().ok()?.find(|a| a.is_ipv4())
}

/// Bind a UDP socket on our LAN IP and build an `Rtc` with host + reflexive
/// candidates already added (so the generated SDP carries them — no trickle).
fn new_rtc<P: Platform>(ctx: &NetCtx<P>) -> Option<(Rtc, UdpSocket)> {
    ensure_crypto();
    let my_ip = ctx.identity.lock().unwrap().ip.clone();
    let socket = UdpSocket::bind(format!("{my_ip}:0"))
        .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
        .ok()?;
    let local = socket.local_addr().ok()?;
    let mut rtc = Rtc::builder().build(Instant::now());
    if let Ok(host) = Candidate::host(local, "udp") {
        rtc.add_local_candidate(host);
    }
    if let Some(server) = resolve(STUN_SERVER) {
        if let Some(refl) = stun_binding(&socket, server) {
            if let Ok(c) = Candidate::server_reflexive(refl, local, "udp") {
                rtc.add_local_candidate(c);
            }
        }
    }
    Some((rtc, socket))
}

/// Initiator: create an offer with a data channel. Returns the rtc/socket to
/// keep, the pending state, and the serialized offer SDP to signal.
pub fn create_offer<P: Platform>(ctx: &NetCtx<P>) -> Option<(Rtc, UdpSocket, SdpPendingOffer, String)> {
    let (mut rtc, socket) = new_rtc(ctx)?;
    let mut api = rtc.sdp_api();
    api.add_channel("data".to_string());
    let (offer, pending) = api.apply()?;
    let sdp = serde_json::to_string(&offer).ok()?;
    Some((rtc, socket, pending, sdp))
}

/// Initiator: apply the answer SDP and spawn the driver.
pub fn apply_answer_and_run<P: Platform>(
    ctx: NetCtx<P>,
    mut rtc: Rtc,
    socket: UdpSocket,
    pending: SdpPendingOffer,
    answer_sdp: &str,
    node_id: String,
) -> bool {
    let Ok(answer) = serde_json::from_str::<SdpAnswer>(answer_sdp) else {
        return false;
    };
    if rtc.sdp_api().accept_answer(pending, answer).is_err() {
        return false;
    }
    std::thread::spawn(move || drive(ctx, rtc, socket, node_id));
    true
}

/// Responder: accept an offer SDP, spawn the driver, and return the answer SDP.
pub fn accept_offer_and_run<P: Platform>(ctx: NetCtx<P>, offer_sdp: &str, node_id: String) -> Option<String> {
    let offer: SdpOffer = serde_json::from_str(offer_sdp).ok()?;
    let (mut rtc, socket) = new_rtc(&ctx)?;
    let answer = rtc.sdp_api().accept_offer(offer).ok()?;
    let sdp = serde_json::to_string(&answer).ok()?;
    std::thread::spawn(move || drive(ctx, rtc, socket, node_id));
    Some(sdp)
}

/// The canonical str0m drive loop for one connection. Pumps `poll_output` to
/// completion before each input (the cardinal str0m rule), ferries app frames
/// over the data channel, and registers/unregisters the peer's live link.
fn drive<P: Platform>(ctx: NetCtx<P>, mut rtc: Rtc, socket: UdpSocket, node_id: String) {
    let local = socket.local_addr().ok();
    let (tx, rx) = mpsc::channel::<String>();
    let my_conn_id = RTC_CONN_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut cid: Option<ChannelId> = None;
    let mut registered = false;
    let mut buf = vec![0u8; 2000];

    loop {
        if !rtc.is_alive() {
            break;
        }
        // Drain queued outgoing app frames into the data channel (once open).
        if let Some(c) = cid {
            while let Ok(frame) = rx.try_recv() {
                if let Some(mut ch) = rtc.channel(c) {
                    let _ = ch.write(false, frame.as_bytes());
                }
            }
        }

        // Pump all output until str0m asks for a timeout.
        let timeout = loop {
            match rtc.poll_output() {
                Ok(Output::Timeout(t)) => break t,
                Ok(Output::Transmit(t)) => {
                    let _ = socket.send_to(&t.contents, t.destination);
                }
                Ok(Output::Event(e)) => match e {
                    Event::ChannelOpen(id, _) => {
                        cid = Some(id);
                        if !registered {
                            registered = true;
                            ctx.ws_conns.lock().unwrap().insert(node_id.clone(), (my_conn_id, tx.clone()));
                            mark_live(&ctx, &node_id, TransportKind::WebRtc, None);
                        }
                    }
                    Event::ChannelData(data) => {
                        if let Ok(WsFrame::Msg { nonce, ciphertext }) = serde_json::from_slice::<WsFrame>(&data.data) {
                            let env = Envelope { nonce, ciphertext };
                            handle_incoming(&ctx, &env, String::new(), "UDP");
                        }
                    }
                    Event::ChannelClose(_) => rtc.disconnect(),
                    _ => {}
                },
                Err(_) => {
                    cleanup(&ctx, &node_id, my_conn_id, registered);
                    return;
                }
            }
        };

        // Stop if a newer link replaced us or the heartbeat evicted us.
        if registered {
            let still = ctx
                .ws_conns
                .lock()
                .unwrap()
                .get(&node_id)
                .map(|(id, _)| *id == my_conn_id)
                .unwrap_or(false);
            if !still || !ctx.p2p_conns.lock().unwrap().contains_key(&node_id) {
                break;
            }
        }

        // Read one datagram (bounded so we revisit outgoing/eviction promptly).
        let now = Instant::now();
        let dur = if timeout <= now {
            Duration::from_millis(1)
        } else {
            (timeout - now).min(Duration::from_millis(250))
        };
        let _ = socket.set_read_timeout(Some(dur));
        buf.resize(2000, 0);
        match socket.recv_from(&mut buf) {
            Ok((n, source)) => {
                let dest = local.unwrap_or(source);
                if let Ok(contents) = (&buf[..n]).try_into() {
                    let _ = rtc.handle_input(Input::Receive(
                        Instant::now(),
                        Receive { proto: Protocol::Udp, source, destination: dest, contents },
                    ));
                }
            }
            Err(_) => {
                let _ = rtc.handle_input(Input::Timeout(Instant::now()));
            }
        }
    }

    cleanup(&ctx, &node_id, my_conn_id, registered);
}

fn cleanup<P: Platform>(ctx: &NetCtx<P>, node_id: &str, my_conn_id: u64, registered: bool) {
    if !registered {
        return;
    }
    {
        let mut g = ctx.ws_conns.lock().unwrap();
        if g.get(node_id).map(|(id, _)| *id == my_conn_id).unwrap_or(false) {
            g.remove(node_id);
        }
    }
    drop_live(ctx, node_id);
}
