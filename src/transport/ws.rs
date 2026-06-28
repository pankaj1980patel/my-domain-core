//! WebSocket transport: a persistent, bidirectional connection. Whichever side
//! can reach the other "triggers" it; thereafter messages flow both ways over
//! the single socket. One connection per peer (duplicates are dropped).

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use tungstenite::Message as WsMessage;

use crate::engine::NetCtx;
use crate::events::CoreEvent;
use crate::model::{Envelope, WsFrame};
use crate::platform::Platform;

use super::{handle_incoming, mark_live, drop_live, TransportKind};

static WS_CONN_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn ws_server_loop<P: Platform>(listener: TcpListener, ctx: NetCtx<P>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        if let Ok(ws) = tungstenite::accept(stream) {
            let ctx = ctx.clone();
            std::thread::spawn(move || handle_ws_conn(ws, ctx));
        }
    }
}

pub fn handle_ws_conn<S: Read + Write, P: Platform>(mut ws: tungstenite::WebSocket<S>, ctx: NetCtx<P>) {
    // Announce ourselves.
    {
        let id = ctx.identity.lock().unwrap();
        let hello = serde_json::to_string(&WsFrame::Hello {
            node_id: id.node_id.clone(),
            name: id.name.clone(),
        })
        .unwrap_or_default();
        let _ = ws.send(WsMessage::Text(hello));
    }
    let (tx, rx) = mpsc::channel::<String>();
    let my_conn_id = WS_CONN_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut peer_id: Option<String> = None;

    loop {
        match ws.read() {
            Ok(WsMessage::Text(t)) => {
                if let Ok(frame) = serde_json::from_str::<WsFrame>(&t) {
                    match frame {
                        WsFrame::Hello { node_id, .. } => {
                            // One socket per peer: drop a duplicate connection.
                            let mut guard = ctx.ws_conns.lock().unwrap();
                            if guard.contains_key(&node_id) {
                                break;
                            }
                            guard.insert(node_id.clone(), (my_conn_id, tx.clone()));
                            drop(guard);
                            ctx.sink.emit(CoreEvent::WsConnected { node_id: node_id.clone() });
                            mark_live(&ctx, &node_id, TransportKind::Ws, None);
                            peer_id = Some(node_id);
                        }
                        WsFrame::Msg { nonce, ciphertext } => {
                            let env = Envelope { nonce, ciphertext };
                            handle_incoming(&ctx, &env, String::new(), "WS");
                        }
                    }
                }
            }
            Ok(WsMessage::Close(_)) => break,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        // Flush any queued outgoing frames.
        let mut dead = false;
        while let Ok(out) = rx.try_recv() {
            if ws.send(WsMessage::Text(out)).is_err() {
                dead = true;
                break;
            }
        }
        if dead {
            break;
        }
    }
    // Only remove our own entry (a newer connection may have replaced it).
    if let Some(pid) = peer_id {
        let mut g = ctx.ws_conns.lock().unwrap();
        if g.get(&pid).map(|(id, _)| *id == my_conn_id).unwrap_or(false) {
            g.remove(&pid);
            drop(g);
            ctx.sink.emit(CoreEvent::WsDisconnected { node_id: pid.clone() });
            drop_live(&ctx, &pid);
        }
    }
}

/// Dial a peer's WebSocket listener (the "trigger").
pub fn ws_connect<P: Platform>(ctx: NetCtx<P>, ip: &str, ws_port: u16) -> Result<(), String> {
    let addr: Ipv4Addr = ip.parse().map_err(|_| "bad peer ip")?;
    let stream = TcpStream::connect_timeout(
        &SocketAddr::new(addr.into(), ws_port),
        Duration::from_secs(4),
    )
    .map_err(|e| format!("WS connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| e.to_string())?;
    let req = format!("ws://{ip}:{ws_port}/");
    let (ws, _resp) =
        tungstenite::client(req.as_str(), stream).map_err(|e| format!("WS handshake failed: {e}"))?;
    std::thread::spawn(move || handle_ws_conn(ws, ctx));
    Ok(())
}
