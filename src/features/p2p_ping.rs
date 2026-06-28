//! P2P liveness: a tiny encrypted ping/pong that proves a direct datagram path
//! (UDP / hole-punched) is alive. Receiving either proves the sender reached us,
//! so we mark them live; the engine's heartbeat thread keeps refreshing it and
//! evicts links that go stale. Like the other control messages, the sender's
//! node_id travels in the JSON body (`"from"`) — the carrying envelope's `from`
//! is only a display name.

use crate::engine::NetCtx;
use crate::platform::Platform;
use crate::transport::{mark_live, send_control_to, TransportKind};

use super::{ControlHandler, ControlMsg};

pub struct P2pPingHandler;

impl<P: Platform> ControlHandler<P> for P2pPingHandler {
    fn kinds(&self) -> &'static [&'static str] {
        &["p2p_ping", "p2p_pong"]
    }

    fn handle(&self, ctx: &NetCtx<P>, msg: &ControlMsg) {
        let from = msg.str("from");
        if from.is_empty() {
            return;
        }
        // Either direction proves a live datagram path. `mark_live` also refreshes
        // `last_seen`, so a pong doubles as a heartbeat ack.
        mark_live(ctx, &from, TransportKind::Udp, None);
        if msg.kind() == "p2p_ping" {
            let me = ctx.identity.lock().unwrap().node_id.clone();
            let pong = serde_json::json!({ "type": "p2p_pong", "from": me }).to_string();
            send_control_to(ctx, &from, &pong);
        }
    }
}
