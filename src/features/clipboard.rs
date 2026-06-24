//! Clipboard sharing: active push (`clipboard`) plus passive pull
//! (`clipboard_request` / `clipboard_response`).

use std::sync::atomic::Ordering;

use crate::engine::NetCtx;
use crate::events::CoreEvent;
use crate::platform::Platform;
use crate::transport::send_control_to;

use super::{ControlHandler, ControlMsg};

pub struct ClipboardHandler;

impl<P: Platform> ControlHandler<P> for ClipboardHandler {
    fn kinds(&self) -> &'static [&'static str] {
        &["clipboard", "clipboard_request", "clipboard_response"]
    }

    fn handle(&self, ctx: &NetCtx<P>, msg: &ControlMsg) {
        match msg.kind() {
            // Unsolicited push from a peer in active mode: only apply if we too
            // have auto-sync enabled and a clipboard.
            "clipboard" => {
                if ctx.clip_active.load(Ordering::Relaxed) {
                    if let Some(clip) = ctx.platform.clipboard() {
                        let c = msg.str("content");
                        *ctx.clip_last.lock().unwrap() = c.clone();
                        clip.set(&c);
                        ctx.sink.emit(CoreEvent::Clipboard {
                            from: msg.from.to_string(),
                            ip: msg.ip.to_string(),
                            protocol: msg.protocol.to_string(),
                            action: "synced".into(),
                        });
                    }
                }
            }
            // A peer is pulling our clipboard: reply with the current value.
            "clipboard_request" => {
                let requester = msg.str("from");
                if !requester.is_empty() {
                    let me = ctx.identity.lock().unwrap().node_id.clone();
                    let current = ctx.platform.clipboard().and_then(|c| c.get()).unwrap_or_default();
                    let resp = serde_json::json!({
                        "type": "clipboard_response",
                        "content": current,
                        "from": me,
                    })
                    .to_string();
                    send_control_to(ctx, &requester, &resp);
                }
            }
            // Reply to a pull we initiated: hand it to the waiting command.
            "clipboard_response" => {
                if let Some(tx) = ctx.clip_pending.lock().unwrap().remove(&msg.str("from")) {
                    let _ = tx.send(msg.str("content"));
                }
            }
            _ => {}
        }
    }
}
