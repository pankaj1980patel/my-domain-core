//! Discrete-feature layer: small, reliable control messages that ride inside the
//! encrypted `Plaintext.text` as a JSON object with a `"type"` tag.
//!
//! Each feature lives in its own file and exposes a [`ControlHandler`]. Handlers
//! register into a [`ControlRegistry`] keyed by the `"type"` value(s) they claim;
//! the engine builds the registry once and dispatch is a map lookup. Adding a
//! feature = a new file + one `register(...)` line — nothing else changes.
//!
//! Streaming features (audio/video, remote control) need the binary channel-mux
//! (protocol v2) instead; that seam is documented in `crate::service`.

pub mod call_history;
pub mod call_notification;
pub mod clipboard;
pub mod notification;

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::engine::NetCtx;
use crate::platform::Platform;

/// A parsed control message handed to a [`ControlHandler`]. `from`/`ip`/`protocol`
/// describe the carrying chat envelope; field accessors read the JSON body.
pub struct ControlMsg<'a> {
    pub from: &'a str,
    pub ip: &'a str,
    pub protocol: &'a str,
    value: Value,
}

impl<'a> ControlMsg<'a> {
    pub fn kind(&self) -> &str {
        self.value.get("type").and_then(|t| t.as_str()).unwrap_or("")
    }
    /// String field, or "" if absent.
    pub fn str(&self, key: &str) -> String {
        self.value.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
    }
    /// Optional string field.
    pub fn opt(&self, key: &str) -> Option<String> {
        self.value.get(key).and_then(|x| x.as_str()).map(String::from)
    }
    /// Raw JSON field (for opaque passthrough payloads).
    pub fn json(&self, key: &str) -> Value {
        self.value.get(key).cloned().unwrap_or(Value::Null)
    }
}

/// One feature's inbound handler. A handler may claim several `"type"` values
/// (e.g. clipboard's push/request/response trio).
pub trait ControlHandler<P: Platform>: Send + Sync {
    fn kinds(&self) -> &'static [&'static str];
    fn handle(&self, ctx: &NetCtx<P>, msg: &ControlMsg);
}

/// Map of `"type"` → handler. Built once per engine.
pub struct ControlRegistry<P: Platform> {
    handlers: HashMap<&'static str, Arc<dyn ControlHandler<P>>>,
}

impl<P: Platform> ControlRegistry<P> {
    /// The standard feature set wired into every build.
    pub fn with_defaults() -> Self {
        let mut r = ControlRegistry { handlers: HashMap::new() };
        r.register(Arc::new(clipboard::ClipboardHandler));
        r.register(Arc::new(notification::NotificationHandler));
        r.register(Arc::new(call_notification::CallNotificationHandler));
        r.register(Arc::new(call_history::CallHistoryHandler));
        r
    }

    pub fn register(&mut self, handler: Arc<dyn ControlHandler<P>>) {
        for kind in handler.kinds() {
            self.handlers.insert(kind, handler.clone());
        }
    }

    /// Dispatch `text` to its handler. Returns `true` if it was a recognized
    /// control message (handled in-band; the caller must NOT show it as chat).
    pub fn dispatch(&self, ctx: &NetCtx<P>, from: &str, ip: &str, protocol: &str, text: &str) -> bool {
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            return false;
        };
        let kind = match value.get("type").and_then(|t| t.as_str()) {
            Some(k) => k.to_string(),
            None => return false,
        };
        let Some(handler) = self.handlers.get(kind.as_str()).cloned() else {
            return false;
        };
        let msg = ControlMsg { from, ip, protocol, value };
        handler.handle(ctx, &msg);
        true
    }
}
