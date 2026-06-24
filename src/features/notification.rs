//! Notification sharing: mirror a peer's OS notification locally.

use crate::engine::NetCtx;
use crate::events::CoreEvent;
use crate::platform::Platform;

use super::{ControlHandler, ControlMsg};

pub struct NotificationHandler;

impl<P: Platform> ControlHandler<P> for NotificationHandler {
    fn kinds(&self) -> &'static [&'static str] {
        &["notification"]
    }

    fn handle(&self, ctx: &NetCtx<P>, msg: &ControlMsg) {
        if let Some(n) = ctx.platform.notifier() {
            n.post(&msg.str("title"), &msg.str("body"));
        }
        ctx.sink.emit(CoreEvent::Notification {
            from: msg.str("from"),
            title: msg.str("title"),
            body: msg.str("body"),
            app: msg.opt("app"),
        });
    }
}
