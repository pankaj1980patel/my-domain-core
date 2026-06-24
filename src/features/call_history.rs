//! Call-history sync: receive a peer's call-log entries (opaque JSON payload).

use crate::engine::NetCtx;
use crate::events::CoreEvent;
use crate::platform::Platform;

use super::{ControlHandler, ControlMsg};

pub struct CallHistoryHandler;

impl<P: Platform> ControlHandler<P> for CallHistoryHandler {
    fn kinds(&self) -> &'static [&'static str] {
        &["call_history"]
    }

    fn handle(&self, ctx: &NetCtx<P>, msg: &ControlMsg) {
        ctx.sink.emit(CoreEvent::CallHistory {
            from: msg.str("from"),
            entries: msg.json("entries"),
        });
    }
}
