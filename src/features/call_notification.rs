//! Call-notification sharing: forward an incoming/missed/ended call event.

use crate::engine::NetCtx;
use crate::events::CoreEvent;
use crate::platform::Platform;

use super::{ControlHandler, ControlMsg};

pub struct CallNotificationHandler;

impl<P: Platform> ControlHandler<P> for CallNotificationHandler {
    fn kinds(&self) -> &'static [&'static str] {
        &["call_notification"]
    }

    fn handle(&self, ctx: &NetCtx<P>, msg: &ControlMsg) {
        ctx.sink.emit(CoreEvent::CallNotification {
            from: msg.str("from"),
            caller: msg.str("caller"),
            number: msg.opt("number"),
            state: msg.str("state"),
        });
    }
}
