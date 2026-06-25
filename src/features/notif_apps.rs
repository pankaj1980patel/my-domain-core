//! App-notification pub/sub. A consumer asks a producer for its shareable app
//! list, then subscribes to specific packages; the subscription is stored on the
//! producer (in `NetCtx::subs`). When the producer captures a notification from
//! a subscribed app it forwards it as a normal `notification` (see
//! `Engine::share_app_notification`).
//!
//!   apps_request   { from }                          consumer → producer
//!   apps_list      { from, apps[], subscribed[] }    producer → consumer
//!   subscribe_apps { from, apps[] }                  consumer → producer

use serde_json::Value;

use crate::engine::NetCtx;
use crate::events::CoreEvent;
use crate::platform::Platform;
use crate::transport::send_control_to;

use super::{ControlHandler, ControlMsg};

pub struct NotifAppsHandler;

impl<P: Platform> ControlHandler<P> for NotifAppsHandler {
    fn kinds(&self) -> &'static [&'static str] {
        &["apps_request", "subscribe_apps", "apps_list"]
    }

    fn handle(&self, ctx: &NetCtx<P>, msg: &ControlMsg) {
        match msg.kind() {
            // Producer: reply with our app list + the requester's subscription.
            "apps_request" => {
                let from = msg.str("from");
                if from.is_empty() {
                    return;
                }
                let me = ctx.identity.lock().unwrap().node_id.clone();
                let apps: Value = serde_json::from_str(&ctx.installed_apps.lock().unwrap())
                    .unwrap_or_else(|_| Value::Array(vec![]));
                let subscribed = ctx.subs.lock().unwrap().get(&from).cloned().unwrap_or_default();
                let reply = serde_json::json!({
                    "type": "apps_list", "from": me, "apps": apps, "subscribed": subscribed,
                })
                .to_string();
                send_control_to(ctx, &from, &reply);
            }
            // Producer: store this peer's subscription (full enabled set).
            "subscribe_apps" => {
                let from = msg.str("from");
                if from.is_empty() {
                    return;
                }
                let apps: Vec<String> = msg
                    .json("apps")
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                ctx.subs.lock().unwrap().insert(from, apps);
            }
            // Consumer: surface the producer's app list to the UI.
            "apps_list" => {
                ctx.sink.emit(CoreEvent::AppsList {
                    from: msg.str("from"),
                    apps: msg.json("apps"),
                    subscribed: msg.json("subscribed"),
                });
            }
            _ => {}
        }
    }
}
