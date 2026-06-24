//! Protocol v2: binary multiplexed framing for the streaming/channel-mux layer.
//!
//! This is the seam for audio/video + remote control, which can't ride the v1
//! JSON control-message path. Today's messaging/clipboard/notification/call
//! features still use v1 (see `crate::transport` + `crate::features`); cutting
//! those over to v2 is a coordinated wire change made alongside the streaming
//! work (and gated by the `ver` byte so v1 and v2 can coexist for a release).

pub mod frame;
pub mod mux;
