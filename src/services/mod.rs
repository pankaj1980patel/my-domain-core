//! Streaming services (protocol v2). These are feature-gated so low-power builds
//! exclude their (future) codec/media dependencies entirely.
//!
//! Each implements `crate::service::Service` and rides v2 channels: media on a
//! datagram channel, control/input on a reliable one. Bodies are seams today;
//! they fill in alongside the channel-mux `Connection` and platform media APIs
//! (`AudioIo` / `VideoIo` / `ScreenSource` / `InputSink`).

#[cfg(feature = "av")]
pub mod av;

#[cfg(feature = "remote-control")]
pub mod remotecontrol;
