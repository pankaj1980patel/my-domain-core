//! The platform abstraction. Each client (desktop, android, …) implements
//! `Platform`; the Engine is generic over it. This hides every real divergence
//! between platforms behind one trait so the networking/feature code is shared.

use std::net::{Ipv4Addr, UdpSocket};

use crate::capabilities::{Clipboard, Notifier};

/// How to choose the multicast interface(s) and the /24 sweep base for LAN
/// discovery.
#[derive(Clone)]
pub enum IfaceMode {
    /// Desktop: enumerate all non-loopback IPv4 interfaces (via `if_addrs`) and
    /// join multicast on each.
    All { v4_addrs: Vec<Ipv4Addr> },
    /// Android: pin to one Wi-Fi interface IP (`set_multicast_if_v4`) because the
    /// default route is cellular.
    Single(Ipv4Addr),
}

/// Best-effort local IPv4 via the "connect to 8.8.8.8" trick. Shared default.
pub fn detect_local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

/// Everything the Engine needs from its host platform. Capability accessors
/// return `None` when the platform doesn't support that feature.
pub trait Platform: Send + Sync + 'static {
    // --- stable identity ---
    /// Stable, hardware-derived device id (machine-uid / ANDROID_ID). Empty
    /// string => the Engine falls back to a random UUID.
    fn device_id(&self) -> String;
    /// Human-readable device name (hostname / user-supplied).
    fn device_name(&self) -> String;

    /// Platform tag for the registry: "desktop" | "android" | "ios" | "mac".
    fn platform_kind(&self) -> &'static str {
        "unknown"
    }

    // --- network ---
    /// Interface strategy for multicast + LAN sweep. Re-queried on network change.
    fn iface_mode(&self) -> IfaceMode;
    /// Current best local IPv4 (string). Default uses the 8.8.8.8 trick.
    fn local_ip(&self) -> String {
        detect_local_ip()
    }

    // --- session persistence (server_url + username only) ---
    fn kv_get(&self, _key: &str) -> Option<String> {
        None
    }
    fn kv_set(&self, _key: &str, _value: &str) {}

    // --- push (roadmap: FCM) ---
    fn fcm_token(&self) -> Option<String> {
        None
    }

    // --- capabilities (absent => feature degrades gracefully) ---
    fn clipboard(&self) -> Option<&dyn Clipboard> {
        None
    }
    fn notifier(&self) -> Option<&dyn Notifier> {
        None
    }
}
