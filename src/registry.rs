//! Registry (HTTP) client. The registry is a directory only: it maps a user's
//! devices to their endpoints. All calls return `Result<_, String>` so adapters
//! can surface the message verbatim.

use std::time::Duration;

use serde::Deserialize;

use crate::model::Identity;

#[derive(Deserialize)]
pub struct TokenResp {
    pub token: String,
    pub username: String,
}

#[derive(Deserialize)]
pub struct RegistryDevice {
    pub node_id: String,
    pub name: String,
    pub ip: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    #[serde(default)]
    pub ws_port: u16,
    // Peer-visible reachability state (server `DeviceOut`); defaulted so older
    // server responses still deserialize.
    #[serde(default)]
    pub ws_open: bool,
    #[serde(default)]
    pub inbound_blocked: bool,
    #[serde(default)]
    pub reflexive_ip: Option<String>,
    #[serde(default)]
    pub reflexive_udp_port: Option<u16>,
}

/// Normalize a user-entered server URL to just `scheme://host[:port]`, dropping
/// any path/query so pasting a full endpoint (e.g. `.../auth/login`) doesn't get
/// the path appended twice.
pub fn base(url: &str) -> String {
    let u = url.trim().trim_end_matches('/');
    match u.find("://") {
        Some(i) => {
            let host_start = i + 3;
            let host_end = u[host_start..]
                .find('/')
                .map(|j| host_start + j)
                .unwrap_or(u.len());
            u[..host_end].to_string()
        }
        None => u.to_string(),
    }
}

pub fn http_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, r) => r
            .into_json::<serde_json::Value>()
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or_else(|| format!("server returned HTTP {code}")),
        other => other.to_string(),
    }
}

pub fn auth_call(url: &str, path: &str, username: &str, password: &str) -> Result<TokenResp, String> {
    ureq::post(&format!("{}{}", base(url), path))
        .timeout(Duration::from_secs(10))
        .send_json(serde_json::json!({ "username": username, "password": password }))
        .map_err(http_err)?
        .into_json::<TokenResp>()
        .map_err(|e| e.to_string())
}

pub fn verify_password_call(url: &str, username: &str, password: &str) -> Result<bool, String> {
    match ureq::post(&format!("{}/auth/verify", base(url)))
        .timeout(Duration::from_secs(10))
        .send_json(serde_json::json!({ "username": username, "password": password }))
    {
        Ok(_) => Ok(true),
        Err(ureq::Error::Status(401, _)) => Ok(false),
        Err(e) => Err(http_err(e)),
    }
}

pub fn registry_register(
    url: &str,
    token: &str,
    id: &Identity,
    fcm_token: Option<&str>,
    platform: &str,
    supports_ipv6: bool,
) -> Result<(), String> {
    ureq::post(&format!("{}/devices/register", base(url)))
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({
            "node_id": id.node_id,
            "name": id.name,
            "ip": id.ip,
            "tcp_port": id.tcp_port,
            "udp_port": id.udp_port,
            "ws_port": id.ws_port,
            "fcm_token": fcm_token,
            "platform": platform,
            "supports_ipv6": supports_ipv6,
        }))
        .map_err(http_err)?;
    Ok(())
}

/// Relay a typed signal to one of the user's other devices (server pushes it via
/// FCM). `data` is the typed payload.
pub fn send_signal(
    url: &str,
    token: &str,
    from: &str,
    to: &str,
    kind: &str,
    data: serde_json::Value,
) -> Result<(), String> {
    ureq::post(&format!("{}/signal", base(url)))
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({ "from": from, "to": to, "type": kind, "data": data }))
        .map_err(http_err)?;
    Ok(())
}

/// Round-trip FCM self-test: ask the server to push a `ping` to our OWN device
/// token. The pong is delivered back through the platform's FCM receiver. `sid`
/// correlates the request with the received pong.
pub fn send_selfping(url: &str, token: &str, node_id: &str, sid: &str) -> Result<(), String> {
    ureq::post(&format!("{}/signal/selfping", base(url)))
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({ "node_id": node_id, "sid": sid }))
        .map_err(http_err)?;
    Ok(())
}

/// Partial live-state update (e.g. flip `ws_open`, record STUN mapping).
pub fn update_device_state(
    url: &str,
    token: &str,
    node_id: &str,
    ws_open: Option<bool>,
    inbound_blocked: Option<bool>,
    reflexive_ip: Option<&str>,
    reflexive_udp_port: Option<u16>,
) -> Result<(), String> {
    ureq::post(&format!("{}/devices/state", base(url)))
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({
            "node_id": node_id,
            "ws_open": ws_open,
            "inbound_blocked": inbound_blocked,
            "reflexive_ip": reflexive_ip,
            "reflexive_udp_port": reflexive_udp_port,
        }))
        .map_err(http_err)?;
    Ok(())
}

#[derive(Deserialize, Clone, Copy)]
pub struct ProbeResult {
    pub tcp_reachable: bool,
    pub ws_reachable: bool,
    pub udp_reachable: bool,
}

/// Ask the server to dial back to our advertised ports (inbound firewall check).
pub fn probe_inbound(url: &str, token: &str, node_id: &str, checks: &[&str]) -> Result<ProbeResult, String> {
    ureq::post(&format!("{}/devices/probe", base(url)))
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({ "node_id": node_id, "check": checks }))
        .map_err(http_err)?
        .into_json::<ProbeResult>()
        .map_err(|e| e.to_string())
}

/// Outbound reachability: can we reach the server at all?
pub fn health_ok(url: &str) -> bool {
    ureq::get(&format!("{}/health", base(url)))
        .timeout(Duration::from_secs(5))
        .call()
        .is_ok()
}

pub fn registry_fetch(url: &str, token: &str, exclude: &str) -> Result<Vec<RegistryDevice>, String> {
    ureq::get(&format!("{}/devices?exclude={}", base(url), exclude))
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(http_err)?
        .into_json::<Vec<RegistryDevice>>()
        .map_err(|e| e.to_string())
}
