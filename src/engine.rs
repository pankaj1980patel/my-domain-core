//! The Engine: owns all networking state, spawns the receive/clipboard threads,
//! and exposes the public API that platform adapters (Tauri commands / JNI
//! shims) thin-wrap. Generic over `Platform`.
//!
//! Threading model: blocking thread-per-connection (a small fixed set of loops
//! plus short-lived per-message threads) — chosen for low cpu/battery.

use std::collections::HashMap;
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::crypto::derive_key;
use crate::discovery::{self, PeerMap, DISCOVERY_PORT};
use crate::events::{CoreEvent, EventSink};
use crate::features::ControlRegistry;
use crate::model::{Identity, Peer, Source};
use crate::platform::Platform;
use crate::registry::{auth_call, base, registry_fetch, registry_register, verify_password_call, RegistryDevice};
use crate::signal::Signal;
use crate::transport::{self, ws};

pub type KeyHolder = Arc<Mutex<Option<[u8; 32]>>>;
/// node_id -> (connection id, outgoing-frame sender). One entry per peer.
pub type WsConns = Arc<Mutex<HashMap<String, (u64, mpsc::Sender<String>)>>>;
/// node_id -> sender awaiting that peer's clipboard pull response.
pub type ClipPending = Arc<Mutex<HashMap<String, mpsc::Sender<String>>>>;
/// subscriber node_id -> the package names whose notifications they want
/// (app-notification pub/sub; held on the producer device).
pub type Subs = Arc<Mutex<HashMap<String, Vec<String>>>>;

/// Shared handles the receive loops + clipboard watcher need.
pub struct NetCtx<P: Platform> {
    pub platform: Arc<P>,
    pub identity: Arc<Mutex<Identity>>,
    pub key: KeyHolder,
    pub peers: PeerMap,
    pub ws_conns: WsConns,
    pub sink: Arc<dyn EventSink>,
    pub clip_active: Arc<AtomicBool>,
    pub clip_last: Arc<Mutex<String>>,
    pub clip_pending: ClipPending,
    pub control: Arc<ControlRegistry<P>>,
    /// Producer's shareable app list as a JSON array string (pushed by the host).
    pub installed_apps: Arc<Mutex<String>>,
    /// App-notification subscriptions (subscriber node_id -> packages).
    pub subs: Subs,
}

impl<P: Platform> Clone for NetCtx<P> {
    fn clone(&self) -> Self {
        NetCtx {
            platform: self.platform.clone(),
            identity: self.identity.clone(),
            key: self.key.clone(),
            peers: self.peers.clone(),
            ws_conns: self.ws_conns.clone(),
            sink: self.sink.clone(),
            clip_active: self.clip_active.clone(),
            clip_last: self.clip_last.clone(),
            clip_pending: self.clip_pending.clone(),
            control: self.control.clone(),
            installed_apps: self.installed_apps.clone(),
            subs: self.subs.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub username: Option<String>,
    pub server_url: Option<String>,
    pub has_key: bool,
}

#[derive(Serialize, Default)]
pub struct SavedSession {
    pub server_url: String,
    pub username: String,
}

pub struct Engine<P: Platform> {
    platform: Arc<P>,
    sink: Arc<dyn EventSink>,
    identity: Arc<Mutex<Identity>>,
    peers: PeerMap,
    ws_conns: WsConns,
    key: KeyHolder,
    server_url: Arc<Mutex<Option<String>>>,
    token: Arc<Mutex<Option<String>>>,
    username: Arc<Mutex<Option<String>>>,
    disco_send: Arc<UdpSocket>,
    clip_active: Arc<AtomicBool>,
    clip_last: Arc<Mutex<String>>,
    clip_pending: ClipPending,
    control: Arc<ControlRegistry<P>>,
    installed_apps: Arc<Mutex<String>>,
    subs: Subs,
}

impl<P: Platform> Engine<P> {
    /// Bind sockets, build identity, and spawn the discovery / tcp / udp / ws /
    /// clipboard / network-change threads.
    pub fn start(platform: P, sink: Arc<dyn EventSink>) -> Result<Engine<P>, String> {
        let platform = Arc::new(platform);

        let raw_id = platform.device_id();
        let node_id = if raw_id.trim().is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            raw_id
        };
        let name = platform.device_name();

        let tcp_listener = TcpListener::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        let tcp_port = tcp_listener.local_addr().map_err(|e| e.to_string())?.port();
        let udp_msg_socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        let udp_port = udp_msg_socket.local_addr().map_err(|e| e.to_string())?.port();
        let ws_listener = TcpListener::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        let ws_port = ws_listener.local_addr().map_err(|e| e.to_string())?.port();

        let identity = Arc::new(Mutex::new(Identity {
            node_id,
            name,
            ip: platform.local_ip(),
            tcp_port,
            udp_port,
            ws_port,
        }));

        let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
        let ws_conns: WsConns = Arc::new(Mutex::new(HashMap::new()));
        let key: KeyHolder = Arc::new(Mutex::new(None));
        let clip_active = Arc::new(AtomicBool::new(false));
        let clip_last = Arc::new(Mutex::new(String::new()));
        let clip_pending: ClipPending = Arc::new(Mutex::new(HashMap::new()));
        let control = Arc::new(ControlRegistry::with_defaults(platform.clipboard().is_some()));
        let installed_apps = Arc::new(Mutex::new(String::from("[]")));
        let subs: Subs = Arc::new(Mutex::new(HashMap::new()));

        // Discovery socket. If multicast bind fails (some networks/permissions),
        // fall back to a plain UDP socket for sending — messaging still works.
        let iface_mode = platform.iface_mode();
        let disco_send: Arc<UdpSocket> = match discovery::bind_multicast(&iface_mode) {
            Ok(recv) => {
                let send = Arc::new(recv.try_clone().map_err(|e| e.to_string())?);
                let peers_c = peers.clone();
                let identity_c = identity.clone();
                let sink_c = sink.clone();
                let send_c = send.clone();
                std::thread::spawn(move || {
                    discovery::discovery_recv_loop(recv, send_c, peers_c, identity_c, sink_c)
                });
                send
            }
            Err(_) => Arc::new(UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?),
        };

        let ctx = NetCtx {
            platform: platform.clone(),
            identity: identity.clone(),
            key: key.clone(),
            peers: peers.clone(),
            ws_conns: ws_conns.clone(),
            sink: sink.clone(),
            clip_active: clip_active.clone(),
            clip_last: clip_last.clone(),
            clip_pending: clip_pending.clone(),
            control: control.clone(),
            installed_apps: installed_apps.clone(),
            subs: subs.clone(),
        };

        // Direct messaging receivers.
        {
            let ctx = ctx.clone();
            std::thread::spawn(move || transport::tcp_recv_loop(tcp_listener, ctx));
        }
        {
            let ctx = ctx.clone();
            std::thread::spawn(move || transport::udp_recv_loop(udp_msg_socket, ctx));
        }
        {
            let ctx = ctx.clone();
            std::thread::spawn(move || ws::ws_server_loop(ws_listener, ctx));
        }

        // Clipboard auto-sync watcher — only if this platform has a clipboard.
        if platform.clipboard().is_some() {
            let ctx = ctx.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_millis(1000));
                if !ctx.clip_active.load(Ordering::Relaxed) {
                    continue;
                }
                let Some(clip) = ctx.platform.clipboard() else { continue };
                let Some(cur) = clip.get() else { continue };
                if cur.is_empty() {
                    continue;
                }
                let changed = {
                    let mut last = ctx.clip_last.lock().unwrap();
                    if *last != cur {
                        *last = cur.clone();
                        true
                    } else {
                        false
                    }
                };
                if changed {
                    let me = ctx.identity.lock().unwrap().node_id.clone();
                    let msg = serde_json::json!({ "type": "clipboard", "content": cur, "from": me }).to_string();
                    transport::broadcast_control(&ctx, &msg);
                }
            });
        }

        // Network-change watcher: refresh the advertised IP.
        {
            let identity = identity.clone();
            let platform = platform.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                let current = platform.local_ip();
                let mut id = identity.lock().unwrap();
                if id.ip != current && current != "0.0.0.0" {
                    id.ip = current;
                }
            });
        }

        Ok(Engine {
            platform,
            sink,
            identity,
            peers,
            ws_conns,
            key,
            server_url: Arc::new(Mutex::new(None)),
            token: Arc::new(Mutex::new(None)),
            username: Arc::new(Mutex::new(None)),
            disco_send,
            clip_active,
            clip_last,
            clip_pending,
            control,
            installed_apps,
            subs,
        })
    }

    fn net_ctx(&self) -> NetCtx<P> {
        NetCtx {
            platform: self.platform.clone(),
            identity: self.identity.clone(),
            key: self.key.clone(),
            peers: self.peers.clone(),
            ws_conns: self.ws_conns.clone(),
            sink: self.sink.clone(),
            clip_active: self.clip_active.clone(),
            clip_last: self.clip_last.clone(),
            clip_pending: self.clip_pending.clone(),
            control: self.control.clone(),
            installed_apps: self.installed_apps.clone(),
            subs: self.subs.clone(),
        }
    }

    /// Send an already-built control-message JSON to one peer (best transport).
    fn send_control(&self, node_id: &str, json: &str) -> Result<(), String> {
        let from = self.identity.lock().unwrap().name.clone();
        let proto = if self.ws_conns.lock().unwrap().contains_key(node_id) { "WS" } else { "UDP" };
        transport::send_payload(&self.peers, &self.ws_conns, &self.key, &from, node_id, proto, json)
    }

    fn emit_peers(&self) {
        let list: Vec<Peer> = self.peers.lock().unwrap().values().cloned().collect();
        self.sink.emit(CoreEvent::PeersUpdated { peers: list });
    }

    // --- read-only state ---

    pub fn identity(&self) -> Identity {
        self.identity.lock().unwrap().clone()
    }

    pub fn get_peers(&self) -> Vec<Peer> {
        self.peers.lock().unwrap().values().cloned().collect()
    }

    pub fn connected_peers(&self) -> Vec<String> {
        self.ws_conns.lock().unwrap().keys().cloned().collect()
    }

    pub fn is_ready(&self) -> bool {
        self.token.lock().unwrap().is_some() && self.key.lock().unwrap().is_some()
    }

    pub fn session_info(&self) -> SessionInfo {
        SessionInfo {
            username: self.username.lock().unwrap().clone(),
            server_url: self.server_url.lock().unwrap().clone(),
            has_key: self.key.lock().unwrap().is_some(),
        }
    }

    pub fn saved_session(&self) -> SavedSession {
        SavedSession {
            server_url: self.platform.kv_get("server_url").unwrap_or_default(),
            username: self.platform.kv_get("username").unwrap_or_default(),
        }
    }

    // --- auth / key ---

    fn do_auth(&self, path: &str, server_url: &str, username: &str, password: &str) -> Result<(), String> {
        if server_url.trim().is_empty() {
            return Err("server URL is required".into());
        }
        let resp = auth_call(server_url, path, username.trim(), password)?;
        let url = base(server_url);
        *self.server_url.lock().unwrap() = Some(url.clone());
        *self.token.lock().unwrap() = Some(resp.token);
        *self.username.lock().unwrap() = Some(resp.username.clone());
        self.platform.kv_set("server_url", &url);
        self.platform.kv_set("username", &resp.username);
        Ok(())
    }

    pub fn auth_login(&self, server_url: &str, username: &str, password: &str) -> Result<(), String> {
        self.do_auth("/auth/login", server_url, username, password)
    }

    pub fn auth_register(&self, server_url: &str, username: &str, password: &str) -> Result<(), String> {
        self.do_auth("/auth/register", server_url, username, password)
    }

    /// DEV / LAN-only: skip the registry. Set a local username + key so LAN
    /// discovery and messaging work between devices sharing the same credentials.
    pub fn dev_login(&self, username: &str, passphrase: &str) -> Result<(), String> {
        let username = username.trim();
        if username.is_empty() || passphrase.trim().is_empty() {
            return Err("username and encryption key required".into());
        }
        let key = derive_key(passphrase, username).ok_or("failed to derive key")?;
        *self.username.lock().unwrap() = Some(username.to_string());
        *self.key.lock().unwrap() = Some(key);
        Ok(())
    }

    pub fn set_encryption_key(&self, passphrase: &str) -> Result<(), String> {
        let username = self.username.lock().unwrap().clone().ok_or("log in first")?;
        if passphrase.trim().is_empty() {
            return Err("encryption key is required".into());
        }
        let key = derive_key(passphrase, &username).ok_or("failed to derive key")?;
        *self.key.lock().unwrap() = Some(key);
        Ok(())
    }

    pub fn update_encryption_key(&self, new_passphrase: &str, password: &str) -> Result<(), String> {
        let username = self.username.lock().unwrap().clone().ok_or("log in first")?;
        let url = self.server_url.lock().unwrap().clone().ok_or("no server")?;
        if !verify_password_call(&url, &username, password)? {
            return Err("incorrect password".into());
        }
        if new_passphrase.trim().is_empty() {
            return Err("new encryption key is required".into());
        }
        let key = derive_key(new_passphrase, &username).ok_or("failed to derive key")?;
        *self.key.lock().unwrap() = Some(key);
        Ok(())
    }

    pub fn generate_key(&self) -> String {
        crate::crypto::generate_key()
    }

    pub fn logout(&self) {
        *self.token.lock().unwrap() = None;
        *self.key.lock().unwrap() = None;
    }

    // --- discovery / peers ---

    pub fn refresh_from_server(&self) -> Result<(), String> {
        let url = self.server_url.lock().unwrap().clone().ok_or("not logged in")?;
        let token = self.token.lock().unwrap().clone().ok_or("not logged in")?;
        let id = self.identity.lock().unwrap().clone();
        registry_register(
            &url,
            &token,
            &id,
            self.platform.fcm_token().as_deref(),
            self.platform.platform_kind(),
            false,
        )?;
        let devices = registry_fetch(&url, &token, &id.node_id)?;
        self.apply_registry_peers(devices);
        Ok(())
    }

    fn apply_registry_peers(&self, devices: Vec<RegistryDevice>) {
        {
            let mut map = self.peers.lock().unwrap();
            map.retain(|_, p| p.source != Source::Registry);
            for d in devices {
                map.insert(
                    d.node_id.clone(),
                    Peer {
                        node_id: d.node_id,
                        name: d.name,
                        ip: d.ip,
                        tcp_port: d.tcp_port,
                        udp_port: d.udp_port,
                        ws_port: d.ws_port,
                        source: Source::Registry,
                    },
                );
            }
        }
        self.emit_peers();
    }

    pub fn scan_lan(&self) {
        let id = self.identity.lock().unwrap().clone();
        let socket = self.disco_send.clone();
        let targets = discovery::lan_targets(&self.platform.iface_mode());
        std::thread::spawn(move || {
            for _ in 0..3 {
                discovery::send_beacon(&socket, &id, false, &targets);
                std::thread::sleep(Duration::from_millis(700));
            }
        });
    }

    /// Update the advertised IP after a network change (android passes the new
    /// Wi-Fi IP; desktop passes `None` to recompute). Re-registers if logged in.
    pub fn network_changed(&self, new_ip: Option<&str>) {
        let ip = match new_ip {
            Some(s) if s.parse::<Ipv4Addr>().is_ok() => s.to_string(),
            _ => self.platform.local_ip(),
        };
        self.identity.lock().unwrap().ip = ip;
        if self.token.lock().unwrap().is_some() {
            let _ = self.refresh_from_server();
        }
    }

    pub fn add_manual_peer(&self, name: &str, ip: &str, tcp_port: u16, udp_port: u16, ws_port: u16) -> Result<(), String> {
        let parsed: Ipv4Addr = ip.trim().parse().map_err(|_| format!("invalid IPv4: {ip}"))?;
        let node_id = format!("manual:{parsed}");
        let display = if name.trim().is_empty() {
            parsed.to_string()
        } else {
            name.trim().to_string()
        };
        self.peers.lock().unwrap().insert(
            node_id.clone(),
            Peer {
                node_id,
                name: display,
                ip: parsed.to_string(),
                tcp_port,
                udp_port,
                ws_port,
                source: Source::Manual,
            },
        );
        self.emit_peers();
        Ok(())
    }

    pub fn remove_peer(&self, node_id: &str) {
        self.peers.lock().unwrap().remove(node_id);
        self.emit_peers();
    }

    // --- messaging ---

    pub fn connect_ws(&self, node_id: &str) -> Result<(), String> {
        let peer = self.peers.lock().unwrap().get(node_id).cloned().ok_or("peer not found")?;
        if peer.ws_port == 0 {
            return Err("peer has no WebSocket port".into());
        }
        if self.ws_conns.lock().unwrap().contains_key(node_id) {
            return Ok(());
        }
        ws::ws_connect(self.net_ctx(), &peer.ip, peer.ws_port)
    }

    pub fn send(&self, node_id: &str, protocol: &str, text: &str) -> Result<(), String> {
        let from = self
            .username
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.identity.lock().unwrap().name.clone());
        transport::send_payload(&self.peers, &self.ws_conns, &self.key, &from, node_id, protocol, text)
    }

    // --- clipboard ---

    pub fn enable_clipboard_sync(&self) {
        if let Some(clip) = self.platform.clipboard() {
            if let Some(cur) = clip.get() {
                *self.clip_last.lock().unwrap() = cur;
            }
        }
        self.clip_active.store(true, Ordering::Relaxed);
    }

    pub fn disable_clipboard_sync(&self) {
        self.clip_active.store(false, Ordering::Relaxed);
    }

    pub fn clipboard_sync_enabled(&self) -> bool {
        self.clip_active.load(Ordering::Relaxed)
    }

    /// Pull a peer's clipboard once, write it locally, and return it.
    pub fn get_clipboard(&self, node_id: &str) -> Result<String, String> {
        let clip = self.platform.clipboard().ok_or("clipboard not supported on this device")?;
        let (tx, rx) = mpsc::channel::<String>();
        self.clip_pending.lock().unwrap().insert(node_id.to_string(), tx);

        let me = self.identity.lock().unwrap().node_id.clone();
        let from = self.identity.lock().unwrap().name.clone();
        let req = serde_json::json!({ "type": "clipboard_request", "from": me }).to_string();
        let proto = if self.ws_conns.lock().unwrap().contains_key(node_id) { "WS" } else { "UDP" };

        if let Err(e) = transport::send_payload(&self.peers, &self.ws_conns, &self.key, &from, node_id, proto, &req) {
            self.clip_pending.lock().unwrap().remove(node_id);
            return Err(e);
        }

        let result = rx.recv_timeout(Duration::from_secs(6));
        self.clip_pending.lock().unwrap().remove(node_id);
        let content = result.map_err(|_| {
            "no clipboard response from peer (is it reachable and using the same key?)".to_string()
        })?;
        clip.set(&content);
        *self.clip_last.lock().unwrap() = content.clone();
        Ok(content)
    }

    // --- feature sharing (broadcast a control message to all peers) ---

    /// Share an OS notification with all of the user's other devices.
    pub fn share_notification(&self, title: &str, body: &str, app: Option<&str>) {
        let from = self.identity.lock().unwrap().node_id.clone();
        let msg = serde_json::json!({
            "type": "notification", "title": title, "body": body, "app": app, "from": from,
        })
        .to_string();
        transport::broadcast_control(&self.net_ctx(), &msg);
    }

    /// Share an incoming/missed/ended call notification.
    pub fn share_call_notification(&self, caller: &str, number: Option<&str>, state: &str) {
        let from = self.identity.lock().unwrap().node_id.clone();
        let msg = serde_json::json!({
            "type": "call_notification", "caller": caller, "number": number, "state": state, "from": from,
        })
        .to_string();
        transport::broadcast_control(&self.net_ctx(), &msg);
    }

    /// Share call-history entries (an opaque JSON array, passed through as-is).
    pub fn share_call_history(&self, entries_json: &str) {
        let from = self.identity.lock().unwrap().node_id.clone();
        let entries: serde_json::Value =
            serde_json::from_str(entries_json).unwrap_or(serde_json::Value::Null);
        let msg = serde_json::json!({ "type": "call_history", "entries": entries, "from": from }).to_string();
        transport::broadcast_control(&self.net_ctx(), &msg);
    }

    // --- app-notification pub/sub ---

    /// Set this device's shareable app list (JSON array of {pkg,label}) — pushed
    /// by the host (e.g. android PackageManager). Producers answer `apps_request`
    /// with this.
    pub fn set_installed_apps(&self, apps_json: &str) {
        *self.installed_apps.lock().unwrap() = apps_json.to_string();
    }

    /// Consumer: ask a producer for its app list (reply arrives as CoreEvent::AppsList).
    pub fn request_apps(&self, node_id: &str) -> Result<(), String> {
        let me = self.identity.lock().unwrap().node_id.clone();
        let m = serde_json::json!({ "type": "apps_request", "from": me }).to_string();
        self.send_control(node_id, &m)
    }

    /// Consumer: set the full enabled package set on a producer.
    pub fn subscribe_apps(&self, node_id: &str, apps_json: &str) -> Result<(), String> {
        let me = self.identity.lock().unwrap().node_id.clone();
        let apps: serde_json::Value =
            serde_json::from_str(apps_json).unwrap_or(serde_json::Value::Array(vec![]));
        let m = serde_json::json!({ "type": "subscribe_apps", "from": me, "apps": apps }).to_string();
        self.send_control(node_id, &m)
    }

    /// Producer: a local app posted a notification — forward it to every peer
    /// subscribed to that package (as a normal `notification`).
    pub fn share_app_notification(&self, pkg: &str, app: &str, title: &str, body: &str) {
        let me = self.identity.lock().unwrap().node_id.clone();
        let targets: Vec<String> = self
            .subs
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, pkgs)| pkgs.iter().any(|p| p == pkg))
            .map(|(n, _)| n.clone())
            .collect();
        for n in targets {
            let m = serde_json::json!({
                "type": "notification", "from": me, "title": title, "body": body, "app": app,
            })
            .to_string();
            let _ = self.send_control(&n, &m);
        }
    }

    // --- signaling / connection setup (Roadmap B) ---

    /// Outbound + inbound reachability check. Outbound = the server is reachable;
    /// inbound = the server can dial back to our advertised ports. Persists the
    /// inbound result via `/devices/state`.
    pub fn firewall_check(&self) -> Result<FirewallStatus, String> {
        let url = self.server_url.lock().unwrap().clone().ok_or("not logged in")?;
        let outbound_ok = crate::registry::health_ok(&url);
        if !outbound_ok {
            return Ok(FirewallStatus { outbound_ok: false, inbound_blocked: true });
        }
        let token = self.token.lock().unwrap().clone().ok_or("not logged in")?;
        let node_id = self.identity.lock().unwrap().node_id.clone();
        let probe = crate::registry::probe_inbound(&url, &token, &node_id, &["tcp", "ws"])?;
        let inbound_blocked = !(probe.tcp_reachable || probe.ws_reachable);
        Ok(FirewallStatus { outbound_ok, inbound_blocked })
    }

    /// Tell the registry whether our WS server is currently reachable.
    pub fn update_ws_open(&self, open: bool) -> Result<(), String> {
        let url = self.server_url.lock().unwrap().clone().ok_or("not logged in")?;
        let token = self.token.lock().unwrap().clone().ok_or("not logged in")?;
        let node_id = self.identity.lock().unwrap().node_id.clone();
        crate::registry::update_device_state(&url, &token, &node_id, Some(open), None, None, None)
    }

    /// Relay a typed signal to a sibling device (via the server's FCM relay).
    pub fn send_signal(&self, to: &str, sig: &Signal) -> Result<(), String> {
        let url = self.server_url.lock().unwrap().clone().ok_or("not logged in")?;
        let token = self.token.lock().unwrap().clone().ok_or("not logged in")?;
        let me = self.identity.lock().unwrap().node_id.clone();
        let data = serde_json::to_value(sig).map_err(|e| e.to_string())?;
        crate::registry::send_signal(&url, &token, &me, to, "signal", data)
    }

    /// Round-trip FCM self-test: ask the server to push a `ping` to our own
    /// device token. Returns the correlation id; the pong arrives via the
    /// platform's FCM receiver (which the adapter surfaces to the UI). Verifies
    /// the full push path end to end (server FCM send → device receive).
    pub fn fcm_selftest(&self) -> Result<String, String> {
        let url = self.server_url.lock().unwrap().clone().ok_or("not logged in")?;
        let token = self.token.lock().unwrap().clone().ok_or("not logged in")?;
        let node_id = self.identity.lock().unwrap().node_id.clone();
        let sid = uuid::Uuid::new_v4().to_string();
        crate::registry::send_selfping(&url, &token, &node_id, &sid)?;
        Ok(sid)
    }

    /// Handle an inbound signal (delivered by the platform's FCM receiver as the
    /// raw JSON `payload`). Drives the responder side of the connection ladder.
    pub fn on_signal(&self, from: &str, payload: &str) {
        let Ok(sig) = serde_json::from_str::<Signal>(payload) else {
            return;
        };
        match sig {
            // Initiator wants us reachable: our WS server is already listening,
            // so mark it open and tell them where to dial.
            Signal::StartWs { sid } => {
                let id = self.identity.lock().unwrap().clone();
                let _ = self.update_ws_open(true);
                let _ = self.send_signal(from, &Signal::WsReady { sid, ip: id.ip, ws_port: id.ws_port });
            }
            // Responder is reachable: dial it.
            Signal::WsReady { ip, ws_port, .. } => {
                let _ = ws::ws_connect(self.net_ctx(), &ip, ws_port);
            }
            // Hole punch / TURN: handled by the NAT module (wired during the
            // streaming/NAT phase — see crate::nat).
            _ => {}
        }
    }

    /// Best-effort connect to a peer along the fallback ladder. Direct WS first;
    /// if that's not reachable, ask the peer (via signaling) to open its WS and
    /// dial back — the reply arrives through `on_signal`.
    pub fn connect(&self, node_id: &str) -> Result<(), String> {
        let peer = self.peers.lock().unwrap().get(node_id).cloned().ok_or("peer not found")?;
        // 1. Direct WS if the peer advertises one and is reachable.
        if peer.ws_port != 0 && !peer_inbound_blocked(&peer) {
            if self.connect_ws(node_id).is_ok() {
                return Ok(());
            }
        }
        // 2. FCM-coordinated start-WS. Peer replies WsReady → on_signal dials.
        let sid = uuid::Uuid::new_v4().to_string();
        self.send_signal(node_id, &Signal::StartWs { sid })
    }
}

#[derive(Serialize)]
pub struct FirewallStatus {
    pub outbound_ok: bool,
    pub inbound_blocked: bool,
}

/// Peers from LAN/registry don't currently carry the firewall flag in the core
/// `Peer` struct; treat unknown as not-blocked so the direct attempt is made.
fn peer_inbound_blocked(_peer: &Peer) -> bool {
    false
}

// Keep DISCOVERY_PORT reachable for adapters that want it.
pub use crate::discovery::MCAST_GROUP;
pub const DISCO_PORT: u16 = DISCOVERY_PORT;
