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
use crate::transport::{self, ws, P2pConns};

pub type KeyHolder = Arc<Mutex<Option<[u8; 32]>>>;
/// node_id -> (connection id, outgoing-frame sender). One entry per peer.
pub type WsConns = Arc<Mutex<HashMap<String, (u64, mpsc::Sender<String>)>>>;
/// node_id -> sender awaiting that peer's clipboard pull response.
pub type ClipPending = Arc<Mutex<HashMap<String, mpsc::Sender<String>>>>;
/// subscriber node_id -> the package names whose notifications they want
/// (app-notification pub/sub; held on the producer device).
pub type Subs = Arc<Mutex<HashMap<String, Vec<String>>>>;
/// In-flight punch negotiations: sid -> sender that delivers the peer's answered
/// candidates to the waiting initiator thread.
pub type PunchWaiters = Arc<Mutex<HashMap<String, mpsc::Sender<Vec<crate::signal::Candidate>>>>>;
/// In-flight WebRTC negotiations: sid -> sender delivering the answer SDP string.
pub type RtcWaiters = Arc<Mutex<HashMap<String, mpsc::Sender<String>>>>;

/// Shared handles the receive loops + clipboard watcher need.
pub struct NetCtx<P: Platform> {
    pub platform: Arc<P>,
    pub identity: Arc<Mutex<Identity>>,
    pub key: KeyHolder,
    pub peers: PeerMap,
    pub ws_conns: WsConns,
    /// Unified live-connection registry (all transports). UI green dot reads this.
    pub p2p_conns: P2pConns,
    /// In-flight punch negotiations (initiator side).
    pub punch_waiters: PunchWaiters,
    /// In-flight WebRTC negotiations (initiator side).
    pub rtc_waiters: RtcWaiters,
    pub sink: Arc<dyn EventSink>,
    pub clip_active: Arc<AtomicBool>,
    pub clip_last: Arc<Mutex<String>>,
    pub clip_pending: ClipPending,
    pub control: Arc<ControlRegistry<P>>,
    /// Producer's shareable app list as a JSON array string (pushed by the host).
    pub installed_apps: Arc<Mutex<String>>,
    /// App-notification subscriptions (subscriber node_id -> packages).
    pub subs: Subs,
    /// Directed transport for peers with no live persistent channel: "UDP"
    /// (default) or "TCP". A live WS/punch/WebRTC link always wins over this.
    pub directed_transport: Arc<Mutex<String>>,
}

impl<P: Platform> Clone for NetCtx<P> {
    fn clone(&self) -> Self {
        NetCtx {
            platform: self.platform.clone(),
            identity: self.identity.clone(),
            key: self.key.clone(),
            peers: self.peers.clone(),
            ws_conns: self.ws_conns.clone(),
            p2p_conns: self.p2p_conns.clone(),
            punch_waiters: self.punch_waiters.clone(),
            rtc_waiters: self.rtc_waiters.clone(),
            sink: self.sink.clone(),
            clip_active: self.clip_active.clone(),
            clip_last: self.clip_last.clone(),
            clip_pending: self.clip_pending.clone(),
            control: self.control.clone(),
            installed_apps: self.installed_apps.clone(),
            subs: self.subs.clone(),
            directed_transport: self.directed_transport.clone(),
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
    p2p_conns: P2pConns,
    punch_waiters: PunchWaiters,
    rtc_waiters: RtcWaiters,
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
    directed_transport: Arc<Mutex<String>>,
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
        let p2p_conns: P2pConns = Arc::new(Mutex::new(HashMap::new()));
        let punch_waiters: PunchWaiters = Arc::new(Mutex::new(HashMap::new()));
        let rtc_waiters: RtcWaiters = Arc::new(Mutex::new(HashMap::new()));
        let key: KeyHolder = Arc::new(Mutex::new(None));
        let clip_active = Arc::new(AtomicBool::new(false));
        let clip_last = Arc::new(Mutex::new(String::new()));
        let clip_pending: ClipPending = Arc::new(Mutex::new(HashMap::new()));
        let control = Arc::new(ControlRegistry::with_defaults(platform.clipboard().is_some()));
        let installed_apps = Arc::new(Mutex::new(String::from("[]")));
        let subs: Subs = Arc::new(Mutex::new(HashMap::new()));
        let directed_transport = Arc::new(Mutex::new(String::from("UDP")));

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
            p2p_conns: p2p_conns.clone(),
            punch_waiters: punch_waiters.clone(),
            rtc_waiters: rtc_waiters.clone(),
            sink: sink.clone(),
            clip_active: clip_active.clone(),
            clip_last: clip_last.clone(),
            clip_pending: clip_pending.clone(),
            control: control.clone(),
            installed_apps: installed_apps.clone(),
            subs: subs.clone(),
            directed_transport: directed_transport.clone(),
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

        // P2P heartbeat: keepalive pings for connectionless links (UDP/punch/
        // webrtc) and staleness eviction. WS is event-driven, so it's skipped.
        {
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                const INTERVAL: Duration = Duration::from_secs(5);
                const TIMEOUT: u64 = 15;
                loop {
                    std::thread::sleep(INTERVAL);
                    let me = ctx.identity.lock().unwrap().node_id.clone();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let ping = serde_json::json!({ "type": "p2p_ping", "from": me }).to_string();
                    for (node_id, kind, last_seen) in transport::live_snapshot(&ctx) {
                        if kind == transport::TransportKind::Ws {
                            continue;
                        }
                        if now.saturating_sub(last_seen) > TIMEOUT {
                            transport::drop_live(&ctx, &node_id);
                        } else {
                            transport::send_control_to(&ctx, &node_id, &ping);
                        }
                    }
                }
            });
        }

        Ok(Engine {
            platform,
            sink,
            identity,
            peers,
            ws_conns,
            p2p_conns,
            punch_waiters,
            rtc_waiters,
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
            directed_transport,
        })
    }

    fn net_ctx(&self) -> NetCtx<P> {
        NetCtx {
            platform: self.platform.clone(),
            identity: self.identity.clone(),
            key: self.key.clone(),
            peers: self.peers.clone(),
            ws_conns: self.ws_conns.clone(),
            p2p_conns: self.p2p_conns.clone(),
            punch_waiters: self.punch_waiters.clone(),
            rtc_waiters: self.rtc_waiters.clone(),
            sink: self.sink.clone(),
            clip_active: self.clip_active.clone(),
            clip_last: self.clip_last.clone(),
            clip_pending: self.clip_pending.clone(),
            control: self.control.clone(),
            installed_apps: self.installed_apps.clone(),
            subs: self.subs.clone(),
            directed_transport: self.directed_transport.clone(),
        }
    }

    /// The transport a message to `node_id` should use right now: the active
    /// persistent link (WS/punch/WebRTC) if any, else the directed transport.
    fn proto_for(&self, node_id: &str) -> &'static str {
        let directed = self.directed_transport.lock().unwrap().clone();
        transport::best_proto(&self.ws_conns, &directed, node_id)
    }

    /// Send an already-built control-message JSON to one peer (active connection).
    fn send_control(&self, node_id: &str, json: &str) -> Result<(), String> {
        let from = self.identity.lock().unwrap().name.clone();
        let proto = self.proto_for(node_id);
        transport::send_payload(&self.peers, &self.ws_conns, &self.key, &from, node_id, proto, json)
    }

    /// Directed transport setting ("UDP" | "TCP") for peers with no live link.
    pub fn directed_transport(&self) -> String {
        self.directed_transport.lock().unwrap().clone()
    }

    /// Set the directed transport ("UDP" default, or "TCP"); anything else maps
    /// to UDP. Only affects peers without a live persistent connection.
    pub fn set_directed_transport(&self, t: &str) {
        let v = if t.trim().eq_ignore_ascii_case("tcp") { "TCP" } else { "UDP" };
        *self.directed_transport.lock().unwrap() = v.to_string();
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
        self.p2p_conns.lock().unwrap().keys().cloned().collect()
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
                        ws_open: d.ws_open,
                        inbound_blocked: d.inbound_blocked,
                        reflexive_ip: d.reflexive_ip,
                        reflexive_udp_port: d.reflexive_udp_port,
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
                ws_open: false,
                inbound_blocked: false,
                reflexive_ip: None,
                reflexive_udp_port: None,
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

    /// Send a chat message, auto-selecting the transport: the active persistent
    /// connection (WS/punch/WebRTC) if one is live, else the directed transport
    /// (UDP/TCP). Returns the protocol used so the UI can report it.
    pub fn send(&self, node_id: &str, text: &str) -> Result<String, String> {
        let from = self
            .username
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.identity.lock().unwrap().name.clone());
        let proto = self.proto_for(node_id);
        transport::send_payload(&self.peers, &self.ws_conns, &self.key, &from, node_id, proto, text)?;
        Ok(proto.to_string())
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
        let proto = self.proto_for(node_id);

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
        // Persist so siblings see our reachability via `GET /devices` and the
        // connect ladder can use it. Best-effort — don't fail the check on this.
        let _ = crate::registry::update_device_state(
            &url,
            &token,
            &node_id,
            None,
            Some(inbound_blocked),
            None,
            None,
        );
        Ok(FirewallStatus { outbound_ok, inbound_blocked })
    }

    /// Run the firewall check on a background thread and persist the result, so
    /// other devices see our reachability. Called once after login (the probe
    /// does a blocking server dial-back, so it must not run on the UI thread).
    pub fn report_firewall(&self) {
        let url = self.server_url.lock().unwrap().clone();
        let token = self.token.lock().unwrap().clone();
        let node_id = self.identity.lock().unwrap().node_id.clone();
        let (Some(url), Some(token)) = (url, token) else { return };
        std::thread::spawn(move || {
            if !crate::registry::health_ok(&url) {
                return;
            }
            if let Ok(probe) = crate::registry::probe_inbound(&url, &token, &node_id, &["tcp", "ws"]) {
                let inbound_blocked = !(probe.tcp_reachable || probe.ws_reachable);
                let _ = crate::registry::update_device_state(
                    &url, &token, &node_id, None, Some(inbound_blocked), None, None,
                );
            }
        });
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
            // Initiator wants to hole-punch: gather our candidates, answer with
            // them, and punch toward theirs. Off-thread (STUN + HTTP block).
            Signal::PunchOffer { sid, candidates, .. } => {
                let ctx = self.net_ctx();
                let from = from.to_string();
                let server_url = self.server_url.clone();
                let token = self.token.clone();
                std::thread::spawn(move || {
                    if let Some((socket, my_cands)) = transport::punch::gather_candidates(&ctx) {
                        let _ = send_signal_via(
                            &server_url,
                            &token,
                            &ctx,
                            &from,
                            &Signal::PunchAnswer { sid, candidates: my_cands, start_in_ms: 0 },
                        );
                        transport::punch::punch_and_run(ctx, socket, candidates, from);
                    }
                });
            }
            // Our offer was answered: hand the peer's candidates to the waiting
            // ladder thread so it can punch.
            Signal::PunchAnswer { sid, candidates, .. } => {
                let waiter = self.punch_waiters.lock().unwrap().remove(&sid);
                if let Some(tx) = waiter {
                    let _ = tx.send(candidates);
                }
            }
            // WebRTC: responder accepts the offer, spawns the driver, answers.
            #[cfg(feature = "webrtc")]
            Signal::SdpOffer { sid, sdp } => {
                let ctx = self.net_ctx();
                let from = from.to_string();
                let server_url = self.server_url.clone();
                let token = self.token.clone();
                std::thread::spawn(move || {
                    if let Some(answer) = transport::rtc::accept_offer_and_run(ctx.clone(), &sdp, from.clone()) {
                        let _ = send_signal_via(&server_url, &token, &ctx, &from, &Signal::SdpAnswer { sid, sdp: answer });
                    }
                });
            }
            // WebRTC: hand the answer SDP to the waiting initiator thread.
            #[cfg(feature = "webrtc")]
            Signal::SdpAnswer { sid, sdp } => {
                let waiter = self.rtc_waiters.lock().unwrap().remove(&sid);
                if let Some(tx) = waiter {
                    let _ = tx.send(sdp);
                }
            }
            // Teardown.
            Signal::Bye { .. } => {
                transport::drop_live(&self.net_ctx(), from);
            }
            // RelayOffer/RelayAnswer (TURN) remain a future hook.
            _ => {}
        }
    }

    /// Kick off the connection ladder on a background thread (returns at once).
    /// Progress is reported via `CoreEvent::ConnectProgress`; success lands as a
    /// `PeerConnected` event when any rung establishes a live link.
    pub fn connect(&self, node_id: &str) -> Result<(), String> {
        // Validate the peer exists up front so the button gets immediate feedback.
        if !self.peers.lock().unwrap().contains_key(node_id) {
            return Err("peer not found".into());
        }
        let ctx = self.net_ctx();
        let server_url = self.server_url.clone();
        let token = self.token.clone();
        let node_id = node_id.to_string();
        std::thread::spawn(move || run_connect_ladder(ctx, server_url, token, node_id));
        Ok(())
    }
}

#[derive(Serialize)]
pub struct FirewallStatus {
    pub outbound_ok: bool,
    pub inbound_blocked: bool,
}

/// Whether a peer reported it can't receive inbound connections. LAN/manual
/// peers default to `false` (unknown → attempt direct); registry peers carry the
/// real flag the device self-reported via `report_firewall`.
fn peer_inbound_blocked(peer: &Peer) -> bool {
    peer.inbound_blocked
}

// ---------------------------------------------------------------------------
// Connection ladder (runs off-thread; uses only NetCtx + the server creds, so
// it doesn't need `&Engine`). Each rung emits ConnectProgress and bails to the
// next on timeout. Rungs are ordered cheapest-first.
// ---------------------------------------------------------------------------

/// Same-LAN heuristic: LAN-discovered peer, or our IPs share a /24.
fn same_lan<P: Platform>(ctx: &NetCtx<P>, peer: &Peer) -> bool {
    if peer.source == Source::Lan {
        return true;
    }
    let my_ip = ctx.identity.lock().unwrap().ip.clone();
    match (my_ip.parse::<Ipv4Addr>(), peer.ip.parse::<Ipv4Addr>()) {
        (Ok(a), Ok(b)) => a.octets()[..3] == b.octets()[..3],
        _ => false,
    }
}

fn is_live<P: Platform>(ctx: &NetCtx<P>, node_id: &str) -> bool {
    ctx.p2p_conns.lock().unwrap().contains_key(node_id)
}

/// Poll for the peer to become live, up to `ms` milliseconds.
fn wait_live<P: Platform>(ctx: &NetCtx<P>, node_id: &str, ms: u64) -> bool {
    let steps = ms / 100;
    for _ in 0..steps {
        std::thread::sleep(Duration::from_millis(100));
        if is_live(ctx, node_id) {
            return true;
        }
    }
    is_live(ctx, node_id)
}

/// Send one UDP ping and wait briefly for the pong to flip the peer live.
fn udp_ping_connect<P: Platform>(ctx: &NetCtx<P>, node_id: &str) -> bool {
    let (me, name) = {
        let id = ctx.identity.lock().unwrap();
        (id.node_id.clone(), id.name.clone())
    };
    let ping = serde_json::json!({ "type": "p2p_ping", "from": me }).to_string();
    if transport::send_payload(&ctx.peers, &ctx.ws_conns, &ctx.key, &name, node_id, "UDP", &ping).is_err() {
        return false;
    }
    wait_live(ctx, node_id, 2000)
}

/// Relay a typed signal using the shared server creds (thread-friendly twin of
/// `Engine::send_signal`).
fn send_signal_via<P: Platform>(
    server_url: &Arc<Mutex<Option<String>>>,
    token: &Arc<Mutex<Option<String>>>,
    ctx: &NetCtx<P>,
    to: &str,
    sig: &Signal,
) -> Result<(), String> {
    let url = server_url.lock().unwrap().clone().ok_or("not logged in")?;
    let tok = token.lock().unwrap().clone().ok_or("not logged in")?;
    let me = ctx.identity.lock().unwrap().node_id.clone();
    let data = serde_json::to_value(sig).map_err(|e| e.to_string())?;
    crate::registry::send_signal(&url, &tok, &me, to, "signal", data)
}

fn run_connect_ladder<P: Platform>(
    ctx: NetCtx<P>,
    server_url: Arc<Mutex<Option<String>>>,
    token: Arc<Mutex<Option<String>>>,
    node_id: String,
) {
    let emit = |stage: &str, detail: Option<String>| {
        ctx.sink.emit(CoreEvent::ConnectProgress {
            node_id: node_id.clone(),
            stage: stage.into(),
            detail,
        });
    };

    if is_live(&ctx, &node_id) {
        emit("connected", None);
        return;
    }
    let Some(peer) = ctx.peers.lock().unwrap().get(&node_id).cloned() else {
        emit("failed", Some("peer not found".into()));
        return;
    };

    // Rung 1 — same-LAN UDP ping/pong (no FCM, no server).
    if same_lan(&ctx, &peer) {
        emit("udp_ping", None);
        if udp_ping_connect(&ctx, &node_id) {
            emit("connected", Some("udp".into()));
            return;
        }
    }

    // Rung 2 — direct WS if the peer advertises a reachable WS server.
    if peer.ws_port != 0 && peer.ws_open && !peer_inbound_blocked(&peer) {
        emit("direct_ws", None);
        if ws::ws_connect(ctx.clone(), &peer.ip, peer.ws_port).is_ok() && wait_live(&ctx, &node_id, 3000) {
            return; // WS handler emits PeerConnected
        }
    }

    // Rung 3 — FCM-coordinated WS: ask the peer to open its WS and reply WsReady,
    // which our on_signal dials. (1 FCM round trip.)
    emit("via_signal", None);
    let sid = uuid::Uuid::new_v4().to_string();
    if send_signal_via(&server_url, &token, &ctx, &node_id, &Signal::StartWs { sid }).is_ok()
        && wait_live(&ctx, &node_id, 8000)
    {
        return;
    }

    // Rung 4 — UDP hole punch. Gather our candidates up front, offer them in one
    // signal, and punch toward the peer's answered candidates (1 FCM round trip).
    emit("punching", None);
    if let Some((socket, my_cands)) = transport::punch::gather_candidates(&ctx) {
        let sid = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = mpsc::channel::<Vec<crate::signal::Candidate>>();
        ctx.punch_waiters.lock().unwrap().insert(sid.clone(), tx);
        let offer = Signal::PunchOffer { sid: sid.clone(), candidates: my_cands, start_in_ms: 0 };
        if send_signal_via(&server_url, &token, &ctx, &node_id, &offer).is_ok() {
            if let Ok(peer_cands) = rx.recv_timeout(Duration::from_secs(8)) {
                ctx.punch_waiters.lock().unwrap().remove(&sid);
                transport::punch::punch_and_run(ctx.clone(), socket, peer_cands, node_id.clone());
                if wait_live(&ctx, &node_id, 9000) {
                    return;
                }
            } else {
                ctx.punch_waiters.lock().unwrap().remove(&sid);
            }
        } else {
            ctx.punch_waiters.lock().unwrap().remove(&sid);
        }
    }

    // Rung 5 — WebRTC data channel. Gather candidates into one SDP offer, send
    // it, and on the single answer drive ICE/DTLS/SCTP peer-to-peer (1 FCM RTT).
    #[cfg(feature = "webrtc")]
    {
        emit("webrtc", None);
        if let Some((rtc, socket, pending, offer_sdp)) = transport::rtc::create_offer(&ctx) {
            let sid = uuid::Uuid::new_v4().to_string();
            let (tx, rx) = mpsc::channel::<String>();
            ctx.rtc_waiters.lock().unwrap().insert(sid.clone(), tx);
            let offer = Signal::SdpOffer { sid: sid.clone(), sdp: offer_sdp };
            if send_signal_via(&server_url, &token, &ctx, &node_id, &offer).is_ok() {
                if let Ok(answer_sdp) = rx.recv_timeout(Duration::from_secs(10)) {
                    ctx.rtc_waiters.lock().unwrap().remove(&sid);
                    if transport::rtc::apply_answer_and_run(ctx.clone(), rtc, socket, pending, &answer_sdp, node_id.clone())
                        && wait_live(&ctx, &node_id, 12000)
                    {
                        return;
                    }
                } else {
                    ctx.rtc_waiters.lock().unwrap().remove(&sid);
                }
            } else {
                ctx.rtc_waiters.lock().unwrap().remove(&sid);
            }
        }
    }

    emit("failed", Some("no reachable path".into()));
}

// Keep DISCOVERY_PORT reachable for adapters that want it.
pub use crate::discovery::MCAST_GROUP;
pub const DISCO_PORT: u16 = DISCOVERY_PORT;
