//! LAN discovery: UDP multicast + broadcast + /24 unicast sweep beacons. The
//! interface strategy (`IfaceMode`) is supplied by the platform so the desktop
//! "all interfaces" and android "single Wi-Fi interface" behaviors share code.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use socket2::{Domain, Protocol, Socket, Type};

use crate::events::{CoreEvent, EventSink};
use crate::model::{Beacon, Identity, Peer, Source};

pub const MCAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 98);
pub const DISCOVERY_PORT: u16 = 45678;

pub type PeerMap = Arc<Mutex<HashMap<String, Peer>>>;

/// Bind the always-listening discovery socket and join the multicast group per
/// the platform's interface strategy.
pub fn bind_multicast(mode: &crate::platform::IfaceMode) -> std::io::Result<UdpSocket> {
    use crate::platform::IfaceMode;
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DISCOVERY_PORT).into())?;
    match mode {
        IfaceMode::All { v4_addrs } => {
            for v4 in v4_addrs {
                let _ = socket.join_multicast_v4(&MCAST_GROUP, v4);
            }
            let _ = socket.join_multicast_v4(&MCAST_GROUP, &Ipv4Addr::UNSPECIFIED);
        }
        IfaceMode::Single(iface) => {
            socket.join_multicast_v4(&MCAST_GROUP, iface)?;
            socket.set_multicast_if_v4(iface)?;
        }
    }
    socket.set_multicast_loop_v4(true)?;
    Ok(socket.into())
}

/// Targets for a LAN announce: multicast + global broadcast + per-interface /24
/// (subnet broadcast + unicast sweep of every host).
pub fn lan_targets(mode: &crate::platform::IfaceMode) -> Vec<SocketAddr> {
    use crate::platform::IfaceMode;
    let mut v = vec![
        SocketAddr::new(MCAST_GROUP.into(), DISCOVERY_PORT),
        SocketAddr::new(Ipv4Addr::BROADCAST.into(), DISCOVERY_PORT),
    ];
    let addrs: Vec<Ipv4Addr> = match mode {
        IfaceMode::All { v4_addrs } => v4_addrs.clone(),
        IfaceMode::Single(ip) => vec![*ip],
    };
    for ip in addrs {
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        let o = ip.octets();
        v.push(SocketAddr::new(Ipv4Addr::new(o[0], o[1], o[2], 255).into(), DISCOVERY_PORT));
        for host in 1..=254u8 {
            if host == o[3] {
                continue;
            }
            v.push(SocketAddr::new(Ipv4Addr::new(o[0], o[1], o[2], host).into(), DISCOVERY_PORT));
        }
    }
    v
}

pub fn send_beacon(socket: &UdpSocket, id: &Identity, reply: bool, to: &[SocketAddr]) {
    let beacon = Beacon {
        node_id: id.node_id.clone(),
        name: id.name.clone(),
        tcp_port: id.tcp_port,
        udp_port: id.udp_port,
        ws_port: id.ws_port,
        reply,
    };
    if let Ok(payload) = serde_json::to_vec(&beacon) {
        let _ = socket.set_broadcast(true);
        for dst in to {
            // Errors for empty hosts in the sweep (EHOSTDOWN/UNREACH/ENETUNREACH)
            // are expected and ignored.
            let _ = socket.send_to(&payload, dst);
        }
    }
}

/// Always-listening receiver. On an announce, record the peer (emitting a
/// `PeersUpdated`) and reply once (unicast) so a single scan discovers both
/// directions.
pub fn discovery_recv_loop(
    recv: UdpSocket,
    send: Arc<UdpSocket>,
    peers: PeerMap,
    identity: Arc<Mutex<Identity>>,
    sink: Arc<dyn EventSink>,
) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, src) = match recv.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let beacon: Beacon = match serde_json::from_slice(&buf[..len]) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if beacon.node_id == identity.lock().unwrap().node_id {
            continue;
        }
        peers.lock().unwrap().insert(
            beacon.node_id.clone(),
            Peer {
                node_id: beacon.node_id.clone(),
                name: beacon.name.clone(),
                ip: src.ip().to_string(),
                tcp_port: beacon.tcp_port,
                udp_port: beacon.udp_port,
                ws_port: beacon.ws_port,
                source: Source::Lan,
            },
        );
        let list: Vec<Peer> = peers.lock().unwrap().values().cloned().collect();
        sink.emit(CoreEvent::PeersUpdated { peers: list });
        // Reply to announces (not to replies) so the scanner is discovered too.
        if !beacon.reply {
            let id = identity.lock().unwrap().clone();
            send_beacon(&send, &id, true, &[SocketAddr::new(src.ip(), DISCOVERY_PORT)]);
        }
    }
}
