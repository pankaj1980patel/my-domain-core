//! Minimal STUN (RFC 5389) Binding client — enough to learn our reflexive
//! (public) IPv4:port mapping for hole punching. Must be run on the SAME socket
//! that will later punch, so the mapping matches.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use rand_core::{OsRng, RngCore};

const MAGIC: u32 = 0x2112_A442;

/// Send a Binding Request on `socket` to `server` and return the observed
/// reflexive address, or `None` on timeout / parse failure.
pub fn stun_binding(socket: &UdpSocket, server: SocketAddr) -> Option<SocketAddr> {
    let mut txid = [0u8; 12];
    OsRng.fill_bytes(&mut txid);

    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
    req.extend_from_slice(&0u16.to_be_bytes()); // message length
    req.extend_from_slice(&MAGIC.to_be_bytes());
    req.extend_from_slice(&txid);

    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    socket.send_to(&req, server).ok()?;

    let mut buf = [0u8; 512];
    let (n, _src) = socket.recv_from(&mut buf).ok()?;
    parse_mapped(&buf[..n])
}

fn parse_mapped(msg: &[u8]) -> Option<SocketAddr> {
    if msg.len() < 20 {
        return None;
    }
    // Binding Success Response.
    if u16::from_be_bytes([msg[0], msg[1]]) != 0x0101 {
        return None;
    }
    let mlen = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let end = (20 + mlen).min(msg.len());
    let magic = MAGIC.to_be_bytes();

    let mut i = 20;
    while i + 4 <= end {
        let atype = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let alen = u16::from_be_bytes([msg[i + 2], msg[i + 3]]) as usize;
        let v = i + 4;
        if v + alen > msg.len() {
            break;
        }
        let val = &msg[v..v + alen];
        // XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001), IPv4 only.
        if (atype == 0x0020 || atype == 0x0001) && val.len() >= 8 && val[1] == 0x01 {
            let (port, ip) = if atype == 0x0020 {
                let port = u16::from_be_bytes([val[2], val[3]]) ^ 0x2112;
                let ip = Ipv4Addr::new(
                    val[4] ^ magic[0],
                    val[5] ^ magic[1],
                    val[6] ^ magic[2],
                    val[7] ^ magic[3],
                );
                (port, ip)
            } else {
                let port = u16::from_be_bytes([val[2], val[3]]);
                let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
                (port, ip)
            };
            return Some(SocketAddr::new(ip.into(), port));
        }
        // Attributes are padded to a 4-byte boundary.
        i = v + alen + ((4 - (alen % 4)) % 4);
    }
    None
}
