//! UDP hole-punch primitive: simultaneous-open between two peers.
//!
//! Both sides must start punching at roughly the same time (coordinated via a
//! relative `start_in_ms` in the `PunchOffer`/`PunchAnswer` signals). Each side
//! blasts a small magic probe to every candidate while listening on the SAME
//! socket; the first peer probe received identifies the working 5-tuple, which
//! is then promoted to the data channel.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Punch toward `candidates`, returning the remote address whose probe we first
/// receive (the bound path), or `None` if none responds within `total`.
pub fn hole_punch(
    socket: &UdpSocket,
    candidates: &[SocketAddr],
    magic: &[u8],
    total: Duration,
) -> Option<SocketAddr> {
    socket.set_read_timeout(Some(Duration::from_millis(50))).ok()?;
    let deadline = Instant::now() + total;
    let mut buf = [0u8; 64];
    let mut last_send = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);

    while Instant::now() < deadline {
        if last_send.elapsed() >= Duration::from_millis(50) {
            for c in candidates {
                let _ = socket.send_to(magic, c);
            }
            last_send = Instant::now();
        }
        if let Ok((n, src)) = socket.recv_from(&mut buf) {
            if n >= magic.len() && &buf[..magic.len()] == magic {
                // Ack so the peer also confirms the path.
                let _ = socket.send_to(magic, src);
                return Some(src);
            }
        }
    }
    None
}
