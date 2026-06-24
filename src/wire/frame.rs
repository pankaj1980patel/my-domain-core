//! Binary frame: a fixed 9-byte header + payload, carried inside the existing
//! E2EE envelope. Layout (big-endian):
//!
//! ```text
//! +------+---------+-----------+-------+--------+-----------+
//! | ver  | service | channel   | flags |  seq   |  payload  |
//! | u8   | u8      | u16       | u8    |  u32   |  bytes…   |
//! +------+---------+-----------+-------+--------+-----------+
//! ```
//!
//! `service` maps to `crate::service::ServiceId`; `channel` is mux-assigned;
//! payload is JSON for control and raw codec bytes for media.

pub const VERSION: u8 = 2;
pub const HEADER_LEN: usize = 9;

/// Frame flags.
pub const FLAG_DATAGRAM: u8 = 0x01; // drop-tolerant (media); else reliable.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub service: u8,
    pub channel: u16,
    pub flags: u8,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(VERSION);
        out.push(self.service);
        out.extend_from_slice(&self.channel.to_be_bytes());
        out.push(self.flags);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Frame> {
        if bytes.len() < HEADER_LEN || bytes[0] != VERSION {
            return None;
        }
        Some(Frame {
            service: bytes[1],
            channel: u16::from_be_bytes([bytes[2], bytes[3]]),
            flags: bytes[4],
            seq: u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]),
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }

    pub fn is_datagram(&self) -> bool {
        self.flags & FLAG_DATAGRAM != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let f = Frame { service: 4, channel: 7, flags: FLAG_DATAGRAM, seq: 42, payload: vec![1, 2, 3] };
        assert_eq!(Frame::decode(&f.encode()), Some(f));
    }
}
