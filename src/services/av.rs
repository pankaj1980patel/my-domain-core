//! Audio/video calls (feature `av`). Media frames ride a datagram channel using
//! the platform's `AudioIo` / `VideoIo`; call setup + codec negotiation ride a
//! reliable channel and the signaling layer. Seam only for now.

use crate::service::{ChannelId, Service, ServiceId};

pub struct AvService;

impl Service for AvService {
    fn id(&self) -> ServiceId {
        ServiceId::Av
    }

    fn on_frame(&self, _node_id: &str, _chan: ChannelId, _data: &[u8]) {
        // TODO: decode media frame → AudioIo::play / VideoIo display.
    }
}
