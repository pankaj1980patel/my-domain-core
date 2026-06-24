//! Remote control (feature `remote-control`). Screen frames ride a datagram
//! channel via `ScreenSource`; input events ride a reliable channel and are
//! applied via `InputSink`. Seam only for now.

use crate::service::{ChannelId, Service, ServiceId};

pub struct RemoteControlService;

impl Service for RemoteControlService {
    fn id(&self) -> ServiceId {
        ServiceId::RemoteControl
    }

    fn on_frame(&self, _node_id: &str, _chan: ChannelId, _data: &[u8]) {
        // TODO: reliable channel → InputSink::inject; datagram → ScreenSource frames.
    }
}
