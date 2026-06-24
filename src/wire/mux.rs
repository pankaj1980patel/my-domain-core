//! Channel multiplexing over a v2 connection. A `Connection` carries many
//! logical channels (reliable over WS/TCP, datagram over UDP); the mux assigns
//! channel ids and routes inbound `Frame`s to the owning service.
//!
//! Only the channel allocator is implemented today; the full `Connection` that
//! binds reliable + datagram transports together lands with the streaming work.

use std::sync::atomic::{AtomicU16, Ordering};

use crate::service::Reliability;

/// Allocates locally-initiated channel ids. (Even ids could be reserved for one
/// side and odd for the other to avoid collisions; kept simple for now.)
pub struct ChannelAllocator {
    next: AtomicU16,
}

impl ChannelAllocator {
    pub fn new() -> Self {
        ChannelAllocator { next: AtomicU16::new(1) }
    }

    pub fn alloc(&self, _reliability: Reliability) -> u16 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for ChannelAllocator {
    fn default() -> Self {
        Self::new()
    }
}
