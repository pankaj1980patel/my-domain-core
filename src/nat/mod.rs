//! NAT traversal: STUN reflexive-address discovery + a UDP hole-punch primitive.
//!
//! The full ladder (gather candidates → `PunchOffer`/`PunchAnswer` via signaling
//! → simultaneous punch → promote to the data channel; TURN relay fallback with
//! coturn ephemeral creds) is wired during the streaming/NAT phase. These
//! primitives are the building blocks and require live multi-network testing.

pub mod punch;
pub mod stun;
