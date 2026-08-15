//! Shared engine for `h2tapd` (the live HPACK state keeper) and `h2rebuild`
//! (the offline normalizer).
//!
//! Both binaries MUST frame and decode identically, otherwise a snapshot taken
//! by the daemon will not line up with the stream the rebuilder replays. That
//! is the reason this is one crate rather than two implementations.

pub mod conn;
pub mod frame;
pub mod hpack;
pub mod pkt;
pub mod reassembly;
pub mod snapshot;

pub use conn::{BlockKind, DecodedBlock, Direction, ProcessedFrame};
pub use frame::{FrameHeader, FrameType};
pub use hpack::{Decoder, Field, HpackError};
pub use reassembly::Reassembler;
