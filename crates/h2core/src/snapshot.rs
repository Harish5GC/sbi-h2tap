//! The on-disk contract between `h2tapd` and `h2rebuild`.
//!
//! A dynamic table is only meaningful at an exact byte position in the TCP
//! stream, so every direction snapshot carries `next_frame_seq`: the absolute
//! sequence number of the next frame boundary, as of which `entries` is the
//! table. The rebuilder seeks to that byte before decoding anything. Without
//! it a snapshot would be worse than useless, because a table applied at the
//! wrong offset yields plausible headers that are wrong.

use serde::{Deserialize, Serialize};

use crate::hpack::Field;

pub const SNAPSHOT_VERSION: u32 = 1;

/// A header name or value. Plain text in the normal case; hex when the bytes
/// are not valid UTF-8, which HPACK permits even though HTTP field values in
/// practice are ASCII.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Str {
    Text(String),
    Hex { hex: String },
}

impl Str {
    pub fn from_bytes(b: &[u8]) -> Str {
        match std::str::from_utf8(b) {
            Ok(s) => Str::Text(s.to_string()),
            Err(_) => Str::Hex { hex: b.iter().map(|x| format!("{x:02x}")).collect() },
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Str::Text(s) => s.as_bytes().to_vec(),
            Str::Hex { hex } => hex
                .as_bytes()
                .chunks(2)
                .filter_map(|p| {
                    u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub n: Str,
    pub v: Str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirSnapshot {
    /// "c2s" or "s2c".
    pub dir: String,
    pub src: String,
    pub dst: String,
    /// Absolute TCP sequence number of the next frame boundary. `entries` is
    /// the dynamic table as of this byte.
    pub next_frame_seq: u32,
    pub max_table_size: usize,
    /// True when `max_table_size` was learned from the wire rather than
    /// assumed to be the RFC default. Exactness claims rest on it being right.
    #[serde(default)]
    pub capacity_observed: bool,
    pub table_size: usize,
    /// False when this direction's table is not fully known. The rebuilder
    /// still runs, but decodes partially.
    pub usable: bool,
    /// Why it is not usable, when it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Newest first: index 62 is `entries[0]`, 63 is `entries[1]`, and so on.
    pub entries: Vec<Entry>,
}

impl DirSnapshot {
    pub fn fields(&self) -> Vec<Field> {
        self.entries
            .iter()
            .map(|e| Field::new(e.n.to_bytes(), e.v.to_bytes()))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnSnapshot {
    /// Stable across the connection's life and unique over time: a 5-tuple
    /// alone is not, because ports get reused.
    pub conn_id: String,
    pub client: String,
    pub server: String,
    pub first_seen_unix_us: u64,
    pub dirs: Vec<DirSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSnapshot {
    pub version: u32,
    pub capture_id: String,
    pub started_unix_us: u64,
    pub iface: String,
    pub pcap_path: String,
    /// Connections whose tables are fully known and safe to rebuild.
    pub conns_usable: usize,
    /// Connections with at least one direction we cannot vouch for.
    pub conns_degraded: usize,
    pub conns: Vec<ConnSnapshot>,
}

impl CaptureSnapshot {
    pub fn find(&self, conn_id: &str) -> Option<&ConnSnapshot> {
        self.conns.iter().find(|c| c.conn_id == conn_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_binary_round_trip() {
        let t = Str::from_bytes(b"application/json");
        let b = Str::from_bytes(&[0xff, 0x00, 0x41]);
        assert!(matches!(t, Str::Text(_)));
        assert!(matches!(b, Str::Hex { .. }));
        assert_eq!(t.to_bytes(), b"application/json");
        assert_eq!(b.to_bytes(), vec![0xff, 0x00, 0x41]);

        let json = serde_json::to_string(&b).unwrap();
        let back: Str = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_bytes(), vec![0xff, 0x00, 0x41]);
    }

    #[test]
    fn snapshot_json_round_trips() {
        let s = CaptureSnapshot {
            version: SNAPSHOT_VERSION,
            capture_id: "cap-1".into(),
            started_unix_us: 1,
            iface: "eth0".into(),
            pcap_path: "/tmp/x.pcap".into(),
            conns_usable: 1,
            conns_degraded: 0,
            conns: vec![ConnSnapshot {
                conn_id: "a".into(),
                client: "10.0.0.1:5000".into(),
                server: "10.0.0.2:7777".into(),
                first_seen_unix_us: 1,
                dirs: vec![DirSnapshot {
                    dir: "c2s".into(),
                    src: "10.0.0.1:5000".into(),
                    dst: "10.0.0.2:7777".into(),
                    next_frame_seq: 4_294_967_000,
                    max_table_size: 4096,
                    capacity_observed: true,
                    table_size: 57,
                    usable: true,
                    reason: None,
                    entries: vec![Entry {
                        n: Str::from_bytes(b":authority"),
                        v: Str::from_bytes(b"nrf.5gc"),
                    }],
                }],
            }],
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: CaptureSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(back.conns[0].dirs[0].next_frame_seq, 4_294_967_000);
        assert_eq!(back.find("a").unwrap().dirs[0].fields()[0].name_str(), ":authority");
    }
}
