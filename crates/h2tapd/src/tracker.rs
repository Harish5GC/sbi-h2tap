//! Live connection table: one HPACK context per direction, maintained
//! continuously so a snapshot can be taken at any moment.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use h2core::conn::Direction;
use h2core::pkt::{tcp_flags, TcpSegment};
use h2core::snapshot::{ConnSnapshot, DirSnapshot, Entry, Str};

type Key = (IpAddr, u16, IpAddr, u16);

fn key_of(a: (IpAddr, u16), b: (IpAddr, u16)) -> Key {
    // Direction-independent: both directions of a connection map to one key.
    if (a.0, a.1) <= (b.0, b.1) {
        (a.0, a.1, b.0, b.1)
    } else {
        (b.0, b.1, a.0, a.1)
    }
}

pub struct DirTrack {
    pub dir: Direction,
    /// When the currently pending (received but not yet framed) bytes first
    /// appeared. Used to check the ring buffer still covers them.
    pub pending_since_us: Option<u64>,
}

impl DirTrack {
    fn new(from_start: bool, expect_preface: bool, table_limit: usize) -> Self {
        let mut dir = if from_start {
            Direction::from_connection_start(false, expect_preface)
        } else {
            Direction::joined_midstream(false)
        };
        dir.set_table_track_limit(table_limit);
        DirTrack { dir, pending_since_us: None }
    }

    fn after_feed(&mut self, now_us: u64) {
        if self.dir.reasm.available().is_empty() {
            self.pending_since_us = None;
        } else if self.pending_since_us.is_none() {
            self.pending_since_us = Some(now_us);
        }
    }
}

pub struct Conn {
    pub id: String,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub closed_at_us: Option<u64>,
    pub c2s: DirTrack,
    pub s2c: DirTrack,
}

impl Conn {
    fn dir_mut(&mut self, is_c2s: bool) -> &mut DirTrack {
        if is_c2s {
            &mut self.c2s
        } else {
            &mut self.s2c
        }
    }
}

pub struct Tracker {
    conns: HashMap<Key, Conn>,
    server_ports: Vec<u16>,
    max_conns: usize,
    idle_us: u64,
    table_limit: usize,
    pub segments: u64,
    pub evicted: u64,
    pub rejected_full: u64,
}

impl Tracker {
    pub fn new(
        mut server_ports: Vec<u16>,
        max_conns: usize,
        idle_secs: u64,
        table_limit: usize,
    ) -> Self {
        // Sorted so the per-packet lookup is a binary search.
        server_ports.sort_unstable();
        server_ports.dedup();
        Tracker {
            conns: HashMap::new(),
            server_ports,
            max_conns,
            idle_us: idle_secs * 1_000_000,
            table_limit,
            segments: 0,
            evicted: 0,
            rejected_full: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.conns.len()
    }

    pub fn on_segment(&mut self, seg: &TcpSegment<'_>, now_us: u64) {
        self.segments += 1;
        let src = (seg.src_ip, seg.src_port);
        let dst = (seg.dst_ip, seg.dst_port);
        let k = key_of(src, dst);

        let syn = seg.has(tcp_flags::SYN);
        let ack = seg.has(tcp_flags::ACK);
        let fresh_syn = syn && !ack;

        // A bare SYN means a brand new connection. Ports get reused, so an
        // existing entry on this key is a previous connection and must be
        // replaced rather than continued.
        if fresh_syn {
            self.conns.remove(&k);
        }

        if !self.conns.contains_key(&k) {
            if self.conns.len() >= self.max_conns {
                self.rejected_full += 1;
                return;
            }
            // Who is the client? A bare SYN is definitive; otherwise fall back
            // to the configured server ports; otherwise assume the sender.
            let (client, server) = if fresh_syn {
                (src, dst)
            } else if self.server_ports.binary_search(&dst.1).is_ok() {
                (src, dst)
            } else if self.server_ports.binary_search(&src.1).is_ok() {
                (dst, src)
            } else {
                (src, dst)
            };
            let client = SocketAddr::new(client.0, client.1);
            let server = SocketAddr::new(server.0, server.1);
            let id = format!("{client}-{server}#{now_us}");
            self.conns.insert(
                k,
                Conn {
                    id,
                    client,
                    server,
                    first_seen_us: now_us,
                    last_seen_us: now_us,
                    closed_at_us: None,
                    // Only a bare SYN proves we have the stream from byte one.
                    c2s: DirTrack::new(fresh_syn, fresh_syn, self.table_limit),
                    s2c: DirTrack::new(fresh_syn, false, self.table_limit),
                },
            );
        }

        let Some(conn) = self.conns.get_mut(&k) else { return };
        conn.last_seen_us = now_us;
        let is_c2s = SocketAddr::new(src.0, src.1) == conn.client;

        if syn {
            conn.dir_mut(is_c2s).dir.reasm.note_syn(seg.seq);
        }
        if seg.has(tcp_flags::RST) || seg.has(tcp_flags::FIN) {
            conn.closed_at_us.get_or_insert(now_us);
        }
        if seg.payload.is_empty() {
            return;
        }

        let frames = conn.dir_mut(is_c2s).dir.feed(seg.seq, seg.payload, now_us);
        conn.dir_mut(is_c2s).after_feed(now_us);

        // SETTINGS_HEADER_TABLE_SIZE bounds the *peer's* encoder, so it caps
        // the decoder for the opposite direction.
        let caps: Vec<u32> = frames.iter().filter_map(|f| f.settings_table_size).collect();
        for c in caps {
            conn.dir_mut(!is_c2s).dir.dec.apply_peer_capacity(c as usize);
        }
    }

    /// Drive timeouts and drop dead connections.
    pub fn tick(&mut self, now_us: u64) {
        for c in self.conns.values_mut() {
            c.c2s.dir.tick(now_us);
            c.s2c.dir.tick(now_us);
        }
        let idle = self.idle_us;
        let before = self.conns.len();
        self.conns.retain(|_, c| {
            if now_us.saturating_sub(c.last_seen_us) > idle {
                return false;
            }
            // Keep closed connections briefly so a capture started right after
            // teardown still sees them.
            match c.closed_at_us {
                Some(t) => now_us.saturating_sub(t) < 10_000_000,
                None => true,
            }
        });
        self.evicted += (before - self.conns.len()) as u64;
    }

    pub fn iter(&self) -> impl Iterator<Item = &Conn> {
        self.conns.values()
    }

    /// Build the snapshot. `ring_oldest_us` is the timestamp of the oldest
    /// packet the capture will contain; a direction with pending bytes older
    /// than that is not usable, because the rebuilder would be missing bytes
    /// the table already accounts for.
    pub fn snapshot(&self, ring_oldest_us: Option<u64>) -> (Vec<ConnSnapshot>, usize, usize) {
        let mut out = Vec::with_capacity(self.conns.len());
        let mut usable_conns = 0usize;
        let mut degraded_conns = 0usize;

        for c in self.conns.values() {
            let dirs = vec![
                dir_snapshot("c2s", c.client, c.server, &c.c2s, ring_oldest_us),
                dir_snapshot("s2c", c.server, c.client, &c.s2c, ring_oldest_us),
            ];
            if dirs.iter().all(|d| d.usable) {
                usable_conns += 1;
            } else {
                degraded_conns += 1;
            }
            out.push(ConnSnapshot {
                conn_id: c.id.clone(),
                client: c.client.to_string(),
                server: c.server.to_string(),
                first_seen_unix_us: c.first_seen_us,
                dirs,
            });
        }
        (out, usable_conns, degraded_conns)
    }
}

fn dir_snapshot(
    name: &str,
    src: SocketAddr,
    dst: SocketAddr,
    t: &DirTrack,
    ring_oldest_us: Option<u64>,
) -> DirSnapshot {
    let pending_covered = match (t.pending_since_us, ring_oldest_us) {
        (None, _) => true,
        (Some(p), Some(oldest)) => p >= oldest,
        // Pending bytes but no ring at all: the capture cannot contain them.
        (Some(_), None) => false,
    };

    let reason = if t.dir.dec.over_limit() {
        Some(format!(
            "peer negotiated a {}-byte dynamic table, above --max-table-bytes; not tracked",
            t.dir.dec.max_size()
        ))
    } else if t.dir.poisoned {
        Some("hpack state lost (packet gap or decode error)".to_string())
    } else if t.dir.desynced {
        Some("frame boundary unknown".to_string())
    } else if !t.dir.dec.is_exact() {
        Some("joined mid-stream; dynamic table not fully observed".to_string())
    } else if !pending_covered {
        Some("partially received frame predates the capture ring".to_string())
    } else {
        None
    };

    DirSnapshot {
        dir: name.to_string(),
        src: src.to_string(),
        dst: dst.to_string(),
        next_frame_seq: t.dir.next_frame_seq(),
        max_table_size: t.dir.dec.max_size(),
        capacity_observed: t.dir.dec.capacity_observed(),
        table_size: t.dir.dec.table_size(),
        usable: reason.is_none() && t.dir.is_snapshottable(),
        reason,
        entries: t
            .dir
            .dec
            .entries()
            .map(|f| Entry { n: Str::from_bytes(&f.name), v: Str::from_bytes(&f.value) })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use h2core::frame::{build_frame, flags, FrameType, PREFACE};

    const CLIENT_IP: &str = "10.0.0.1";
    const SERVER_IP: &str = "10.0.0.2";
    const BASE: u32 = 500_000;

    fn seg<'a>(from_client: bool, seq: u32, fl: u8, payload: &'a [u8]) -> TcpSegment<'a> {
        let (src_ip, dst_ip, src_port, dst_port) = if from_client {
            (CLIENT_IP, SERVER_IP, 41234u16, 7777u16)
        } else {
            (SERVER_IP, CLIENT_IP, 7777, 41234)
        };
        TcpSegment {
            eth_dst: [0; 6],
            eth_src: [0; 6],
            src_ip: src_ip.parse().unwrap(),
            dst_ip: dst_ip.parse().unwrap(),
            src_port,
            dst_port,
            seq,
            ack: 0,
            flags: fl,
            payload,
        }
    }

    fn lit_indexed(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut v = vec![0x40];
        v.push(name.len() as u8);
        v.extend_from_slice(name);
        v.push(value.len() as u8);
        v.extend_from_slice(value);
        v
    }

    fn client_stream() -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(PREFACE);
        s.extend_from_slice(&build_frame(FrameType::SETTINGS, 0, 0, &[0, 1, 0, 0, 16, 0]));
        let mut b = vec![0x82, 0x87, 0x84];
        b.extend_from_slice(&lit_indexed(b":authority", b"nrf.5gc"));
        b.extend_from_slice(&lit_indexed(b"3gpp-sbi-target-apiroot", b"https://udm"));
        s.extend_from_slice(&build_frame(FrameType::HEADERS, flags::END_HEADERS, 1, &b));
        s
    }

    #[test]
    fn tracks_a_connection_and_snapshots_an_aligned_table() {
        let mut t = Tracker::new(vec![7777], 100, 300, usize::MAX);
        t.on_segment(&seg(true, BASE - 1, tcp_flags::SYN, &[]), 1_000);
        t.on_segment(&seg(false, 900_000, tcp_flags::SYN | tcp_flags::ACK, &[]), 1_100);

        let stream = client_stream();
        t.on_segment(&seg(true, BASE, tcp_flags::ACK, &stream), 2_000);

        let (conns, usable, degraded) = t.snapshot(Some(0));
        assert_eq!(conns.len(), 1);
        assert_eq!((usable, degraded), (1, 0));

        let c = &conns[0];
        assert_eq!(c.client, format!("{CLIENT_IP}:41234"));
        assert_eq!(c.server, format!("{SERVER_IP}:7777"));

        let c2s = c.dirs.iter().find(|d| d.dir == "c2s").unwrap();
        assert!(c2s.usable, "reason: {:?}", c2s.reason);
        // Newest first: index 62 is the last insertion.
        let names: Vec<String> = c2s.entries.iter().map(|e| match &e.n {
            Str::Text(s) => s.clone(),
            Str::Hex { hex } => hex.clone(),
        }).collect();
        assert_eq!(names, vec!["3gpp-sbi-target-apiroot", ":authority"]);
        // The whole stream was consumed, so the next frame starts right after.
        assert_eq!(c2s.next_frame_seq, BASE.wrapping_add(stream.len() as u32));
    }

    /// The snapshot a rebuilder consumes has to be refused when the tables
    /// cannot be vouched for, rather than handed over and trusted.
    #[test]
    fn a_gap_makes_the_direction_unusable() {
        let mut t = Tracker::new(vec![7777], 100, 300, usize::MAX);
        t.on_segment(&seg(true, BASE - 1, tcp_flags::SYN, &[]), 1_000);
        let stream = client_stream();
        t.on_segment(&seg(true, BASE, tcp_flags::ACK, &stream), 2_000);

        // A segment far ahead leaves a hole that never fills.
        let far = BASE + stream.len() as u32 + 10_000;
        t.on_segment(&seg(true, far, tcp_flags::ACK, b"\x00\x00\x00\x00\x04\x00\x00\x00\x00"), 3_000);
        t.tick(30_000_000);

        let (conns, usable, degraded) = t.snapshot(Some(0));
        assert_eq!((usable, degraded), (0, 1));
        let c2s = conns[0].dirs.iter().find(|d| d.dir == "c2s").unwrap();
        assert!(!c2s.usable);
        assert!(c2s.reason.as_deref().unwrap().contains("gap"), "{:?}", c2s.reason);
    }

    /// Joining an already-established connection is honest about it: the table
    /// is not fully known, so the snapshot is not offered as usable.
    #[test]
    fn midstream_join_is_reported_as_not_usable() {
        let mut t = Tracker::new(vec![7777], 100, 300, usize::MAX);
        let stream = client_stream();
        // No SYN, and we start partway in.
        t.on_segment(&seg(true, BASE, tcp_flags::ACK, &stream[30..]), 2_000);

        let (conns, usable, _) = t.snapshot(Some(0));
        assert_eq!(usable, 0);
        let c2s = conns[0].dirs.iter().find(|d| d.dir == "c2s").unwrap();
        assert!(!c2s.usable);
    }

    /// Port reuse must start a fresh connection, not continue the old table.
    #[test]
    fn port_reuse_starts_a_new_connection() {
        let mut t = Tracker::new(vec![7777], 100, 300, usize::MAX);
        t.on_segment(&seg(true, BASE - 1, tcp_flags::SYN, &[]), 1_000);
        t.on_segment(&seg(true, BASE, tcp_flags::ACK, &client_stream()), 2_000);
        let first_id = t.snapshot(Some(0)).0[0].conn_id.clone();

        // Same 5-tuple, new SYN: a different connection.
        t.on_segment(&seg(true, 7_000_000, tcp_flags::SYN, &[]), 9_000);
        let (conns, _, _) = t.snapshot(Some(0));
        assert_eq!(conns.len(), 1);
        assert_ne!(conns[0].conn_id, first_id, "must not reuse the old connection id");
        assert!(conns[0].dirs[0].entries.is_empty(), "table must start empty");
    }

    /// Pending bytes older than the capture ring cannot be in the pcap, so the
    /// direction must not be offered as usable.
    #[test]
    fn pending_bytes_outside_the_ring_are_refused() {
        let mut t = Tracker::new(vec![7777], 100, 300, usize::MAX);
        t.on_segment(&seg(true, BASE - 1, tcp_flags::SYN, &[]), 1_000);
        let stream = client_stream();
        // Deliver a partial frame: the parser keeps the tail buffered.
        let cut = stream.len() - 4;
        t.on_segment(&seg(true, BASE, tcp_flags::ACK, &stream[..cut]), 2_000);

        // Ring only goes back to t=5_000, after those bytes arrived.
        let (conns, usable, _) = t.snapshot(Some(5_000));
        assert_eq!(usable, 0);
        let c2s = conns[0].dirs.iter().find(|d| d.dir == "c2s").unwrap();
        assert!(c2s.reason.as_deref().unwrap().contains("ring"), "{:?}", c2s.reason);

        // With a ring that covers them, it is usable again.
        let (_, usable2, _) = t.snapshot(Some(0));
        assert_eq!(usable2, 1);
    }
}
