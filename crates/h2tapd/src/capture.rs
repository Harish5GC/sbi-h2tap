//! The capture thread. It owns all connection state, which is why the control
//! API talks to it over a channel rather than sharing a lock.
//!
//! Starting a capture is a single step taken between two packets: flush the
//! ring buffer into the pcap, then snapshot the tables. Because both happen at
//! the same point in the same packet stream, the snapshot is aligned with the
//! pcap by construction rather than by timing luck. That is the whole reason
//! the daemon writes the pcap itself instead of leaving it to tcpdump.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::{DataLink, TsResolution};
use serde::Deserialize;
use serde_json::{json, Value};

use h2core::pkt::parse_ethernet;
use h2core::snapshot::{CaptureSnapshot, SNAPSHOT_VERSION};

use crate::sock::PacketSocket;
use crate::tracker::Tracker;

pub fn unix_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct StartReq {
    pub name: Option<String>,
    pub pcap: Option<String>,
    pub snapshot: Option<String>,
}

pub enum Cmd {
    Connections(Sender<Value>),
    Health(Sender<Value>),
    Start { req: StartReq, reply: Sender<Result<Value, String>> },
    Stop { id: Option<String>, reply: Sender<Result<Value, String>> },
}

#[derive(Debug, Clone)]
pub struct Config {
    pub iface: String,
    pub ports: Vec<u16>,
    pub out_dir: PathBuf,
    pub ring_bytes: usize,
    pub idle_secs: u64,
    pub max_conns: usize,
    pub promiscuous: bool,
    pub snaplen: u32,
    pub ring_secs: u64,
    pub max_table_bytes: usize,
    pub kernel_filter: bool,
    pub read_buffer_bytes: usize,
}

/// Recent packets, kept so that a capture can start slightly "in the past".
///
/// When a capture begins, a direction may be holding a partially received
/// frame whose earlier bytes are already consumed. Those bytes have to be in
/// the pcap or the rebuilder cannot frame from `next_frame_seq`. Replaying the
/// ring guarantees the pcap starts at or before every direction's snapshot
/// point.
struct Ring {
    q: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    limit: usize,
    max_age_us: u64,
}

impl Ring {
    fn new(limit: usize, max_age_secs: u64) -> Self {
        Ring { q: VecDeque::new(), bytes: 0, limit, max_age_us: max_age_secs * 1_000_000 }
    }

    fn push(&mut self, ts_us: u64, data: &[u8]) {
        self.bytes += data.len();
        self.q.push_back((ts_us, data.to_vec()));
        // Bound by age as well as size. The backfill exists only to complete
        // partially received frames, which is a matter of seconds. Keeping
        // more drags long-dead connections into the capture that the snapshot
        // knows nothing about, and they can only decode partially.
        let cutoff = ts_us.saturating_sub(self.max_age_us);
        while let Some((t, _)) = self.q.front() {
            if *t >= cutoff {
                break;
            }
            if let Some((_, d)) = self.q.pop_front() {
                self.bytes -= d.len();
            }
        }
        while self.bytes > self.limit {
            match self.q.pop_front() {
                Some((_, d)) => self.bytes -= d.len(),
                None => break,
            }
        }
    }

    fn oldest_us(&self) -> Option<u64> {
        self.q.front().map(|(t, _)| *t)
    }
}

struct Session {
    id: String,
    pcap_path: PathBuf,
    snapshot_path: PathBuf,
    writer: PcapWriter<BufWriter<File>>,
    packets: u64,
    bytes: u64,
    started_us: u64,
    conns_usable: usize,
    conns_degraded: usize,
}

impl Session {
    fn write(&mut self, ts_us: u64, data: &[u8]) {
        let pkt = PcapPacket::new(Duration::from_micros(ts_us), data.len() as u32, data);
        if self.writer.write_packet(&pkt).is_ok() {
            self.packets += 1;
            self.bytes += data.len() as u64;
        }
    }

    fn summary(&self) -> Value {
        json!({
            "capture_id": self.id,
            "pcap": self.pcap_path,
            "snapshot": self.snapshot_path,
            "packets": self.packets,
            "bytes": self.bytes,
            "started_unix_us": self.started_us,
            "conns_usable": self.conns_usable,
            "conns_degraded": self.conns_degraded,
        })
    }
}

pub fn run(cfg: Config, cmds: Receiver<Cmd>) -> Result<(), String> {
    let iface = pnet_datalink::interfaces()
        .into_iter()
        .find(|i| i.name == cfg.iface)
        .ok_or_else(|| format!("interface {} not found", cfg.iface))?;

    // We create the socket ourselves so we keep the descriptor: pnet exposes
    // neither the kernel's drop counter nor a way to attach a filter. The
    // filter is attached before pnet binds, so no unfiltered packet is ever
    // queued on it.
    let mut psock = PacketSocket::open(&cfg.ports, cfg.kernel_filter).map_err(|e| {
        format!(
            "opening packet socket: {e} (raw capture needs CAP_NET_RAW; try: setcap cap_net_raw,cap_net_admin=eip <binary>)"
        )
    })?;

    let dl_cfg = pnet_datalink::Config {
        read_timeout: Some(Duration::from_millis(100)),
        read_buffer_size: cfg.read_buffer_bytes,
        promiscuous: cfg.promiscuous,
        socket_fd: Some(psock.fd),
        ..Default::default()
    };

    let mut rx = match pnet_datalink::channel(&iface, dl_cfg) {
        Ok(pnet_datalink::Channel::Ethernet(_tx, rx)) => rx,
        Ok(_) => return Err("unsupported channel type".into()),
        Err(e) => {
            return Err(format!(
                "opening {}: {e} (raw capture needs CAP_NET_RAW; try: sudo setcap cap_net_raw,cap_net_admin=eip <binary>)",
                cfg.iface
            ))
        }
    };

    let mut tracker = Tracker::new(cfg.ports.clone(), cfg.max_conns, cfg.idle_secs, cfg.max_table_bytes);
    let mut ring = Ring::new(cfg.ring_bytes, cfg.ring_secs);
    let mut session: Option<Session> = None;
    let mut last_tick = unix_us();
    let mut read_errors: u64 = 0;

    eprintln!(
        "h2tapd: watching {} for tcp ports {} ({} filter, {} MiB read buffer)",
        cfg.iface,
        if cfg.ports.is_empty() { "ALL".to_string() } else { fmt_ports(&cfg.ports) },
        if psock.filtered_in_kernel { "kernel" } else { "userspace" },
        cfg.read_buffer_bytes >> 20
    );

    loop {
        // Commands are handled between packets, so "state right now" always
        // means "state after every packet already in the ring".
        while let Ok(cmd) = cmds.try_recv() {
            match cmd {
                Cmd::Connections(reply) => {
                    let _ = reply.send(connections_json(&tracker));
                }
                Cmd::Health(reply) => {
                    let (kp, kd) = psock.stats();
                    let _ = reply.send(health_json(
                        &tracker, &session, &ring, read_errors, kp, kd,
                        psock.filtered_in_kernel,
                    ));
                }
                Cmd::Start { req, reply } => {
                    let r = start_capture(&cfg, &tracker, &ring, req, &mut session);
                    let _ = reply.send(r);
                }
                Cmd::Stop { id, reply } => {
                    let r = match session.take() {
                        Some(s) if id.is_none() || id.as_deref() == Some(s.id.as_str()) => {
                            Ok(s.summary())
                        }
                        Some(s) => {
                            let want = id.unwrap_or_default();
                            let have = s.id.clone();
                            session = Some(s);
                            Err(format!("no capture {want} (running: {have})"))
                        }
                        None => Err("no capture is running".to_string()),
                    };
                    let _ = reply.send(r);
                }
            }
        }

        match rx.next() {
            Ok(frame) => {
                let now = unix_us();
                let seg = parse_ethernet(frame);
                let interesting = match &seg {
                    Some(s) => {
                        cfg.ports.is_empty()
                            || cfg.ports.contains(&s.src_port)
                            || cfg.ports.contains(&s.dst_port)
                    }
                    None => false,
                };
                if interesting {
                    if let Some(s) = session.as_mut() {
                        s.write(now, frame);
                    }
                    ring.push(now, frame);
                    if let Some(seg) = seg {
                        tracker.on_segment(&seg, now);
                    }
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {}
                _ => {
                    read_errors += 1;
                    if read_errors % 1000 == 1 {
                        eprintln!("h2tapd: capture read error: {e}");
                    }
                }
            },
        }

        let now = unix_us();
        if now.saturating_sub(last_tick) > 1_000_000 {
            tracker.tick(now);
            // Poll the kernel counters on a timer too: reading resets them, so
            // leaving them unread for a long time risks the u32 wrapping.
            psock.stats();
            last_tick = now;
        }
    }
}

fn start_capture(
    cfg: &Config,
    tracker: &Tracker,
    ring: &Ring,
    req: StartReq,
    session: &mut Option<Session>,
) -> Result<Value, String> {
    if let Some(s) = session {
        return Err(format!("capture {} is already running", s.id));
    }

    let started_us = unix_us();
    let id = req.name.clone().unwrap_or_else(|| format!("cap-{started_us}"));
    if id.contains(['/', '\\']) {
        return Err("capture name must not contain path separators".into());
    }

    let pcap_path =
        req.pcap.map(PathBuf::from).unwrap_or_else(|| cfg.out_dir.join(format!("{id}.pcap")));
    let snapshot_path = req
        .snapshot
        .map(PathBuf::from)
        .unwrap_or_else(|| cfg.out_dir.join(format!("{id}.snapshot.json")));

    for p in [&pcap_path, &snapshot_path] {
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
    }

    let file = File::create(&pcap_path).map_err(|e| format!("{}: {e}", pcap_path.display()))?;
    let header = PcapHeader {
        snaplen: cfg.snaplen,
        datalink: DataLink::ETHERNET,
        ts_resolution: TsResolution::MicroSecond,
        ..Default::default()
    };
    let mut writer = PcapWriter::with_header(BufWriter::new(file), header)
        .map_err(|e| format!("writing pcap header: {e}"))?;

    // Replay the ring first: this is what guarantees the pcap starts at or
    // before every direction's next_frame_seq.
    let mut packets = 0u64;
    let mut bytes = 0u64;
    for (ts, data) in ring.q.iter() {
        let pkt = PcapPacket::new(Duration::from_micros(*ts), data.len() as u32, data);
        if writer.write_packet(&pkt).is_ok() {
            packets += 1;
            bytes += data.len() as u64;
        }
    }

    // Snapshot as of exactly this point in the packet stream.
    let (conns, usable, degraded) = tracker.snapshot(ring.oldest_us());
    let snap = CaptureSnapshot {
        version: SNAPSHOT_VERSION,
        capture_id: id.clone(),
        started_unix_us: started_us,
        iface: cfg.iface.clone(),
        pcap_path: pcap_path.to_string_lossy().into_owned(),
        conns_usable: usable,
        conns_degraded: degraded,
        conns,
    };
    let json = serde_json::to_string_pretty(&snap).map_err(|e| e.to_string())?;
    fs::write(&snapshot_path, json).map_err(|e| format!("{}: {e}", snapshot_path.display()))?;

    let degraded_detail: Vec<Value> = snap
        .conns
        .iter()
        .flat_map(|c| {
            c.dirs.iter().filter(|d| !d.usable).map(move |d| {
                json!({ "conn_id": c.conn_id, "dir": d.dir, "reason": d.reason })
            })
        })
        .collect();

    *session = Some(Session {
        id: id.clone(),
        pcap_path: pcap_path.clone(),
        snapshot_path: snapshot_path.clone(),
        writer,
        packets,
        bytes,
        started_us,
        conns_usable: usable,
        conns_degraded: degraded,
    });

    Ok(json!({
        "capture_id": id,
        "pcap": pcap_path,
        "snapshot": snapshot_path,
        "backfilled_packets": packets,
        "backfilled_bytes": bytes,
        "conns_total": snap.conns.len(),
        "conns_usable": usable,
        "conns_degraded": degraded,
        "degraded": degraded_detail,
    }))
}

fn connections_json(tracker: &Tracker) -> Value {
    let now = unix_us();
    let conns: Vec<Value> = tracker
        .iter()
        .map(|c| {
            let d = |name: &str, t: &crate::tracker::DirTrack| {
                json!({
                    "dir": name,
                    "snapshottable": t.dir.is_snapshottable(),
                    "exact": t.dir.dec.is_exact(),
                    "poisoned": t.dir.poisoned,
                    "desynced": t.dir.desynced,
                    "next_frame_seq": t.dir.next_frame_seq(),
                    "table_entries": t.dir.dec.entries().count(),
                    "table_size": t.dir.dec.table_size(),
                    "max_table_size": t.dir.dec.max_size(),
                    "capacity_observed": t.dir.dec.capacity_observed(),
                    "table_untracked": t.dir.dec.over_limit(),
                    "frames": t.dir.frames,
                    "header_blocks": t.dir.blocks,
                    "unresolved_refs": t.dir.dec.unresolved_refs(),
                    "gaps": t.dir.reasm.gaps,
                    "resyncs": t.dir.resyncs,
                    "decode_errors": t.dir.decode_errors,
                    "bytes": t.dir.reasm.bytes,
                })
            };
            json!({
                "conn_id": c.id,
                "client": c.client.to_string(),
                "server": c.server.to_string(),
                "age_s": now.saturating_sub(c.first_seen_us) / 1_000_000,
                "idle_s": now.saturating_sub(c.last_seen_us) / 1_000_000,
                "closing": c.closed_at_us.is_some(),
                "dirs": [d("c2s", &c.c2s), d("s2c", &c.s2c)],
            })
        })
        .collect();
    json!({ "count": conns.len(), "conns": conns })
}

#[allow(clippy::too_many_arguments)]
fn health_json(
    tracker: &Tracker,
    session: &Option<Session>,
    ring: &Ring,
    read_errors: u64,
    kernel_packets: u64,
    kernel_drops: u64,
    kernel_filter: bool,
) -> Value {
    let mut gaps = 0u64;
    let mut poisoned = 0usize;
    let mut exact = 0usize;
    let mut dirs = 0usize;
    for c in tracker.iter() {
        for t in [&c.c2s, &c.s2c] {
            dirs += 1;
            gaps += t.dir.reasm.gaps;
            if t.dir.poisoned {
                poisoned += 1;
            }
            if t.dir.dec.is_exact() {
                exact += 1;
            }
        }
    }
    json!({
        "conns": tracker.len(),
        "dirs": dirs,
        "dirs_exact": exact,
        "dirs_poisoned": poisoned,
        // What the kernel handed us, and what it threw away because we were
        // not reading fast enough. kernel_drops is the early warning: it rises
        // before a gap corrupts anything, and any non-zero value means this
        // host cannot keep up with its own traffic.
        "kernel_packets": kernel_packets,
        "kernel_drops": kernel_drops,
        "kernel_filter": kernel_filter,
        // A packet the daemon never saw shows up here as a reassembly gap.
        // That is the consequence: a gap means the table for that direction is
        // no longer trustworthy, and it is reported as such.
        "reassembly_gaps": gaps,
        "segments": tracker.segments,
        "conns_evicted": tracker.evicted,
        "conns_rejected_table_full": tracker.rejected_full,
        "capture_read_errors": read_errors,
        "ring_packets": ring.q.len(),
        "ring_bytes": ring.bytes,
        "ring_span_s": ring.oldest_us().map(|o| (unix_us().saturating_sub(o)) / 1_000_000),
        "ring_oldest_unix_us": ring.oldest_us(),
        "capture": session.as_ref().map(|s| s.summary()),
    })
}

fn fmt_ports(ports: &[u16]) -> String {
    ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::Ring;

    #[test]
    fn ring_is_bounded_by_age_not_just_size() {
        let mut r = Ring::new(1 << 20, 5);
        r.push(1_000_000, &[0u8; 100]); // t = 1s
        r.push(2_000_000, &[0u8; 100]); // t = 2s
        assert_eq!(r.q.len(), 2);

        // A packet 10s later must age both out: the backfill only needs to
        // cover a partially received frame, and keeping hours of history drags
        // long-dead connections into the capture.
        r.push(12_000_000, &[0u8; 100]);
        assert_eq!(r.q.len(), 1);
        assert_eq!(r.oldest_us(), Some(12_000_000));
        assert_eq!(r.bytes, 100, "byte accounting must follow the eviction");
    }

    #[test]
    fn ring_still_respects_the_byte_limit() {
        let mut r = Ring::new(250, 3600);
        for i in 0..5 {
            r.push(1_000_000 + i, &[0u8; 100]);
        }
        assert!(r.bytes <= 250, "bytes={}", r.bytes);
        assert_eq!(r.q.len(), 2);
    }
}
