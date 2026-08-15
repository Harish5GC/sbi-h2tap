//! Turn (pcap + snapshot) into a capture whose headers decode standalone.
//!
//! Every header block is re-encoded as literals with no indexing and no
//! Huffman, so the output needs no dynamic table at all and can be opened at
//! any point. Because that changes header block lengths, the TCP stream shifts
//! and the packets cannot be patched in place; the connection is synthesized
//! instead, preserving MACs, addresses, ports, stream ids, frame order and
//! timestamps, with fresh sequence numbers and recomputed checksums.
//!
//! The output is an analysis artifact, not a wire replica. Do not use it to
//! argue about anything TCP-level: packet boundaries, window behaviour and
//! retransmissions are all synthetic.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapReader, PcapWriter};
use pcap_file::{DataLink, TsResolution};
use serde_json::json;

use h2core::conn::{BlockKind, DecodedBlock, Direction};
use h2core::frame::{build_frame, flags, FrameType, DEFAULT_MAX_FRAME_SIZE, PREFACE};
use h2core::hpack::{encode_literal, Field};
use h2core::pkt::{build_tcp_packet, parse_ethernet, tcp_flags, Endpoint};
use h2core::snapshot::CaptureSnapshot;

/// Fixed initial sequence numbers. The normalized stream has different lengths
/// from the original, so original sequence numbers could not be preserved
/// anyway; fixed values make the output deterministic.
const ISN: [u32; 2] = [0x1000_0000, 0x2000_0000];
const WINDOW: u16 = 65535;

const C2S: usize = 0;
const S2C: usize = 1;

type Key = (IpAddr, u16, IpAddr, u16);

fn key_of(a: (IpAddr, u16), b: (IpAddr, u16)) -> Key {
    if (a.0, a.1) <= (b.0, b.1) {
        (a.0, a.1, b.0, b.1)
    } else {
        (b.0, b.1, a.0, a.1)
    }
}

pub struct Options {
    pub pcap: PathBuf,
    pub snapshot: Option<PathBuf>,
    pub out: PathBuf,
    pub jsonl: Option<PathBuf>,
    pub mss: usize,
}

#[derive(Debug, Default)]
pub struct Report {
    pub packets_in: u64,
    pub conns: usize,
    pub conns_seeded: usize,
    pub conns_misaligned: usize,
    pub header_blocks: usize,
    pub blocks_exact: usize,
    pub blocks_partial: usize,
    pub unresolved_refs: usize,
    pub decode_failures: usize,
    pub frames_dropped: usize,
    pub packets_out: u64,
    /// Bytes of ring backfill that precede a snapshot point, and the number of
    /// directions affected. Header blocks wholly inside this region cannot be
    /// decoded and are not emitted.
    pub pre_snapshot_bytes: u64,
    pub pre_snapshot_dirs: usize,
}

struct Seed {
    entries: Vec<Field>,
    max_size: usize,
    next_frame_seq: u32,
    usable: bool,
    reason: Option<String>,
}

struct DirState {
    dir: Direction,
    ep: Option<Endpoint>,
    /// Normalized frame bytes, tagged with the timestamp of the packet that
    /// completed the original frame.
    out: Vec<(u64, Vec<u8>)>,
    seeded: bool,
}

impl DirState {
    fn new() -> Self {
        DirState { dir: Direction::joined_midstream(true), ep: None, out: Vec::new(), seeded: false }
    }
}

struct ConnState {
    client: SocketAddr,
    server: SocketAddr,
    first_ts: u64,
    last_ts: u64,
    /// We saw this connection's SYN, so it began during the capture and its
    /// tables start empty. A snapshot entry on the same 5-tuple describes a
    /// *previous* connection and must not be applied.
    saw_syn: bool,
    dirs: [DirState; 2],
}

pub fn run(opts: Options) -> Result<Report, String> {
    let mut rep = Report::default();

    // ---- snapshot -------------------------------------------------------
    let mut seeds: HashMap<(String, String), Seed> = HashMap::new();
    if let Some(p) = &opts.snapshot {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let snap: CaptureSnapshot =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;
        for c in &snap.conns {
            for d in &c.dirs {
                seeds.insert(
                    (d.src.clone(), d.dst.clone()),
                    Seed {
                        entries: d.fields(),
                        max_size: d.max_table_size,
                        next_frame_seq: d.next_frame_seq,
                        usable: d.usable,
                        reason: d.reason.clone(),
                    },
                );
            }
        }
    }

    // ---- replay ---------------------------------------------------------
    let f = File::open(&opts.pcap).map_err(|e| format!("{}: {e}", opts.pcap.display()))?;
    let mut reader = PcapReader::new(f).map_err(|e| format!("{}: {e}", opts.pcap.display()))?;

    let mut jsonl = match &opts.jsonl {
        Some(p) => {
            Some(BufWriter::new(File::create(p).map_err(|e| format!("{}: {e}", p.display()))?))
        }
        None => None,
    };

    let mut conns: HashMap<Key, ConnState> = HashMap::new();
    let mut order: Vec<Key> = Vec::new();

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.map_err(|e| format!("reading {}: {e}", opts.pcap.display()))?;
        rep.packets_in += 1;
        let ts = pkt.timestamp.as_micros() as u64;
        let Some(seg) = parse_ethernet(&pkt.data) else { continue };

        let src = (seg.src_ip, seg.src_port);
        let dst = (seg.dst_ip, seg.dst_port);
        let k = key_of(src, dst);
        let fresh_syn = seg.has(tcp_flags::SYN) && !seg.has(tcp_flags::ACK);

        if fresh_syn && conns.contains_key(&k) {
            // Port reuse: this is a different connection on the same tuple.
            conns.remove(&k);
        }
        if !conns.contains_key(&k) {
            let (client, server) = if fresh_syn {
                (src, dst)
            } else if seeds.contains_key(&(fmt(src), fmt(dst))) {
                // The snapshot labels c2s src->dst, so a hit here means src is
                // the client.
                (src, dst)
            } else {
                (src, dst)
            };
            let mut cs = ConnState {
                client: SocketAddr::new(client.0, client.1),
                server: SocketAddr::new(server.0, server.1),
                first_ts: ts,
                last_ts: ts,
                saw_syn: fresh_syn,
                dirs: [DirState::new(), DirState::new()],
            };
            if fresh_syn {
                cs.dirs[C2S].dir = Direction::from_connection_start(true, true);
                cs.dirs[S2C].dir = Direction::from_connection_start(true, false);
            }
            conns.insert(k, cs);
            order.push(k);
            rep.conns += 1;
        }

        let Some(cs) = conns.get_mut(&k) else { continue };
        cs.last_ts = ts;
        let d = if SocketAddr::new(src.0, src.1) == cs.client { C2S } else { S2C };

        if cs.dirs[d].ep.is_none() {
            cs.dirs[d].ep = Some(Endpoint {
                eth_dst: seg.eth_dst,
                eth_src: seg.eth_src,
                src_ip: seg.src_ip,
                dst_ip: seg.dst_ip,
                src_port: seg.src_port,
                dst_port: seg.dst_port,
            });
        }

        // Seed the moment we first touch a direction, before any bytes are fed.
        // Never seed a connection whose SYN we saw: ports get reused, so a
        // snapshot entry on this tuple belongs to an earlier connection and
        // applying it would mean a stale table at a wrong offset.
        if !cs.dirs[d].seeded {
            cs.dirs[d].seeded = true;
            if cs.saw_syn {
                // Starts empty; nothing to seed.
            } else if let Some(s) = seeds.get(&(fmt(src), fmt(dst))) {
                if s.usable {
                    cs.dirs[d].dir.seed_from_snapshot(
                        s.entries.clone(),
                        s.max_size,
                        s.next_frame_seq,
                    );
                    rep.conns_seeded += 1;
                } else {
                    eprintln!(
                        "h2rebuild: {} -> {}: snapshot not usable ({}); decoding partially",
                        fmt(src),
                        fmt(dst),
                        s.reason.as_deref().unwrap_or("unspecified")
                    );
                }
            }
        }

        if seg.has(tcp_flags::SYN) {
            cs.dirs[d].dir.reasm.note_syn(seg.seq);
        }
        if seg.payload.is_empty() {
            continue;
        }

        let frames = cs.dirs[d].dir.feed(seg.seq, seg.payload, ts);
        let caps: Vec<u32> = frames.iter().filter_map(|f| f.settings_table_size).collect();

        let conn_label = format!("{}-{}", cs.client, cs.server);
        for f in &frames {
            if f.truncated {
                rep.frames_dropped += 1;
                continue;
            }
            if f.is_header_frame {
                let Some(blk) = &f.decoded else { continue };
                rep.header_blocks += 1;
                if blk.exact && blk.unresolved == 0 {
                    rep.blocks_exact += 1;
                } else {
                    rep.blocks_partial += 1;
                }
                rep.unresolved_refs += blk.unresolved;

                if let Some(w) = jsonl.as_mut() {
                    write_jsonl(w, ts, &conn_label, d, blk);
                }
                for bytes in encode_block(blk, opts_max_frame()) {
                    cs.dirs[d].out.push((ts, bytes));
                }
            } else {
                cs.dirs[d].out.push((
                    ts,
                    build_frame(f.hdr.typ, f.hdr.flags, f.hdr.stream_id, &f.payload),
                ));
            }
        }

        // A header block we could not decode still has to be visible, or the
        // rebuilt capture would quietly lose a message.
        let failures = cs.dirs[d].dir.decode_errors;
        if failures as usize > rep.decode_failures {
            let missing = failures as usize - rep.decode_failures;
            rep.decode_failures = failures as usize;
            for _ in 0..missing {
                let marker = DecodedBlock {
                    stream_id: 0,
                    fields: vec![Field::new(
                        &b"@hpack-decode-failed"[..],
                        &b"header block could not be decoded"[..],
                    )],
                    end_stream: false,
                    kind: BlockKind::Headers,
                    promised_stream_id: None,
                    exact: false,
                    unresolved: 0,
                };
                // Stream 0 is illegal for HEADERS, so use 1 to keep the frame
                // structurally valid while still standing out.
                let mut m = marker;
                m.stream_id = 1;
                for bytes in encode_block(&m, opts_max_frame()) {
                    cs.dirs[d].out.push((ts, bytes));
                }
            }
        }

        for c in caps {
            let other = 1 - d;
            cs.dirs[other].dir.dec.apply_peer_capacity(c as usize);
        }
    }

    for k in &order {
        if let Some(cs) = conns.get(k) {
            if cs.dirs.iter().any(|d| d.dir.snapshot_misaligned) {
                rep.conns_misaligned += 1;
            }
            for d in &cs.dirs {
                if d.dir.pre_snapshot_skipped > 0 {
                    rep.pre_snapshot_bytes += d.dir.pre_snapshot_skipped;
                    rep.pre_snapshot_dirs += 1;
                }
            }
        }
    }

    if let Some(w) = jsonl.as_mut() {
        let _ = w.flush();
    }

    // ---- synthesize -----------------------------------------------------
    write_pcap(&opts, &order, &mut conns, &mut rep)?;
    Ok(rep)
}

fn opts_max_frame() -> usize {
    DEFAULT_MAX_FRAME_SIZE
}

fn fmt(a: (IpAddr, u16)) -> String {
    SocketAddr::new(a.0, a.1).to_string()
}

/// Re-encode a decoded block as literal-only HEADERS (plus CONTINUATION when
/// it no longer fits in one frame).
fn encode_block(blk: &DecodedBlock, max_frame: usize) -> Vec<Vec<u8>> {
    let mut body = Vec::new();
    let typ = if blk.kind == BlockKind::PushPromise {
        if let Some(p) = blk.promised_stream_id {
            body.extend_from_slice(&(p & 0x7fff_ffff).to_be_bytes());
        }
        FrameType::PUSH_PROMISE
    } else {
        FrameType::HEADERS
    };
    body.extend_from_slice(&encode_literal(&blk.fields));

    // PADDED and PRIORITY are dropped: the padding is gone and the priority
    // bytes were stripped before decoding, so keeping the flags would lie.
    let base_flags = if blk.end_stream && typ == FrameType::HEADERS { flags::END_STREAM } else { 0 };

    let mut out = Vec::new();
    let max_frame = max_frame.max(1);
    let mut first = true;
    let mut rest = &body[..];
    loop {
        let n = rest.len().min(max_frame);
        let (chunk, tail) = rest.split_at(n);
        let last = tail.is_empty();
        let mut f = if first { base_flags } else { 0 };
        if last {
            f |= flags::END_HEADERS;
        }
        out.push(build_frame(
            if first { typ } else { FrameType::CONTINUATION },
            f,
            blk.stream_id,
            chunk,
        ));
        first = false;
        rest = tail;
        if last {
            break;
        }
    }
    out
}

fn write_jsonl(w: &mut BufWriter<File>, ts: u64, conn: &str, d: usize, blk: &DecodedBlock) {
    let headers: Vec<_> = blk
        .fields
        .iter()
        .map(|f| json!({"n": f.name_str(), "v": f.value_str(), "unresolved": f.unknown}))
        .collect();
    let rec = json!({
        "ts_us": ts,
        "conn": conn,
        "dir": if d == C2S { "c2s" } else { "s2c" },
        "stream": blk.stream_id,
        "kind": match blk.kind {
            BlockKind::Headers => "headers",
            BlockKind::Trailers => "trailers",
            BlockKind::PushPromise => "push_promise",
        },
        "end_stream": blk.end_stream,
        "hpack_exact": blk.exact,
        "unresolved_refs": blk.unresolved,
        "headers": headers,
    });
    let _ = writeln!(w, "{rec}");
}

struct OutPkt {
    ts: u64,
    phase: u8,
    conn: usize,
    seq_in_conn: usize,
    dir: usize,
    flags: u8,
    payload: Vec<u8>,
}

fn write_pcap(
    opts: &Options,
    order: &[Key],
    conns: &mut HashMap<Key, ConnState>,
    rep: &mut Report,
) -> Result<(), String> {
    let mut pkts: Vec<OutPkt> = Vec::new();
    let mut eps: Vec<[Endpoint; 2]> = Vec::new();

    for (ci, k) in order.iter().enumerate() {
        let Some(cs) = conns.get_mut(k) else { continue };

        // One direction may never have been captured; mirror the other.
        let ep_c2s = cs.dirs[C2S].ep.clone().or_else(|| cs.dirs[S2C].ep.clone().map(|e| e.reversed()));
        let ep_s2c = cs.dirs[S2C].ep.clone().or_else(|| cs.dirs[C2S].ep.clone().map(|e| e.reversed()));
        let (Some(a), Some(b)) = (ep_c2s, ep_s2c) else { continue };
        eps.push([a, b]);

        let mut n = 0usize;
        let mut push = |p: OutPkt, n: &mut usize| {
            let mut p = p;
            p.seq_in_conn = *n;
            *n += 1;
            pkts.push(p);
        };

        let t0 = cs.first_ts;
        push(OutPkt { ts: t0, phase: 0, conn: ci, seq_in_conn: 0, dir: C2S, flags: tcp_flags::SYN, payload: vec![] }, &mut n);
        push(OutPkt { ts: t0, phase: 0, conn: ci, seq_in_conn: 0, dir: S2C, flags: tcp_flags::SYN | tcp_flags::ACK, payload: vec![] }, &mut n);
        push(OutPkt { ts: t0, phase: 0, conn: ci, seq_in_conn: 0, dir: C2S, flags: tcp_flags::ACK, payload: vec![] }, &mut n);

        // Lead the client stream with the HTTP/2 preface so the rebuilt
        // capture identifies itself and dissectors pick it up without being
        // told to "decode as".
        let mut streams: [Vec<(u64, Vec<u8>)>; 2] =
            [std::mem::take(&mut cs.dirs[C2S].out), std::mem::take(&mut cs.dirs[S2C].out)];
        if !streams[C2S].is_empty() {
            streams[C2S].insert(0, (t0, PREFACE.to_vec()));
        }

        for (d, stream) in streams.iter().enumerate() {
            for (ts, bytes) in stream {
                for chunk in bytes.chunks(opts.mss.max(1)) {
                    push(
                        OutPkt {
                            ts: *ts,
                            phase: 1,
                            conn: ci,
                            seq_in_conn: 0,
                            dir: d,
                            flags: tcp_flags::PSH | tcp_flags::ACK,
                            payload: chunk.to_vec(),
                        },
                        &mut n,
                    );
                }
            }
        }

        let t1 = cs.last_ts.max(t0);
        push(OutPkt { ts: t1, phase: 2, conn: ci, seq_in_conn: 0, dir: C2S, flags: tcp_flags::FIN | tcp_flags::ACK, payload: vec![] }, &mut n);
        push(OutPkt { ts: t1, phase: 2, conn: ci, seq_in_conn: 0, dir: S2C, flags: tcp_flags::FIN | tcp_flags::ACK, payload: vec![] }, &mut n);
    }

    // Interleave connections by time, but keep each connection's own packets
    // in causal order.
    pkts.sort_by_key(|p| (p.ts, p.phase, p.conn, p.seq_in_conn));

    let file = File::create(&opts.out).map_err(|e| format!("{}: {e}", opts.out.display()))?;
    let header = PcapHeader {
        snaplen: 65535,
        datalink: DataLink::ETHERNET,
        ts_resolution: TsResolution::MicroSecond,
        ..Default::default()
    };
    let mut w = PcapWriter::with_header(BufWriter::new(file), header)
        .map_err(|e| format!("writing pcap header: {e}"))?;

    let mut next_seq: Vec<[u32; 2]> = vec![ISN; eps.len()];
    let mut ip_id: Vec<[u16; 2]> = vec![[0, 0]; eps.len()];

    for p in &pkts {
        if p.conn >= eps.len() {
            continue;
        }
        let d = p.dir;
        let other = 1 - d;
        let seq = next_seq[p.conn][d];
        // The peer's next expected byte: exactly right for a synthesized
        // stream with no loss.
        let ack = if p.flags & tcp_flags::ACK != 0 { next_seq[p.conn][other] } else { 0 };

        let frame = build_tcp_packet(
            &eps[p.conn][d],
            seq,
            ack,
            p.flags,
            WINDOW,
            ip_id[p.conn][d],
            &p.payload,
        );
        ip_id[p.conn][d] = ip_id[p.conn][d].wrapping_add(1);

        let consumed = p.payload.len() as u32
            + u32::from(p.flags & (tcp_flags::SYN | tcp_flags::FIN) != 0);
        next_seq[p.conn][d] = seq.wrapping_add(consumed);

        let pkt = PcapPacket::new(Duration::from_micros(p.ts), frame.len() as u32, &frame);
        w.write_packet(&pkt).map_err(|e| format!("writing packet: {e}"))?;
        rep.packets_out += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use h2core::frame::FrameType;
    use h2core::snapshot::{ConnSnapshot, DirSnapshot, Entry, Str, SNAPSHOT_VERSION};

    const CLIENT: &str = "10.0.0.1:41234";
    const SERVER: &str = "10.0.0.2:7777";
    const BASE_SEQ: u32 = 1_000_000;

    fn ep() -> Endpoint {
        Endpoint {
            eth_dst: [0x02, 0, 0, 0, 0, 2],
            eth_src: [0x02, 0, 0, 0, 0, 1],
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 41234,
            dst_port: 7777,
        }
    }

    /// Literal with incremental indexing, new name: inserts into the dynamic
    /// table, which is exactly what we need a pre-capture entry to be.
    fn lit_indexed(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut v = vec![0x40];
        v.push(name.len() as u8);
        v.extend_from_slice(name);
        v.push(value.len() as u8);
        v.extend_from_slice(value);
        v
    }

    /// A client stream where the second request references table entries the
    /// first request inserted. Returns (stream bytes, offset of request two).
    fn conversation() -> (Vec<u8>, usize) {
        let mut s = Vec::new();
        s.extend_from_slice(PREFACE);
        s.extend_from_slice(&build_frame(FrameType::SETTINGS, 0, 0, &[0, 1, 0, 0, 16, 0]));

        // Request one: indexed pseudo-headers plus two insertions.
        let mut b1 = vec![0x82, 0x87, 0x84]; // :method GET, :scheme https, :path /
        b1.extend_from_slice(&lit_indexed(b":authority", b"nrf.5gc"));
        b1.extend_from_slice(&lit_indexed(b"3gpp-sbi-target-apiroot", b"https://udm"));
        s.extend_from_slice(&build_frame(FrameType::HEADERS, flags::END_HEADERS, 1, &b1));

        let offset_req2 = s.len();

        // Request two: 0xbe and 0xbf are dynamic indices 62 and 63, i.e. the
        // two entries above. Undecodable without the table.
        let b2 = vec![0x82, 0x87, 0x84, 0xbf, 0xbe];
        s.extend_from_slice(&build_frame(
            FrameType::HEADERS,
            flags::END_HEADERS | flags::END_STREAM,
            3,
            &b2,
        ));
        s.extend_from_slice(&build_frame(FrameType::DATA, flags::END_STREAM, 1, b"{\"x\":1}"));
        (s, offset_req2)
    }

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("h2rebuild-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Write a pcap containing one packet carrying `bytes` at `seq`.
    fn write_input_pcap(path: &PathBuf, seq: u32, bytes: &[u8]) {
        let f = File::create(path).unwrap();
        let hdr = PcapHeader {
            datalink: DataLink::ETHERNET,
            ts_resolution: TsResolution::MicroSecond,
            ..Default::default()
        };
        let mut w = PcapWriter::with_header(BufWriter::new(f), hdr).unwrap();
        let frame = build_tcp_packet(
            &ep(),
            seq,
            1,
            tcp_flags::PSH | tcp_flags::ACK,
            65535,
            1,
            bytes,
        );
        w.write_packet(&PcapPacket::new(Duration::from_micros(1_700_000_000_000_000), frame.len() as u32, &frame))
            .unwrap();
    }

    fn write_snapshot(path: &PathBuf, next_frame_seq: u32, usable: bool) {
        // Newest first: index 62 is entries[0].
        let entries = vec![
            Entry {
                n: Str::from_bytes(b"3gpp-sbi-target-apiroot"),
                v: Str::from_bytes(b"https://udm"),
            },
            Entry { n: Str::from_bytes(b":authority"), v: Str::from_bytes(b"nrf.5gc") },
        ];
        let snap = CaptureSnapshot {
            version: SNAPSHOT_VERSION,
            capture_id: "t".into(),
            started_unix_us: 1,
            iface: "test".into(),
            pcap_path: "x".into(),
            conns_usable: 1,
            conns_degraded: 0,
            conns: vec![ConnSnapshot {
                conn_id: "t1".into(),
                client: CLIENT.into(),
                server: SERVER.into(),
                first_seen_unix_us: 1,
                dirs: vec![DirSnapshot {
                    dir: "c2s".into(),
                    src: CLIENT.into(),
                    dst: SERVER.into(),
                    next_frame_seq,
                    max_table_size: 4096,
                    capacity_observed: true,
                    table_size: 100,
                    usable,
                    reason: if usable { None } else { Some("test".into()) },
                    entries,
                }],
            }],
        };
        std::fs::write(path, serde_json::to_string_pretty(&snap).unwrap()).unwrap();
    }

    /// Decode the rebuilt pcap the way a fresh reader would: no prior state,
    /// no dynamic table. This is what Wireshark effectively does.
    fn decode_output(path: &PathBuf) -> Vec<Vec<(String, String)>> {
        let f = File::open(path).unwrap();
        let mut r = PcapReader::new(f).unwrap();
        let mut dir = Direction::from_connection_start(true, true);
        let mut blocks = Vec::new();
        while let Some(pkt) = r.next_packet() {
            let pkt = pkt.unwrap();
            let Some(seg) = parse_ethernet(&pkt.data) else { continue };
            if seg.src_port != 41234 || seg.payload.is_empty() {
                continue;
            }
            for f in dir.feed(seg.seq, seg.payload, 0) {
                if let Some(b) = f.decoded {
                    blocks.push(
                        b.fields
                            .iter()
                            .map(|x| (x.name_str().into_owned(), x.value_str().into_owned()))
                            .collect(),
                    );
                }
            }
        }
        assert!(!dir.poisoned, "rebuilt capture must decode cleanly");
        blocks
    }

    /// The headline claim: a capture that starts mid-connection, plus the
    /// snapshot, rebuilds into a capture that decodes fully on its own.
    #[test]
    fn midstream_capture_plus_snapshot_rebuilds_exactly() {
        let d = tmpdir();
        let (stream, off) = conversation();
        let inp = d.join("mid.pcap");
        let snap = d.join("mid.json");
        let out = d.join("mid-norm.pcap");

        // Capture begins at request two: request one, which built the table,
        // is not in the pcap at all.
        write_input_pcap(&inp, BASE_SEQ + off as u32, &stream[off..]);
        write_snapshot(&snap, BASE_SEQ + off as u32, true);

        let rep = run(Options {
            pcap: inp,
            snapshot: Some(snap),
            out: out.clone(),
            jsonl: None,
            mss: 1400,
        })
        .unwrap();

        assert_eq!(rep.conns_seeded, 1);
        assert_eq!(rep.header_blocks, 1);
        assert_eq!(rep.blocks_exact, 1, "seeded decode must be exact");
        assert_eq!(rep.unresolved_refs, 0);
        assert_eq!(rep.conns_misaligned, 0);

        let blocks = decode_output(&out);
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            blocks[0],
            vec![
                (":method".to_string(), "GET".to_string()),
                (":scheme".to_string(), "https".to_string()),
                (":path".to_string(), "/".to_string()),
                (":authority".to_string(), "nrf.5gc".to_string()),
                ("3gpp-sbi-target-apiroot".to_string(), "https://udm".to_string()),
            ],
            "headers that referenced pre-capture table entries must come back intact"
        );
    }

    /// Same capture without the snapshot: the tool must degrade visibly rather
    /// than invent plausible headers.
    #[test]
    fn midstream_capture_without_snapshot_marks_the_gaps() {
        let d = tmpdir();
        let (stream, off) = conversation();
        let inp = d.join("nosnap.pcap");
        let out = d.join("nosnap-norm.pcap");
        write_input_pcap(&inp, BASE_SEQ + off as u32, &stream[off..]);

        let rep =
            run(Options { pcap: inp, snapshot: None, out: out.clone(), jsonl: None, mss: 1400 })
                .unwrap();

        assert_eq!(rep.conns_seeded, 0);
        assert_eq!(rep.blocks_exact, 0);
        assert_eq!(rep.unresolved_refs, 2, "both pre-capture references are gaps");

        let blocks = decode_output(&out);
        let names: Vec<&str> = blocks[0].iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"@unresolved-idx-62"), "got {names:?}");
        assert!(names.contains(&"@unresolved-idx-63"), "got {names:?}");
    }

    /// A capture taken from connection setup needs no snapshot at all, and the
    /// rebuilt output must still be HPACK-free.
    #[test]
    fn full_capture_rebuilds_without_a_snapshot() {
        let d = tmpdir();
        let (stream, _) = conversation();
        let inp = d.join("full.pcap");
        let out = d.join("full-norm.pcap");
        let jsonl = d.join("full.jsonl");

        // Include the SYN so the rebuilder knows it has the stream from byte one.
        let f = File::create(&inp).unwrap();
        let hdr = PcapHeader {
            datalink: DataLink::ETHERNET,
            ts_resolution: TsResolution::MicroSecond,
            ..Default::default()
        };
        let mut w = PcapWriter::with_header(BufWriter::new(f), hdr).unwrap();
        let syn = build_tcp_packet(&ep(), BASE_SEQ - 1, 0, tcp_flags::SYN, 65535, 0, &[]);
        w.write_packet(&PcapPacket::new(Duration::from_micros(1000), syn.len() as u32, &syn))
            .unwrap();
        let data =
            build_tcp_packet(&ep(), BASE_SEQ, 1, tcp_flags::PSH | tcp_flags::ACK, 65535, 1, &stream);
        w.write_packet(&PcapPacket::new(Duration::from_micros(2000), data.len() as u32, &data))
            .unwrap();
        drop(w);

        let rep = run(Options {
            pcap: inp,
            snapshot: None,
            out: out.clone(),
            jsonl: Some(jsonl.clone()),
            mss: 1400,
        })
        .unwrap();

        assert_eq!(rep.header_blocks, 2);
        assert_eq!(rep.blocks_exact, 2);
        assert_eq!(rep.unresolved_refs, 0);

        let blocks = decode_output(&out);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1][4], ("3gpp-sbi-target-apiroot".into(), "https://udm".into()));

        let lines = std::fs::read_to_string(&jsonl).unwrap();
        assert_eq!(lines.lines().count(), 2);
        assert!(lines.contains("\"3gpp-sbi-target-apiroot\""));
    }

    /// An unusable snapshot must be ignored rather than applied at the wrong
    /// offset, which would produce confident nonsense.
    #[test]
    fn unusable_snapshot_is_not_applied() {
        let d = tmpdir();
        let (stream, off) = conversation();
        let inp = d.join("bad.pcap");
        let snap = d.join("bad.json");
        let out = d.join("bad-norm.pcap");
        write_input_pcap(&inp, BASE_SEQ + off as u32, &stream[off..]);
        write_snapshot(&snap, BASE_SEQ + off as u32, false);

        let rep =
            run(Options { pcap: inp, snapshot: Some(snap), out, jsonl: None, mss: 1400 }).unwrap();
        assert_eq!(rep.conns_seeded, 0);
        assert_eq!(rep.unresolved_refs, 2);
    }

    /// Ports get reused. A snapshot entry on a 5-tuple describes the
    /// connection that was live when the snapshot was taken; if a *new*
    /// connection appears on the same tuple during the capture, applying that
    /// table would mean stale entries at a wrong offset - the exact failure
    /// this whole design exists to prevent.
    #[test]
    fn snapshot_is_not_applied_to_a_new_connection_on_a_reused_tuple() {
        let d = tmpdir();
        let (stream, _) = conversation();
        let inp = d.join("reuse.pcap");
        let snap = d.join("reuse.json");
        let out = d.join("reuse-norm.pcap");

        // Snapshot describes an earlier connection on this tuple.
        write_snapshot(&snap, BASE_SEQ + 999_999, true);

        // The capture contains a brand new connection: SYN then the full
        // conversation from byte one.
        let f = File::create(&inp).unwrap();
        let hdr = PcapHeader {
            datalink: DataLink::ETHERNET,
            ts_resolution: TsResolution::MicroSecond,
            ..Default::default()
        };
        let mut w = PcapWriter::with_header(BufWriter::new(f), hdr).unwrap();
        let syn = build_tcp_packet(&ep(), BASE_SEQ - 1, 0, tcp_flags::SYN, 65535, 0, &[]);
        w.write_packet(&PcapPacket::new(Duration::from_micros(1000), syn.len() as u32, &syn))
            .unwrap();
        let data =
            build_tcp_packet(&ep(), BASE_SEQ, 1, tcp_flags::PSH | tcp_flags::ACK, 65535, 1, &stream);
        w.write_packet(&PcapPacket::new(Duration::from_micros(2000), data.len() as u32, &data))
            .unwrap();
        drop(w);

        let rep = run(Options {
            pcap: inp,
            snapshot: Some(snap),
            out: out.clone(),
            jsonl: None,
            mss: 1400,
        })
        .unwrap();

        assert_eq!(rep.conns_seeded, 0, "must not seed a connection we saw start");
        assert_eq!(rep.header_blocks, 2);
        assert_eq!(rep.blocks_exact, 2, "decoding from SYN is exact on its own");
        assert_eq!(rep.unresolved_refs, 0);

        // And the headers must be right, not the stale snapshot's values.
        let blocks = decode_output(&out);
        assert_eq!(blocks[1][3], (":authority".into(), "nrf.5gc".into()));
    }
}
