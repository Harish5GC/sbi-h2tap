//! Per-direction HTTP/2 state machine: reassembly -> framing -> HPACK.
//!
//! `h2tapd` and `h2rebuild` both drive this, which is what makes a snapshot
//! taken by one usable by the other. If the two ever framed differently, the
//! `next_frame_seq` in a snapshot would point at a byte the rebuilder does not
//! consider a frame boundary and every header after it would decode to
//! plausible nonsense.

use std::collections::HashSet;

use crate::frame::{
    self, check_frame_chain, header_block_fragment, ChainCheck, FrameHeader, FrameType,
    FRAME_HEADER_LEN, PREFACE,
};
use crate::hpack::{Decoder, Field};
use crate::reassembly::Reassembler;

/// Largest frame payload we will buffer. Beyond this we stay framed but drop
/// the payload rather than let one peer balloon our memory.
const MAX_BUFFERED_FRAME: usize = 1 << 20;
/// Buffer we keep while hunting for a frame boundary.
const RESYNC_WINDOW: usize = 1 << 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// First header block on the stream.
    Headers,
    /// A second header block on a stream, i.e. trailers.
    Trailers,
    PushPromise,
}

#[derive(Debug, Clone)]
pub struct DecodedBlock {
    pub stream_id: u32,
    pub fields: Vec<Field>,
    pub end_stream: bool,
    pub kind: BlockKind,
    /// Set for PUSH_PROMISE, which carries it ahead of the header block and
    /// therefore has to be reinstated when the block is re-encoded.
    pub promised_stream_id: Option<u32>,
    /// True only if this block decoded with no gaps at all: the dynamic table
    /// was fully known AND no reference in it went unresolved. The table can
    /// become exact partway through a block, so this deliberately does not
    /// track the decoder's own `exact` flag.
    pub exact: bool,
    /// Unresolved index references in this block.
    pub unresolved: usize,
}

#[derive(Debug, Clone)]
pub struct ProcessedFrame {
    pub hdr: FrameHeader,
    pub payload: Vec<u8>,
    /// Stream offset and absolute TCP sequence of the frame's first byte.
    pub start_off: u64,
    pub start_seq: u32,
    /// Set on the frame that completes a header block.
    pub decoded: Option<DecodedBlock>,
    /// HEADERS, CONTINUATION or PUSH_PROMISE: the rebuilder replaces these
    /// rather than passing them through.
    pub is_header_frame: bool,
    /// Payload was dropped instead of buffered.
    pub truncated: bool,
    /// SETTINGS_HEADER_TABLE_SIZE advertised here. It bounds the *peer's*
    /// encoder, so the caller applies it to the opposite direction.
    pub settings_table_size: Option<u32>,
}

#[derive(Debug)]
pub struct Direction {
    pub reasm: Reassembler,
    pub dec: Decoder,

    /// HPACK state cannot be trusted (a gap or a decode error occurred).
    pub poisoned: bool,
    /// Frame boundaries are unknown; we are hunting for one.
    pub desynced: bool,

    pub frames: u64,
    pub blocks: u64,
    pub decode_errors: u64,
    pub resyncs: u64,

    keep_payloads: bool,
    expect_preface: bool,
    /// Bytes of a frame payload still to be thrown away.
    discard: u64,
    /// Seek target set when seeding from a snapshot.
    pending_start_seq: Option<u32>,
    /// True if we ever found ourselves past the snapshot point, meaning the
    /// capture is missing bytes the snapshot assumed were present.
    pub snapshot_misaligned: bool,
    /// Bytes skipped because they precede the snapshot point. These are ring
    /// backfill from before the capture began; any header block wholly inside
    /// them is unrecoverable, because decoding it would need the table as it
    /// was *earlier* than the snapshot. Counted so the tool can say so rather
    /// than silently emit fewer blocks than the input contained.
    pub pre_snapshot_skipped: u64,

    /// Cap on dynamic table memory, re-applied whenever the decoder is
    /// replaced.
    table_track_limit: usize,

    block: Vec<u8>,
    block_hdr: Option<FrameHeader>,
    block_promised: Option<u32>,
    open_streams: HashSet<u32>,
}

impl Direction {
    /// A direction we joined mid-stream: frame boundaries unknown, table
    /// partially unknown.
    pub fn joined_midstream(keep_payloads: bool) -> Self {
        Direction {
            reasm: Reassembler::new(),
            dec: Decoder::new_partial(),
            poisoned: false,
            desynced: true,
            frames: 0,
            blocks: 0,
            decode_errors: 0,
            resyncs: 0,
            keep_payloads,
            expect_preface: false,
            discard: 0,
            pending_start_seq: None,
            snapshot_misaligned: false,
            pre_snapshot_skipped: 0,
            table_track_limit: usize::MAX,
            block: Vec::new(),
            block_hdr: None,
            block_promised: None,
            open_streams: HashSet::new(),
        }
    }

    /// A direction we have from its first byte.
    pub fn from_connection_start(keep_payloads: bool, expect_preface: bool) -> Self {
        let mut d = Self::joined_midstream(keep_payloads);
        d.dec = Decoder::new_exact();
        d.desynced = false;
        d.expect_preface = expect_preface;
        d
    }

    /// Cap how large a peer's dynamic table we will hold in memory. A peer
    /// that negotiates more is reported as untracked rather than allowed to
    /// exhaust the host.
    pub fn set_table_track_limit(&mut self, n: usize) {
        self.table_track_limit = n;
        self.dec.set_track_limit(n);
    }

    /// Seed from an `h2tapd` snapshot: the table is known in full, and framing
    /// restarts at `next_frame_seq`.
    pub fn seed_from_snapshot(&mut self, entries: Vec<Field>, max_size: usize, next_frame_seq: u32) {
        self.dec = Decoder::from_entries(entries, max_size);
        self.dec.set_track_limit(self.table_track_limit);
        self.desynced = false;
        self.poisoned = false;
        self.expect_preface = false;
        self.block.clear();
        self.block_hdr = None;
        self.block_promised = None;
        self.discard = 0;
        self.pending_start_seq = Some(next_frame_seq);
    }

    pub fn feed(&mut self, seq: u32, data: &[u8], now_us: u64) -> Vec<ProcessedFrame> {
        if self.reasm.push(seq, data, now_us) {
            self.on_gap();
        }
        self.parse()
    }

    pub fn tick(&mut self, now_us: u64) -> Vec<ProcessedFrame> {
        if self.reasm.check_timeout(now_us) {
            self.on_gap();
            return self.parse();
        }
        Vec::new()
    }

    /// Absolute sequence number of the next byte the frame parser has not
    /// consumed. This is what a snapshot records, and it is always a frame
    /// boundary because `parse()` only stops between frames.
    pub fn next_frame_seq(&self) -> u32 {
        self.reasm.next_unparsed_seq()
    }

    /// A direction is snapshottable only when we know both where the frame
    /// boundaries are and what the table holds.
    pub fn is_snapshottable(&self) -> bool {
        !self.poisoned && !self.desynced && self.dec.is_exact() && self.block_hdr.is_none()
    }

    fn on_gap(&mut self) {
        self.poisoned = true;
        self.desynced = true;
        self.discard = 0;
        self.block.clear();
        self.block_hdr = None;
        self.block_promised = None;
        // Entries we observed are still in the peer's table, but insertions we
        // missed during the gap have shifted them by an unknown amount, so our
        // indices are no longer meaningful. Start over rather than decode
        // confidently wrong headers.
        self.dec.reset_partial();
    }

    fn parse(&mut self) -> Vec<ProcessedFrame> {
        let mut out = Vec::new();
        loop {
            if self.discard > 0 {
                let avail = self.reasm.available().len() as u64;
                let n = self.discard.min(avail);
                if n == 0 {
                    break;
                }
                self.reasm.consume(n as usize);
                self.discard -= n;
                continue;
            }

            if let Some(target) = self.pending_start_seq {
                let delta = target.wrapping_sub(self.reasm.next_unparsed_seq()) as i32;
                if delta > 0 {
                    let avail = self.reasm.available().len();
                    let n = (delta as usize).min(avail);
                    if n == 0 {
                        break;
                    }
                    self.reasm.consume(n);
                    self.pre_snapshot_skipped += n as u64;
                    continue;
                }
                if delta < 0 {
                    // The capture starts after the snapshot point, so bytes the
                    // snapshot assumed we would see are missing. Refuse to
                    // pretend the table is right.
                    self.snapshot_misaligned = true;
                    self.dec.reset_partial();
                    self.desynced = true;
                }
                self.pending_start_seq = None;
                continue;
            }

            if self.desynced {
                if !self.try_resync() {
                    break;
                }
                continue;
            }

            if self.expect_preface {
                let a = self.reasm.available();
                if a.len() < PREFACE.len() {
                    break;
                }
                let matched = a.starts_with(PREFACE);
                self.expect_preface = false;
                if matched {
                    self.reasm.consume(PREFACE.len());
                }
                continue;
            }

            let (hdr, have) = {
                let a = self.reasm.available();
                if a.len() < FRAME_HEADER_LEN {
                    break;
                }
                (FrameHeader::parse(a).expect("length checked"), a.len())
            };

            let plen = hdr.len as usize;
            let start_off = self.reasm.offset();
            let start_seq = self.reasm.next_unparsed_seq();
            let is_hdr_frame = matches!(
                hdr.typ,
                FrameType::HEADERS | FrameType::CONTINUATION | FrameType::PUSH_PROMISE
            );
            let want_payload = (self.keep_payloads || is_hdr_frame || hdr.typ == FrameType::SETTINGS)
                && plen <= MAX_BUFFERED_FRAME;

            if !want_payload {
                self.reasm.consume(FRAME_HEADER_LEN);
                self.discard = plen as u64;
                self.frames += 1;
                out.push(ProcessedFrame {
                    hdr,
                    payload: Vec::new(),
                    start_off,
                    start_seq,
                    decoded: None,
                    is_header_frame: is_hdr_frame,
                    truncated: true,
                    settings_table_size: None,
                });
                continue;
            }

            if have < FRAME_HEADER_LEN + plen {
                break;
            }
            let payload = self.reasm.available()[FRAME_HEADER_LEN..FRAME_HEADER_LEN + plen].to_vec();
            self.reasm.consume(FRAME_HEADER_LEN + plen);
            self.frames += 1;
            out.push(self.handle_frame(hdr, payload, start_off, start_seq));
        }
        out
    }

    fn handle_frame(
        &mut self,
        hdr: FrameHeader,
        payload: Vec<u8>,
        start_off: u64,
        start_seq: u32,
    ) -> ProcessedFrame {
        let mut pf = ProcessedFrame {
            hdr,
            payload,
            start_off,
            start_seq,
            decoded: None,
            is_header_frame: false,
            truncated: false,
            settings_table_size: None,
        };

        match hdr.typ {
            FrameType::SETTINGS => {
                pf.settings_table_size = frame::settings_header_table_size(&hdr, &pf.payload);
            }
            FrameType::HEADERS | FrameType::PUSH_PROMISE => {
                pf.is_header_frame = true;
                // A new block while one is open is a protocol violation; the
                // safe reading is that we lost our place.
                if self.block_hdr.is_some() {
                    self.block.clear();
                }
                if hdr.typ == FrameType::PUSH_PROMISE {
                    // The promised stream id sits ahead of the block, after
                    // the pad-length byte when the frame is padded.
                    let mut p = &pf.payload[..];
                    if hdr.has(frame::flags::PADDED) && !p.is_empty() {
                        p = &p[1..];
                    }
                    if p.len() >= 4 {
                        self.block_promised =
                            Some(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
                    }
                }
                match header_block_fragment(&hdr, &pf.payload) {
                    Some(frag) => {
                        self.block.extend_from_slice(frag);
                        self.block_hdr = Some(hdr);
                        if hdr.has(frame::flags::END_HEADERS) {
                            pf.decoded = self.finish_block();
                        }
                    }
                    None => self.mark_bad_block(),
                }
            }
            FrameType::CONTINUATION => {
                pf.is_header_frame = true;
                if self.block_hdr.is_none() {
                    // CONTINUATION with no open block: we are out of step.
                    self.mark_bad_block();
                } else {
                    self.block.extend_from_slice(&pf.payload);
                    if hdr.has(frame::flags::END_HEADERS) {
                        pf.decoded = self.finish_block();
                    }
                }
            }
            _ => {}
        }

        pf
    }

    fn finish_block(&mut self) -> Option<DecodedBlock> {
        let bhdr = self.block_hdr.take()?;
        let promised = self.block_promised.take();
        let block = std::mem::take(&mut self.block);
        self.blocks += 1;

        let before = self.dec.unresolved_refs();
        let fields = match self.dec.decode(&block) {
            Ok(f) => f,
            Err(_) => {
                self.decode_errors += 1;
                self.poisoned = true;
                // Framing is probably still fine; it is the table that is now
                // untrustworthy.
                self.dec.reset_partial();
                return None;
            }
        };
        let unresolved = (self.dec.unresolved_refs() - before) as usize;

        let sid = bhdr.stream_id;
        let end_stream = bhdr.has(frame::flags::END_STREAM);
        let kind = if bhdr.typ == FrameType::PUSH_PROMISE {
            BlockKind::PushPromise
        } else if self.open_streams.contains(&sid) {
            BlockKind::Trailers
        } else {
            BlockKind::Headers
        };

        if bhdr.typ != FrameType::PUSH_PROMISE {
            if end_stream {
                self.open_streams.remove(&sid);
            } else {
                if self.open_streams.len() > 65_536 {
                    self.open_streams.clear();
                }
                self.open_streams.insert(sid);
            }
        }

        Some(DecodedBlock {
            stream_id: sid,
            fields,
            end_stream,
            kind,
            promised_stream_id: promised,
            exact: self.dec.is_exact() && unresolved == 0,
            unresolved,
        })
    }

    fn mark_bad_block(&mut self) {
        self.block.clear();
        self.block_hdr = None;
        self.block_promised = None;
        self.poisoned = true;
        self.desynced = true;
        self.dec.reset_partial();
    }

    /// Hunt for a frame boundary. Returns true when one was adopted.
    fn try_resync(&mut self) -> bool {
        let avail = self.reasm.available().len();
        if avail < FRAME_HEADER_LEN {
            return false;
        }

        let mut accept: Option<usize> = None;
        let mut wait = false;
        {
            let a = self.reasm.available();
            for off in 0..=a.len().saturating_sub(FRAME_HEADER_LEN) {
                match check_frame_chain(&a[off..], 4, 2) {
                    ChainCheck::Ok => {
                        accept = Some(off);
                        break;
                    }
                    // Plausible but not yet provable. Waiting beats skipping
                    // past what is very likely the real boundary.
                    ChainCheck::NeedMore => {
                        wait = true;
                        break;
                    }
                    ChainCheck::Bad => continue,
                }
            }
        }

        if let Some(off) = accept {
            self.reasm.consume(off);
            self.desynced = false;
            self.resyncs += 1;
            return true;
        }

        if !wait && avail > RESYNC_WINDOW {
            // Nothing plausible in a large window; drop the front so the
            // buffer cannot grow without bound.
            self.reasm.consume(avail - RESYNC_WINDOW);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::build_frame;
    use crate::hpack::encode_literal;

    fn c2s_stream() -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(PREFACE);
        s.extend_from_slice(&build_frame(FrameType::SETTINGS, 0, 0, &[0, 1, 0, 0, 16, 0]));
        // :method GET (idx 2), :scheme https (idx 7), then an indexed literal
        // so the dynamic table gains an entry.
        let mut blk = vec![0x82, 0x87];
        blk.push(0x40);
        blk.extend_from_slice(&[10]);
        blk.extend_from_slice(b"x-sbi-test");
        blk.extend_from_slice(&[3]);
        blk.extend_from_slice(b"amf");
        s.extend_from_slice(&build_frame(FrameType::HEADERS, 0x04, 1, &blk));
        s.extend_from_slice(&build_frame(FrameType::DATA, 0x01, 1, b"{\"supi\":\"imsi-1\"}"));
        s
    }

    #[test]
    fn parses_preface_settings_headers_and_data() {
        let mut d = Direction::from_connection_start(true, true);
        let s = c2s_stream();
        let frames = d.feed(1000, &s, 0);

        let types: Vec<u8> = frames.iter().map(|f| f.hdr.typ).collect();
        assert_eq!(types, vec![FrameType::SETTINGS, FrameType::HEADERS, FrameType::DATA]);
        assert_eq!(frames[0].settings_table_size, Some(4096));

        let blk = frames[1].decoded.as_ref().expect("headers decode");
        assert_eq!(blk.stream_id, 1);
        assert_eq!(blk.kind, BlockKind::Headers);
        assert!(blk.exact);
        assert_eq!(blk.unresolved, 0);
        assert_eq!(blk.fields[0].name_str(), ":method");
        assert_eq!(blk.fields[2].name_str(), "x-sbi-test");

        assert_eq!(frames[2].payload, b"{\"supi\":\"imsi-1\"}");
        assert!(d.is_snapshottable());
    }

    #[test]
    fn frame_split_across_segments_is_reassembled() {
        let mut d = Direction::from_connection_start(true, true);
        let s = c2s_stream();
        let (a, b) = s.split_at(20);
        let f1 = d.feed(1000, a, 0);
        assert!(f1.is_empty(), "nothing complete yet");
        let f2 = d.feed(1000 + a.len() as u32, b, 0);
        assert_eq!(f2.len(), 3);
    }

    #[test]
    fn continuation_frames_are_joined_before_decode() {
        let mut d = Direction::from_connection_start(true, false);
        let fields =
            vec![Field::new(&b":status"[..], &b"200"[..]), Field::new(&b"server"[..], &b"udm"[..])];
        let block = encode_literal(&fields);
        let (a, b) = block.split_at(3);
        let mut s = Vec::new();
        s.extend_from_slice(&build_frame(FrameType::HEADERS, 0, 1, a));
        s.extend_from_slice(&build_frame(FrameType::CONTINUATION, 0x04, 1, b));

        let frames = d.feed(1, &s, 0);
        assert!(frames[0].decoded.is_none());
        let blk = frames[1].decoded.as_ref().unwrap();
        assert_eq!(blk.fields.len(), 2);
        assert_eq!(blk.fields[1].value_str(), "udm");
    }

    #[test]
    fn second_header_block_on_a_stream_is_trailers() {
        let mut d = Direction::from_connection_start(true, false);
        let h = encode_literal(&[Field::new(&b":status"[..], &b"200"[..])]);
        let t = encode_literal(&[Field::new(&b"grpc-status"[..], &b"0"[..])]);
        let mut s = Vec::new();
        s.extend_from_slice(&build_frame(FrameType::HEADERS, 0x04, 3, &h));
        s.extend_from_slice(&build_frame(FrameType::HEADERS, 0x04 | 0x01, 3, &t));
        let frames = d.feed(1, &s, 0);
        assert_eq!(frames[0].decoded.as_ref().unwrap().kind, BlockKind::Headers);
        assert_eq!(frames[1].decoded.as_ref().unwrap().kind, BlockKind::Trailers);
    }

    /// Joining mid-stream: the parser must find the frame boundary on its own
    /// and must not claim the result is exact.
    #[test]
    fn midstream_join_resyncs_to_a_frame_boundary() {
        let mut d = Direction::joined_midstream(true);
        let s = c2s_stream();
        // Start 6 bytes into the DATA frame's neighbourhood: strip the preface
        // and part of the SETTINGS frame so we begin mid-frame.
        let cut = PREFACE.len() + 5;
        let frames = d.feed(500, &s[cut..], 0);

        assert!(!d.desynced, "should have found a boundary");
        assert!(frames.iter().any(|f| f.hdr.typ == FrameType::DATA));
        assert!(!d.dec.is_exact(), "a mid-stream join is never exact up front");
        assert!(!d.is_snapshottable());
    }

    /// A lost segment must poison the direction rather than silently decode
    /// against a stale table.
    #[test]
    fn gap_poisons_the_direction_and_resets_the_table() {
        let mut d = Direction::from_connection_start(true, true);
        let s = c2s_stream();
        d.feed(1000, &s, 0);
        assert!(d.is_snapshottable());

        // A segment far ahead leaves a hole that never fills.
        d.feed(1000 + s.len() as u32 + 5000, b"\x00\x00\x00\x00\x04\x00\x00\x00\x00", 0);
        d.tick(10_000_000);

        assert!(d.poisoned, "gap must poison");
        assert!(!d.is_snapshottable(), "must refuse to snapshot after a gap");
        assert!(!d.dec.is_exact());
    }

    #[test]
    fn snapshot_seed_skips_to_the_recorded_boundary() {
        // Build a stream, note where its second frame starts, then replay from
        // an earlier byte with a seed pointing at that boundary.
        let mut s = Vec::new();
        let h1 = encode_literal(&[Field::new(&b":status"[..], &b"200"[..])]);
        s.extend_from_slice(&build_frame(FrameType::DATA, 0, 7, b"leading-garbage"));
        let boundary = s.len();
        s.extend_from_slice(&build_frame(FrameType::HEADERS, 0x04, 9, &h1));

        let base = 4_000_000_000u32; // near wrap, to exercise the arithmetic
        let mut d = Direction::joined_midstream(true);
        d.seed_from_snapshot(Vec::new(), 4096, base.wrapping_add(boundary as u32));
        let frames = d.feed(base, &s, 0);

        assert_eq!(frames.len(), 1, "bytes before the boundary must be skipped");
        assert_eq!(frames[0].hdr.typ, FrameType::HEADERS);
        assert_eq!(frames[0].decoded.as_ref().unwrap().fields[0].value_str(), "200");
        assert!(!d.snapshot_misaligned);
    }

    #[test]
    fn snapshot_seed_detects_a_capture_that_starts_too_late() {
        let mut d = Direction::joined_midstream(true);
        // Snapshot says the boundary is at seq 1000, but our first byte is
        // 1500: the capture missed 500 bytes the snapshot assumed.
        d.seed_from_snapshot(Vec::new(), 4096, 1000);
        d.feed(1500, &build_frame(FrameType::DATA, 0, 1, b"xy"), 0);
        assert!(d.snapshot_misaligned, "must notice and refuse to trust the table");
    }
}
