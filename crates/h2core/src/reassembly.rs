//! Single-direction TCP reassembly.
//!
//! We do this ourselves rather than lean on a library for one reason: the
//! snapshot format is keyed on **absolute TCP sequence numbers**. A dynamic
//! table is only meaningful at an exact byte position in the stream, so
//! `h2tapd` has to be able to say "this table is the state as of seq N" and
//! `h2rebuild` has to be able to seek to exactly that byte. Most reassembly
//! APIs hand you bytes and hide the sequence numbers.
//!
//! Stream offsets are tracked incrementally, so they stay correct across
//! sequence number wrap. `seq_at()` converts back with wrapping arithmetic.

/// Bytes of out-of-order data we will hold before declaring a gap.
const DEFAULT_OOO_LIMIT: usize = 1 << 20;
/// How long we wait for a hole to be filled before declaring a gap.
const DEFAULT_OOO_TIMEOUT_US: u64 = 2_000_000;
/// Consumed prefix we tolerate before compacting the buffer.
const COMPACT_THRESHOLD: usize = 1 << 16;

#[derive(Debug)]
pub struct Reassembler {
    base_seq: u32,
    /// Next absolute sequence number we expect in order.
    next_seq: u32,
    /// Stream offset of `next_seq`, i.e. total bytes accounted for including
    /// bytes skipped over a gap.
    delivered_off: u64,

    buf: Vec<u8>,
    /// Consumed prefix within `buf`.
    pos: usize,
    /// Stream offset of `buf[pos]`.
    buf_off: u64,

    ooo: Vec<(u32, Vec<u8>)>,
    ooo_bytes: usize,
    ooo_since_us: Option<u64>,
    ooo_limit: usize,
    ooo_timeout_us: u64,

    pub initialized: bool,
    pub saw_syn: bool,
    pub gaps: u64,
    pub bytes: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler {
            base_seq: 0,
            next_seq: 0,
            delivered_off: 0,
            buf: Vec::new(),
            pos: 0,
            buf_off: 0,
            ooo: Vec::new(),
            ooo_bytes: 0,
            ooo_since_us: None,
            ooo_limit: DEFAULT_OOO_LIMIT,
            ooo_timeout_us: DEFAULT_OOO_TIMEOUT_US,
            initialized: false,
            saw_syn: false,
            gaps: 0,
            bytes: 0,
        }
    }

    /// Record the SYN for this direction. Data starts at seq+1, and seeing it
    /// means we have the connection from its very first byte, so the HPACK
    /// table for this direction starts genuinely empty.
    pub fn note_syn(&mut self, seq: u32) {
        if self.initialized {
            return;
        }
        self.base_seq = seq.wrapping_add(1);
        self.next_seq = self.base_seq;
        self.initialized = true;
        self.saw_syn = true;
    }

    /// Unconsumed, in-order bytes.
    pub fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Stream offset of the first unconsumed byte.
    pub fn offset(&self) -> u64 {
        self.buf_off
    }

    /// Absolute TCP sequence number of a stream offset.
    pub fn seq_at(&self, off: u64) -> u32 {
        self.base_seq.wrapping_add(off as u32)
    }

    /// Absolute sequence number of the first unconsumed byte. This is what
    /// goes into a snapshot as `next_frame_seq` once the frame parser has
    /// consumed every complete frame.
    pub fn next_unparsed_seq(&self) -> u32 {
        self.seq_at(self.buf_off)
    }

    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.buf.len() - self.pos);
        self.pos += n;
        self.buf_off += n as u64;
        if self.pos >= COMPACT_THRESHOLD {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    /// Feed one TCP segment. Returns true if a gap was declared, which means
    /// the HPACK state for this direction can no longer be trusted.
    pub fn push(&mut self, seq: u32, data: &[u8], now_us: u64) -> bool {
        if data.is_empty() {
            return false;
        }
        if !self.initialized {
            self.base_seq = seq;
            self.next_seq = seq;
            self.initialized = true;
        }

        let diff = seq.wrapping_sub(self.next_seq) as i32;
        if diff == 0 {
            self.append(data);
        } else if diff < 0 {
            // Retransmission or overlap. Keep only the genuinely new tail.
            let overlap = (-(diff as i64)) as usize;
            if overlap >= data.len() {
                return false; // wholly old
            }
            self.append(&data[overlap..]);
        } else {
            // Future segment: hold it and wait for the hole to fill.
            self.ooo.push((seq, data.to_vec()));
            self.ooo_bytes += data.len();
            self.ooo_since_us.get_or_insert(now_us);
            if self.ooo_bytes > self.ooo_limit {
                return self.force_gap();
            }
            return false;
        }

        self.drain_ooo();
        false
    }

    /// Called periodically so a hole that never fills eventually becomes a
    /// declared gap rather than silently stalling the direction.
    pub fn check_timeout(&mut self, now_us: u64) -> bool {
        if let Some(since) = self.ooo_since_us {
            if now_us.saturating_sub(since) > self.ooo_timeout_us {
                return self.force_gap();
            }
        }
        false
    }

    fn append(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.next_seq = self.next_seq.wrapping_add(data.len() as u32);
        self.delivered_off += data.len() as u64;
        self.bytes += data.len() as u64;
    }

    fn drain_ooo(&mut self) {
        loop {
            let mut best: Option<usize> = None;
            for (i, (seq, data)) in self.ooo.iter().enumerate() {
                let d = seq.wrapping_sub(self.next_seq) as i32;
                if d <= 0 && (-(d as i64)) as usize >= data.len() {
                    // Entirely behind us now.
                    best = Some(i);
                    break;
                }
                if d <= 0 {
                    best = Some(i);
                    break;
                }
            }
            let Some(i) = best else { break };
            let (seq, data) = self.ooo.remove(i);
            self.ooo_bytes -= data.len();
            let overlap = (-(seq.wrapping_sub(self.next_seq) as i32 as i64)) as usize;
            if overlap < data.len() {
                self.append(&data[overlap..]);
            }
        }
        if self.ooo.is_empty() {
            self.ooo_since_us = None;
        }
    }

    /// Give up on a hole: jump forward to the earliest buffered segment and
    /// mark the direction as having lost bytes.
    fn force_gap(&mut self) -> bool {
        self.gaps += 1;

        // Earliest segment ahead of us, by wrapped distance.
        let target = self
            .ooo
            .iter()
            .map(|(s, _)| *s)
            .min_by_key(|s| s.wrapping_sub(self.next_seq))
            .unwrap_or(self.next_seq);

        let skip = target.wrapping_sub(self.next_seq) as u64;
        self.delivered_off += skip;
        self.next_seq = target;

        // Framing is broken across the hole, so anything still pending is
        // unusable. Drop it and realign offsets to the new position.
        self.buf.clear();
        self.pos = 0;
        self.buf_off = self.delivered_off;
        self.ooo_since_us = None;

        self.drain_ooo();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_segments_map_to_absolute_seq() {
        let mut r = Reassembler::new();
        r.push(1000, b"abc", 0);
        r.push(1003, b"def", 0);
        assert_eq!(r.available(), b"abcdef");
        assert_eq!(r.next_unparsed_seq(), 1000);

        r.consume(4);
        assert_eq!(r.available(), b"ef");
        // Four bytes consumed, so the next unparsed byte is seq 1004.
        assert_eq!(r.next_unparsed_seq(), 1004);
    }

    #[test]
    fn syn_sets_the_base_one_past() {
        let mut r = Reassembler::new();
        r.note_syn(500);
        r.push(501, b"hello", 0);
        assert_eq!(r.next_unparsed_seq(), 501);
        assert!(r.saw_syn);
    }

    #[test]
    fn retransmission_is_deduplicated() {
        let mut r = Reassembler::new();
        r.push(10, b"abcd", 0);
        r.push(10, b"abcd", 0); // pure retransmit
        r.push(12, b"cdef", 0); // overlapping retransmit with new tail
        assert_eq!(r.available(), b"abcdef");
    }

    #[test]
    fn out_of_order_is_held_then_drained() {
        let mut r = Reassembler::new();
        r.push(100, b"aa", 0);
        assert!(!r.push(104, b"cc", 0)); // arrives early, buffered
        assert_eq!(r.available(), b"aa");
        assert!(!r.push(102, b"bb", 0)); // fills the hole
        assert_eq!(r.available(), b"aabbcc");
        assert_eq!(r.gaps, 0);
    }

    #[test]
    fn unfilled_hole_becomes_a_gap_and_offsets_stay_aligned() {
        let mut r = Reassembler::new();
        r.push(100, b"aa", 0);
        r.push(110, b"zz", 0); // hole at 102..110
        assert!(r.check_timeout(10_000_000), "stale hole must declare a gap");
        assert_eq!(r.gaps, 1);
        // We jumped to seq 110 and dropped the pending bytes, but the offset
        // to sequence mapping must still hold.
        assert_eq!(r.available(), b"zz");
        assert_eq!(r.next_unparsed_seq(), 110);
    }

    #[test]
    fn offsets_survive_sequence_wrap() {
        let mut r = Reassembler::new();
        // Four bytes at MAX-3..=MAX, so the next byte is seq 0.
        let start = u32::MAX - 3;
        r.push(start, b"abcd", 0);
        r.push(0, b"efgh", 0);
        assert_eq!(r.available(), b"abcdefgh");
        assert_eq!(r.next_unparsed_seq(), start);
        r.consume(6);
        assert_eq!(r.next_unparsed_seq(), 2);
    }
}
