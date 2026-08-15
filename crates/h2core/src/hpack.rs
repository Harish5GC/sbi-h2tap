//! HPACK (RFC 7541) with a tolerant decoder.
//!
//! This differs from a conforming decoder in exactly one way, and that
//! difference is the reason the tool exists: when it meets an index pointing
//! at a dynamic table entry that was inserted *before* we started watching the
//! connection, it emits a placeholder instead of failing.
//!
//! The index arithmetic stays exact even then:
//!
//!   * Dynamic indices start at 62, and 62 is always the newest entry, so each
//!     insertion shifts existing entries up by one.
//!   * Eviction is from the tail, oldest first. Every pre-capture entry is
//!     older than every entry we observed, so the unknown region is always a
//!     suffix of the table and always evicts first.
//!   * Therefore an entry we watched being inserted keeps the index it would
//!     have had if the unknown region did not exist. Ordinary accounting over
//!     our own entries is correct from the first packet.
//!   * Once our own entries fill the table to within `MIN_ENTRY_SIZE` bytes,
//!     no pre-capture entry can still fit, so every one of them is provably
//!     gone. From that point the decode is complete, not partial. That is what
//!     `exact` reports.
//!
//! When `h2tapd` supplies a snapshot the decoder starts exact and none of this
//! degradation applies. The tolerant path is the fallback for connections the
//! daemon never saw the start of (daemon restart, mid-run deployment).

use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt;

use httlib_huffman::{decode as huffman_decode, DecoderSpeed};

/// Per-entry overhead in the dynamic table size accounting (RFC 7541 4.1).
/// Also the size of the smallest possible entry, which is what makes the
/// `exact` proof work.
pub const MIN_ENTRY_SIZE: usize = 32;

pub const DEFAULT_TABLE_SIZE: usize = 4096;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Field {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    /// Arrived as "literal never indexed" (RFC 7541 6.2.3).
    pub sensitive: bool,
    /// Name and/or value came from a pre-capture table entry we cannot resolve.
    pub unknown: bool,
}

impl Field {
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Field { name: name.into(), value: value.into(), sensitive: false, unknown: false }
    }

    pub fn size(&self) -> usize {
        self.name.len() + self.value.len() + MIN_ENTRY_SIZE
    }

    pub fn name_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.name)
    }

    pub fn value_str(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.value)
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name_str(), self.value_str())?;
        if self.sensitive {
            write!(f, " [sensitive]")?;
        }
        if self.unknown {
            write!(f, " [unresolved]")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpackError {
    Truncated,
    IntOverflow,
    ZeroIndex,
    /// Index past the end of the table on a connection whose table we know in
    /// full. Unlike an unresolved pre-capture index this is a genuine protocol
    /// or desync error.
    BadIndex(usize),
    Huffman,
}

impl fmt::Display for HpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HpackError::Truncated => write!(f, "truncated header block"),
            HpackError::IntOverflow => write!(f, "integer overflow"),
            HpackError::ZeroIndex => write!(f, "index 0 is not valid"),
            HpackError::BadIndex(i) => write!(f, "index {i} out of range"),
            HpackError::Huffman => write!(f, "huffman decode failed"),
        }
    }
}

impl std::error::Error for HpackError {}

#[derive(Debug, Clone)]
pub struct Decoder {
    /// Observed entries only, newest first. Index 62 is `table[0]`.
    table: VecDeque<Field>,
    size: usize,
    max_size: usize,
    /// True once no pre-capture entry can still be present. See module docs.
    exact: bool,
    /// Cumulative count of indices we could not resolve.
    unresolved: u64,
    /// True when `max_size` came from the wire (a dynamic table size update or
    /// the peer's SETTINGS) rather than being assumed to be the RFC default.
    ///
    /// It matters because the "table is full, so no pre-capture entry can
    /// remain" proof is only sound if `max_size` is actually right. Joining a
    /// connection mid-stream that negotiated a larger table means we assume
    /// 4096 and under-size our copy. That fails visibly rather than silently -
    /// old indices land out of range and error - but the exactness claim rests
    /// on an assumption, and callers deserve to know which.
    capacity_observed: bool,
    /// Refuse to track a table larger than this. Guards the daemon's memory
    /// against a peer negotiating an enormous table.
    track_limit: usize,
    /// The negotiated table exceeds `track_limit`, so we are not tracking it.
    over_limit: bool,
}

impl Decoder {
    /// A decoder for a connection we joined mid-stream: the table may contain
    /// entries we never saw.
    pub fn new_partial() -> Self {
        Decoder {
            table: VecDeque::new(),
            size: 0,
            max_size: DEFAULT_TABLE_SIZE,
            exact: false,
            unresolved: 0,
            capacity_observed: false,
            track_limit: usize::MAX,
            over_limit: false,
        }
    }

    /// A decoder for a connection we watched from its first byte, so the table
    /// starts genuinely empty.
    pub fn new_exact() -> Self {
        let mut d = Self::new_partial();
        d.exact = true;
        // From the first byte the RFC default applies until the peer changes
        // it, and any change is signalled on the wire. So the capacity is
        // known, not assumed.
        d.capacity_observed = true;
        d
    }

    /// Restore from a snapshot taken by `h2tapd`. The table is known in full,
    /// so this is exact.
    pub fn from_entries(entries: Vec<Field>, max_size: usize) -> Self {
        let size = entries.iter().map(|f| f.size()).sum();
        Decoder {
            table: entries.into(),
            size,
            max_size,
            exact: true,
            unresolved: 0,
            capacity_observed: true,
            track_limit: usize::MAX,
            over_limit: false,
        }
    }

    /// Drop everything we think we know about the table, keeping the
    /// negotiated capacity.
    ///
    /// Used after a lost segment. Entries we observed are still in the peer's
    /// table, but insertions we missed have shifted them by an unknown amount,
    /// so continuing to index them would produce confidently wrong headers.
    pub fn reset_partial(&mut self) {
        self.table.clear();
        self.size = 0;
        self.exact = false;
    }

    pub fn is_exact(&self) -> bool {
        self.exact && !self.over_limit
    }

    /// Whether `max_size` was learned from the wire rather than assumed.
    pub fn capacity_observed(&self) -> bool {
        self.capacity_observed
    }

    /// The peer negotiated a table larger than we are willing to track.
    pub fn over_limit(&self) -> bool {
        self.over_limit
    }

    /// Cap how large a dynamic table we will hold in memory. A peer that
    /// negotiates more than this is tracked as "not tracked" rather than
    /// allowed to consume unbounded memory.
    pub fn set_track_limit(&mut self, n: usize) {
        self.track_limit = n;
        self.enforce_limit();
    }

    fn enforce_limit(&mut self) {
        if self.max_size > self.track_limit {
            self.over_limit = true;
            self.table.clear();
            self.size = 0;
        }
    }

    pub fn unresolved_refs(&self) -> u64 {
        self.unresolved
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    pub fn table_size(&self) -> usize {
        self.size
    }

    /// The observed entries, newest first. This is what gets snapshotted.
    pub fn entries(&self) -> impl Iterator<Item = &Field> {
        self.table.iter()
    }

    /// Apply a capacity advertised by the peer's SETTINGS_HEADER_TABLE_SIZE.
    /// An encoder may never exceed what its peer advertised, so lowering on
    /// this signal is safe. We never raise on it, because the encoder's own
    /// choice may be lower and it signals that with a size update instead.
    pub fn apply_peer_capacity(&mut self, n: usize) {
        self.capacity_observed = true;
        if n < self.max_size {
            self.resize(n);
        }
    }

    fn resize(&mut self, n: usize) {
        // A size update on the wire tells us the real capacity.
        self.capacity_observed = true;
        self.max_size = n;
        self.evict();
        self.enforce_limit();
        self.recheck_exact();
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            match self.table.pop_back() {
                Some(f) => {
                    self.size -= f.size();
                    // We just evicted one of our own entries. Since every
                    // pre-capture entry is older than every entry of ours,
                    // they must all already be gone - but only if the capacity
                    // we evicted against is the real one.
                    if self.capacity_observed {
                        self.exact = true;
                    }
                }
                None => break,
            }
        }
    }

    fn recheck_exact(&mut self) {
        // Only sound when we actually know the capacity: if the peer
        // negotiated a bigger table than we assume, our copy saturates early
        // and "full" proves nothing.
        if !self.capacity_observed || self.over_limit {
            return;
        }
        if !self.exact && self.size + MIN_ENTRY_SIZE > self.max_size {
            // Not even a zero-length entry could still fit alongside ours.
            self.exact = true;
        }
    }

    fn insert(&mut self, f: Field) {
        if self.over_limit {
            // Not tracking this table; every index into it stays unresolved.
            return;
        }
        if f.size() > self.max_size {
            // RFC 7541 4.4: the entry is not added and the table is emptied.
            self.table.clear();
            self.size = 0;
            self.exact = true;
            return;
        }
        self.size += f.size();
        self.table.push_front(f);
        self.evict();
        self.recheck_exact();
    }

    /// Resolve a table index. `None` means it points into the pre-capture
    /// region, which is only possible while `!exact`.
    fn lookup(&self, idx: usize) -> Option<Field> {
        if idx == 0 {
            return None;
        }
        if idx <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[idx - 1];
            return Some(Field::new(n, v));
        }
        self.table.get(idx - STATIC_TABLE.len() - 1).cloned()
    }

    fn placeholder(&mut self, idx: usize) -> Field {
        self.unresolved += 1;
        Field {
            name: format!("@unresolved-idx-{idx}").into_bytes(),
            value: Vec::new(),
            sensitive: false,
            unknown: true,
        }
    }

    /// Decode one complete header block (HEADERS plus any CONTINUATION
    /// fragments, concatenated).
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<Field>, HpackError> {
        let mut out = Vec::new();
        let mut b = block;
        while !b.is_empty() {
            let first = b[0];
            if first & 0x80 != 0 {
                // Indexed header field.
                let (idx, rest) = read_int(b, 7)?;
                b = rest;
                if idx == 0 {
                    return Err(HpackError::ZeroIndex);
                }
                let f = match self.lookup(idx) {
                    Some(f) => f,
                    None if self.is_exact() => return Err(HpackError::BadIndex(idx)),
                    None => self.placeholder(idx),
                };
                out.push(f);
            } else if first & 0xc0 == 0x40 {
                // Literal with incremental indexing.
                let (f, rest) = self.read_literal(b, 6)?;
                b = rest;
                // Insert even when the name is a placeholder: the entry
                // occupies a real slot in the peer's table, so skipping it
                // would shift every later index by one and corrupt the rest of
                // the connection.
                self.insert(f.clone());
                out.push(f);
            } else if first & 0xe0 == 0x20 {
                // Dynamic table size update.
                let (n, rest) = read_int(b, 5)?;
                b = rest;
                self.resize(n);
            } else if first & 0xf0 == 0x10 {
                // Literal never indexed.
                let (mut f, rest) = self.read_literal(b, 4)?;
                b = rest;
                f.sensitive = true;
                out.push(f);
            } else {
                // Literal without indexing.
                let (f, rest) = self.read_literal(b, 4)?;
                b = rest;
                out.push(f);
            }
        }
        Ok(out)
    }

    fn read_literal<'a>(
        &mut self,
        b: &'a [u8],
        prefix: u8,
    ) -> Result<(Field, &'a [u8]), HpackError> {
        let (idx, mut b) = read_int(b, prefix)?;
        let mut f = Field::default();
        if idx == 0 {
            let (name, rest) = read_string(b)?;
            b = rest;
            f.name = name;
        } else {
            let e = match self.lookup(idx) {
                Some(e) => e,
                None if self.is_exact() => return Err(HpackError::BadIndex(idx)),
                None => self.placeholder(idx),
            };
            f.name = e.name;
            f.unknown = e.unknown;
        }
        let (value, b) = read_string(b)?;
        f.value = value;
        Ok((f, b))
    }
}

/// RFC 7541 5.1 variable length integer with an N-bit prefix.
fn read_int(b: &[u8], n: u8) -> Result<(usize, &[u8]), HpackError> {
    let (&first, mut rest) = b.split_first().ok_or(HpackError::Truncated)?;
    let max = (1usize << n) - 1;
    let mut v = (first as usize) & max;
    if v < max {
        return Ok((v, rest));
    }
    let mut shift = 0u32;
    loop {
        let (&c, r) = rest.split_first().ok_or(HpackError::Truncated)?;
        rest = r;
        // A 32-bit value needs groups at shifts 0,7,14,21,28. HPACK integers
        // carry table sizes and indices, and SETTINGS_HEADER_TABLE_SIZE is a
        // full u32, so anything short of this rejects legal input.
        if shift > 28 {
            return Err(HpackError::IntOverflow);
        }
        v = v
            .checked_add(((c & 0x7f) as usize) << shift)
            .ok_or(HpackError::IntOverflow)?;
        shift += 7;
        if c & 0x80 == 0 {
            return Ok((v, rest));
        }
    }
}

/// RFC 7541 5.2 length-prefixed, optionally Huffman-coded string.
fn read_string(b: &[u8]) -> Result<(Vec<u8>, &[u8]), HpackError> {
    let huff = b.first().ok_or(HpackError::Truncated)? & 0x80 != 0;
    let (len, rest) = read_int(b, 7)?;
    if len > rest.len() {
        return Err(HpackError::Truncated);
    }
    let (raw, rest) = rest.split_at(len);
    if !huff {
        return Ok((raw.to_vec(), rest));
    }
    let mut out = Vec::with_capacity(len * 2);
    huffman_decode(raw, &mut out, DecoderSpeed::ThreeBits).map_err(|_| HpackError::Huffman)?;
    Ok((out, rest))
}

// ---------------------------------------------------------------------------
// Literal-only encoder, used to produce the normalized capture.
// ---------------------------------------------------------------------------

/// Re-encode a header list so it is decodable with no dynamic table at all:
/// every field is a literal with a fresh name, never indexed, never Huffman
/// coded. The output is deliberately verbose and deliberately stateless, which
/// is the whole point of the normalized pcap.
pub fn encode_literal(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * 48);
    for f in fields {
        // 0x10 = literal never indexed, 0x00 = literal without indexing.
        // Both leave the decoder's dynamic table untouched.
        out.push(if f.sensitive { 0x10 } else { 0x00 });
        write_string(&mut out, &f.name);
        write_string(&mut out, &f.value);
    }
    out
}

fn write_int(out: &mut Vec<u8>, mut v: usize, n: u8, flags: u8) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 128 {
        out.push(((v & 0x7f) | 0x80) as u8);
        v >>= 7;
    }
    out.push(v as u8);
}

fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    // High bit clear: not Huffman coded.
    write_int(out, s.len(), 7, 0x00);
    out.extend_from_slice(s);
}

// ---------------------------------------------------------------------------

/// RFC 7541 Appendix A, indices 1..=61.
pub static STATIC_TABLE: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .flat_map(|w| w.as_bytes().chunks(2))
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    fn shown(fs: &[Field]) -> Vec<(String, String)> {
        fs.iter()
            .map(|f| (f.name_str().into_owned(), f.value_str().into_owned()))
            .collect()
    }

    /// RFC 7541 C.3: three requests sharing one dynamic table, literals.
    #[test]
    fn rfc7541_c3_request_sequence() {
        let mut d = Decoder::new_exact();

        let r1 = d.decode(&hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d")).unwrap();
        assert_eq!(
            shown(&r1),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
        assert_eq!(d.table_size(), 57);

        let r2 = d.decode(&hex("8286 84be 5808 6e6f 2d63 6163 6865")).unwrap();
        assert_eq!(
            shown(&r2),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
                ("cache-control".into(), "no-cache".into()),
            ]
        );
        assert_eq!(d.table_size(), 110);

        let r3 = d
            .decode(&hex("8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"))
            .unwrap();
        assert_eq!(
            shown(&r3),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/index.html".into()),
                (":authority".into(), "www.example.com".into()),
                ("custom-key".into(), "custom-value".into()),
            ]
        );
        assert_eq!(d.table_size(), 164);
    }

    /// RFC 7541 C.4: same sequence, Huffman coded. Exercises the huffman path.
    #[test]
    fn rfc7541_c4_huffman() {
        let mut d = Decoder::new_exact();
        let r1 = d.decode(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff")).unwrap();
        assert_eq!(
            shown(&r1),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
    }

    /// RFC 7541 C.5: responses with a 256-byte table, exercising eviction.
    #[test]
    fn rfc7541_c5_eviction() {
        let mut d = Decoder::new_exact();
        d.apply_peer_capacity(256);

        d.decode(&hex(
            "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 \
             2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 \
             6c65 2e63 6f6d",
        ))
        .unwrap();
        assert_eq!(d.table_size(), 222);

        d.decode(&hex("4803 3330 37c1 c0bf")).unwrap();
        assert_eq!(d.table_size(), 222);

        let r3 = d
            .decode(&hex(
                "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 \
                 474d 54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 \
                 454f 5049 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 \
                 6572 7369 6f6e 3d31",
            ))
            .unwrap();
        assert_eq!(
            shown(&r3),
            vec![
                (":status".into(), "200".into()),
                ("cache-control".into(), "private".into()),
                ("date".into(), "Mon, 21 Oct 2013 20:13:22 GMT".into()),
                ("location".into(), "https://www.example.com".into()),
                ("content-encoding".into(), "gzip".into()),
                (
                    "set-cookie".into(),
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".into()
                ),
            ]
        );
        assert_eq!(d.table_size(), 215);
    }

    /// A decoder that joined mid-stream emits placeholders rather than failing,
    /// and the indices of entries it *did* observe stay correct.
    #[test]
    fn partial_decoder_placeholders_and_exact_indices() {
        let mut d = Decoder::new_partial();

        // Index 70 refers to an entry inserted before we started watching.
        let out = d.decode(&hex("c6")).unwrap();
        assert!(out[0].unknown);
        assert_eq!(out[0].name_str(), "@unresolved-idx-70");
        assert_eq!(d.unresolved_refs(), 1);
        assert!(!d.is_exact());

        // Now observe a real insertion. It becomes index 62.
        d.decode(&hex("400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"))
            .unwrap();
        let out = d.decode(&hex("be")).unwrap();
        assert_eq!(shown(&out), vec![("custom-key".into(), "custom-value".into())]);
        assert!(!out[0].unknown);
    }

    /// Once our own observed entries fill the table, no pre-capture entry can
    /// remain, and the decoder must say so.
    #[test]
    fn partial_decoder_becomes_exact_when_table_is_full() {
        let mut d = Decoder::new_partial();
        d.apply_peer_capacity(256);
        assert!(!d.is_exact());

        // 256 / (32 + 8) => 7 entries of our own fills it past the point where
        // a 32-byte pre-capture entry could still fit.
        for i in 0..7 {
            let name = format!("hdr-{i}");
            let mut block = vec![0x40];
            write_string(&mut block, name.as_bytes());
            write_string(&mut block, b"v");
            d.decode(&block).unwrap();
        }
        assert!(d.is_exact(), "table full of observed entries must be exact");

        // And from here an out-of-range index is a real error, not a gap.
        assert!(matches!(d.decode(&hex("ff00")), Err(HpackError::BadIndex(_))));
    }

    /// The normalized encoding must round-trip through a decoder that has no
    /// dynamic table state at all. That is the guarantee h2rebuild sells.
    #[test]
    fn literal_encoding_is_stateless() {
        let fields = vec![
            Field::new(&b":status"[..], &b"201"[..]),
            Field::new(&b"content-type"[..], &b"application/json"[..]),
            Field::new(
                &b"location"[..],
                &b"https://amf.5gc.mnc001.mcc001.3gppnetwork.org/namf-comm/v1/ue-contexts/imsi-001010000000001"[..],
            ),
        ];
        let wire = encode_literal(&fields);

        let mut fresh = Decoder::new_exact();
        let back = fresh.decode(&wire).unwrap();
        assert_eq!(shown(&back), shown(&fields));
        // Crucially the decoder's table is still empty: nothing was indexed,
        // so any later block decodes without this one.
        assert_eq!(fresh.table_size(), 0);
    }

    #[test]
    fn literal_encoding_handles_long_strings() {
        let long = vec![b'x'; 5000];
        let fields = vec![Field::new(&b"3gpp-sbi-correlation-info"[..], long.clone())];
        let wire = encode_literal(&fields);
        let mut fresh = Decoder::new_exact();
        let back = fresh.decode(&wire).unwrap();
        assert_eq!(back[0].value, long);
    }


    fn size_update(n: usize) -> Vec<u8> {
        let mut v = Vec::new();
        write_int(&mut v, n, 5, 0x20);
        v
    }

    fn insertion(name: &str, value: &str) -> Vec<u8> {
        let mut b = vec![0x40];
        write_string(&mut b, name.as_bytes());
        write_string(&mut b, value.as_bytes());
        b
    }

    /// Apps are free to negotiate far more than the 4096 default.
    #[test]
    fn large_negotiated_tables_are_honoured() {
        let mut d = Decoder::new_exact();
        d.decode(&size_update(4_096_000)).unwrap();
        assert_eq!(d.max_size(), 4_096_000);

        // And the table really does grow past 4096 rather than evicting.
        let mut wire = Vec::new();
        for i in 0..200 {
            wire.extend_from_slice(&insertion(&format!("h-{i:03}"), &"v".repeat(40)));
        }
        d.decode(&wire).unwrap();
        assert_eq!(d.entries().count(), 200, "nothing may be evicted below capacity");
        assert!(d.table_size() > 4096);
    }

    /// SETTINGS_HEADER_TABLE_SIZE is a full u32, so the varint decoder has to
    /// cover the whole range.
    #[test]
    fn table_size_across_the_full_u32_range() {
        for n in [4096usize, 65_536, 4_096_000, 16_777_216, 268_435_456, u32::MAX as usize] {
            let mut d = Decoder::new_exact();
            d.decode(&size_update(n)).unwrap_or_else(|e| panic!("size {n} failed: {e}"));
            assert_eq!(d.max_size(), n);
        }
    }

    /// The "table is full so nothing older can remain" proof is only sound if
    /// the capacity is the real one. Joining mid-stream we do not know it, so
    /// the claim must not be made.
    #[test]
    fn saturation_does_not_prove_exactness_when_capacity_is_only_assumed() {
        let mut d = Decoder::new_partial();
        assert!(!d.capacity_observed());
        for i in 0..200 {
            d.decode(&insertion(&format!("h-{i:03}"), &"v".repeat(40))).unwrap();
        }
        assert!(!d.is_exact(), "must not claim exactness on an assumed capacity");

        // Once the peer tells us the capacity, the proof becomes available.
        let mut d2 = Decoder::new_partial();
        d2.apply_peer_capacity(4096);
        assert!(d2.capacity_observed());
        for i in 0..200 {
            d2.decode(&insertion(&format!("h-{i:03}"), &"v".repeat(40))).unwrap();
        }
        assert!(d2.is_exact(), "with a known capacity, saturation does prove it");
    }

    /// Under-assuming the capacity must never yield a wrong header. Recent
    /// entries agree; entries we wrongly evicted go out of range instead.
    #[test]
    fn under_assumed_capacity_fails_visibly_never_wrongly() {
        let mut wire = Vec::new();
        for i in 0..200 {
            wire.extend_from_slice(&insertion(&format!("h-{i:03}"), &"v".repeat(20)));
        }
        let mut peer = Decoder::new_exact();
        peer.decode(&size_update(4_096_000)).unwrap();
        peer.decode(&wire).unwrap();

        let mut us = Decoder::new_partial(); // never saw the size update
        us.decode(&wire).unwrap();
        assert!(peer.entries().count() > us.entries().count());

        // Newest entry: both must agree.
        assert_eq!(peer.decode(&[0xbe]).unwrap()[0].name, us.decode(&[0xbe]).unwrap()[0].name);

        // An entry the peer kept but we dropped must not resolve to something
        // else; it is either an error or a flagged placeholder.
        let mut old = Vec::new();
        write_int(&mut old, 62 + 150, 7, 0x80);
        match us.decode(&old) {
            Err(HpackError::BadIndex(_)) => {}
            Ok(v) => assert!(v[0].unknown, "silently returned a wrong entry: {:?}", v[0]),
            Err(e) => panic!("unexpected error {e}"),
        }
    }

    /// A peer negotiating an enormous table must not be able to make us
    /// allocate it.
    #[test]
    fn track_limit_refuses_oversized_tables() {
        let mut d = Decoder::new_exact();
        d.set_track_limit(64 * 1024);
        d.decode(&size_update(4_096_000)).unwrap();
        assert!(d.over_limit(), "must refuse to track beyond the limit");
        assert!(!d.is_exact(), "not tracking means not exact");

        let mut wire = Vec::new();
        for i in 0..500 {
            wire.extend_from_slice(&insertion(&format!("h-{i:03}"), &"v".repeat(100)));
        }
        d.decode(&wire).unwrap();
        assert_eq!(d.table_size(), 0, "nothing may be retained");
        assert_eq!(d.entries().count(), 0);

        // References into it degrade to placeholders, not wrong values.
        let out = d.decode(&[0xbe]).unwrap();
        assert!(out[0].unknown);
    }

    #[test]
    fn varint_round_trip() {
        for v in [0usize, 1, 126, 127, 128, 255, 256, 1337, 16383, 16384, 1 << 20] {
            for (bits, flags) in [(7u8, 0x00u8), (6, 0x40), (5, 0x20), (4, 0x10)] {
                let mut buf = Vec::new();
                write_int(&mut buf, v, bits, flags);
                let (got, rest) = read_int(&buf, bits).unwrap();
                assert_eq!(got, v, "bits={bits}");
                assert!(rest.is_empty());
            }
        }
    }
}
