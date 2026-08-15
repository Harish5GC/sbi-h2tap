//! HTTP/2 frame layer (RFC 9113 section 4-6).

pub const FRAME_HEADER_LEN: usize = 9;
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

pub struct FrameType;

impl FrameType {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;

    pub fn name(t: u8) -> &'static str {
        match t {
            Self::DATA => "DATA",
            Self::HEADERS => "HEADERS",
            Self::PRIORITY => "PRIORITY",
            Self::RST_STREAM => "RST_STREAM",
            Self::SETTINGS => "SETTINGS",
            Self::PUSH_PROMISE => "PUSH_PROMISE",
            Self::PING => "PING",
            Self::GOAWAY => "GOAWAY",
            Self::WINDOW_UPDATE => "WINDOW_UPDATE",
            Self::CONTINUATION => "CONTINUATION",
            _ => "UNKNOWN",
        }
    }
}

pub mod flags {
    pub const END_STREAM: u8 = 0x01;
    pub const ACK: u8 = 0x01;
    pub const END_HEADERS: u8 = 0x04;
    pub const PADDED: u8 = 0x08;
    pub const PRIORITY: u8 = 0x20;
}

pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub len: u32,
    pub typ: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn parse(b: &[u8]) -> Option<FrameHeader> {
        if b.len() < FRAME_HEADER_LEN {
            return None;
        }
        Some(FrameHeader {
            len: u32::from_be_bytes([0, b[0], b[1], b[2]]),
            typ: b[3],
            flags: b[4],
            // Top bit is reserved and must be ignored on receipt.
            stream_id: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        let l = self.len.to_be_bytes();
        out.extend_from_slice(&[l[1], l[2], l[3], self.typ, self.flags]);
        out.extend_from_slice(&(self.stream_id & 0x7fff_ffff).to_be_bytes());
    }

    pub fn total_len(&self) -> usize {
        FRAME_HEADER_LEN + self.len as usize
    }

    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// Serialize a complete frame.
pub fn build_frame(typ: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    FrameHeader { len: payload.len() as u32, typ, flags, stream_id }.write(&mut out);
    out.extend_from_slice(payload);
    out
}

/// Strip padding, priority and (for PUSH_PROMISE) the promised stream id,
/// leaving just the header block fragment.
pub fn header_block_fragment<'a>(hdr: &FrameHeader, payload: &'a [u8]) -> Option<&'a [u8]> {
    let mut p = payload;
    let mut pad = 0usize;
    if hdr.has(flags::PADDED) {
        let (&n, rest) = p.split_first()?;
        pad = n as usize;
        p = rest;
    }
    if hdr.typ == FrameType::HEADERS && hdr.has(flags::PRIORITY) {
        if p.len() < 5 {
            return None;
        }
        p = &p[5..];
    }
    if hdr.typ == FrameType::PUSH_PROMISE {
        if p.len() < 4 {
            return None;
        }
        p = &p[4..];
    }
    if pad > p.len() {
        return None;
    }
    Some(&p[..p.len() - pad])
}

/// The DATA payload with padding removed.
pub fn data_payload<'a>(hdr: &FrameHeader, payload: &'a [u8]) -> Option<&'a [u8]> {
    let mut p = payload;
    let mut pad = 0usize;
    if hdr.has(flags::PADDED) {
        let (&n, rest) = p.split_first()?;
        pad = n as usize;
        p = rest;
    }
    if pad > p.len() {
        return None;
    }
    Some(&p[..p.len() - pad])
}

/// Pull SETTINGS_HEADER_TABLE_SIZE out of a SETTINGS payload, if present.
/// This bounds the *peer's* encoder, so it caps the decoder for the opposite
/// direction of the connection.
pub fn settings_header_table_size(hdr: &FrameHeader, payload: &[u8]) -> Option<u32> {
    if hdr.typ != FrameType::SETTINGS || hdr.has(flags::ACK) {
        return None;
    }
    let mut found = None;
    for e in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([e[0], e[1]]);
        if id == SETTINGS_HEADER_TABLE_SIZE {
            found = Some(u32::from_be_bytes([e[2], e[3], e[4], e[5]]));
        }
    }
    found
}

/// Largest frame length we will treat as plausible while hunting for a frame
/// boundary. Real SETTINGS_MAX_FRAME_SIZE can reach 16 MiB, but accepting that
/// during resync makes the scan far too permissive.
const MAX_PLAUSIBLE_FRAME: u32 = 1 << 20;

/// Does a single frame header at `b` look structurally valid?
///
/// The stream-id and length constraints per frame type are what make resync
/// reliable: random DATA bytes almost never satisfy them.
fn frame_header_plausible(h: &FrameHeader) -> bool {
    if h.typ > 0x0c || h.len > MAX_PLAUSIBLE_FRAME {
        return false;
    }
    match h.typ {
        FrameType::DATA => h.stream_id != 0,
        FrameType::HEADERS | FrameType::CONTINUATION => h.stream_id != 0,
        FrameType::PRIORITY => h.stream_id != 0 && h.len == 5,
        FrameType::RST_STREAM => h.stream_id != 0 && h.len == 4,
        FrameType::SETTINGS => h.stream_id == 0 && h.len % 6 == 0,
        FrameType::PUSH_PROMISE => h.stream_id != 0 && h.len >= 4,
        FrameType::PING => h.stream_id == 0 && h.len == 8,
        FrameType::GOAWAY => h.stream_id == 0 && h.len >= 8,
        FrameType::WINDOW_UPDATE => h.len == 4,
        _ => true,
    }
}

/// Outcome of testing a candidate frame boundary.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainCheck {
    /// `want` frames chained cleanly, or we ran out of data after at least
    /// `min_accept` of them.
    Ok,
    /// Not a frame boundary.
    Bad,
    /// Plausible so far but we need more bytes to be confident.
    NeedMore,
}

/// Walk a candidate frame chain starting at `b`.
pub fn check_frame_chain(b: &[u8], want: usize, min_accept: usize) -> ChainCheck {
    let mut off = 0usize;
    let mut ok = 0usize;
    while ok < want {
        if off + FRAME_HEADER_LEN > b.len() {
            return if ok >= min_accept { ChainCheck::Ok } else { ChainCheck::NeedMore };
        }
        let h = match FrameHeader::parse(&b[off..]) {
            Some(h) => h,
            None => return ChainCheck::Bad,
        };
        if !frame_header_plausible(&h) {
            return ChainCheck::Bad;
        }
        off += h.total_len();
        ok += 1;
    }
    ChainCheck::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let h = FrameHeader { len: 1234, typ: FrameType::HEADERS, flags: 0x05, stream_id: 7 };
        let mut buf = Vec::new();
        h.write(&mut buf);
        assert_eq!(buf.len(), FRAME_HEADER_LEN);
        assert_eq!(FrameHeader::parse(&buf).unwrap(), h);
    }

    #[test]
    fn reserved_bit_is_masked_off() {
        let raw = [0, 0, 0, 1, 4, 0x80, 0, 0, 5];
        assert_eq!(FrameHeader::parse(&raw).unwrap().stream_id, 5);
    }

    #[test]
    fn strips_padding_and_priority() {
        let hdr = FrameHeader {
            len: 0,
            typ: FrameType::HEADERS,
            flags: flags::PADDED | flags::PRIORITY,
            stream_id: 1,
        };
        // pad len 2, 5 priority bytes, 3 block bytes, 2 pad bytes
        let payload = [2u8, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0, 0];
        assert_eq!(header_block_fragment(&hdr, &payload).unwrap(), &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn extracts_settings_table_size() {
        let hdr = FrameHeader { len: 12, typ: FrameType::SETTINGS, flags: 0, stream_id: 0 };
        let payload = [0, 3, 0, 0, 0, 100, 0, 1, 0, 0, 0, 0];
        assert_eq!(settings_header_table_size(&hdr, &payload), Some(0));
    }

    #[test]
    fn settings_ack_carries_no_table_size() {
        let hdr =
            FrameHeader { len: 0, typ: FrameType::SETTINGS, flags: flags::ACK, stream_id: 0 };
        assert_eq!(settings_header_table_size(&hdr, &[]), None);
    }

    #[test]
    fn chain_check_accepts_real_frames_and_rejects_noise() {
        let mut s = Vec::new();
        s.extend_from_slice(&build_frame(FrameType::SETTINGS, 0, 0, &[0, 1, 0, 0, 16, 0]));
        s.extend_from_slice(&build_frame(FrameType::HEADERS, 0x04, 1, &[0x82, 0x86]));
        s.extend_from_slice(&build_frame(FrameType::DATA, 0x01, 1, b"{\"x\":1}"));
        assert_eq!(check_frame_chain(&s, 3, 2), ChainCheck::Ok);

        let noise = b"GET /nnrf-nfm/v1/nf-instances HTTP/1.1\r\nHost: nrf\r\n\r\n";
        assert_eq!(check_frame_chain(noise, 3, 2), ChainCheck::Bad);
    }
}
