//! Ethernet / IPv4 / IPv6 / TCP parsing and synthesis.
//!
//! Shared so that `h2tapd` and `h2rebuild` agree byte for byte on what a
//! segment is. Kept dependency-free: the formats are small and stable, and
//! the rebuilder needs full control over how it emits packets anyway.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const IPPROTO_TCP: u8 = 6;

#[derive(Debug, Clone)]
pub struct TcpSegment<'a> {
    pub eth_dst: [u8; 6],
    pub eth_src: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

impl TcpSegment<'_> {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse an Ethernet frame down to TCP. Returns `None` for anything that is
/// not TCP over IPv4/IPv6, including IPv6 fragments (which we cannot
/// reassemble and must not silently mis-parse).
pub fn parse_ethernet(frame: &[u8]) -> Option<TcpSegment<'_>> {
    if frame.len() < 14 {
        return None;
    }
    let mut eth_dst = [0u8; 6];
    let mut eth_src = [0u8; 6];
    eth_dst.copy_from_slice(&frame[0..6]);
    eth_src.copy_from_slice(&frame[6..12]);

    let mut off = 12;
    let mut ethertype = be16(&frame[off..]);
    off += 2;
    // Skip any number of VLAN tags.
    while matches!(ethertype, ETHERTYPE_VLAN | ETHERTYPE_QINQ) {
        if frame.len() < off + 4 {
            return None;
        }
        ethertype = be16(&frame[off + 2..]);
        off += 4;
    }

    let (src_ip, dst_ip, l4, l4_len) = match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(frame, off)?,
        ETHERTYPE_IPV6 => parse_ipv6(frame, off)?,
        _ => return None,
    };

    if l4.len() < 20 || l4_len < 20 {
        return None;
    }
    let data_off = ((l4[12] >> 4) as usize) * 4;
    if data_off < 20 || data_off > l4_len || data_off > l4.len() {
        return None;
    }
    let payload = &l4[data_off..l4_len.min(l4.len())];

    Some(TcpSegment {
        eth_dst,
        eth_src,
        src_ip,
        dst_ip,
        src_port: be16(&l4[0..]),
        dst_port: be16(&l4[2..]),
        seq: be32(&l4[4..]),
        ack: be32(&l4[8..]),
        flags: l4[13],
        payload,
    })
}

/// Returns (src, dst, l4 slice, l4 length from the IP header).
fn parse_ipv4(frame: &[u8], off: usize) -> Option<(IpAddr, IpAddr, &[u8], usize)> {
    let ip = frame.get(off..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    // A non-zero fragment offset or MF means we are looking at a fragment.
    let frag = be16(&ip[6..]) & 0x3fff;
    if frag != 0 {
        return None;
    }
    if ip[9] != IPPROTO_TCP {
        return None;
    }
    let total_len = be16(&ip[2..]) as usize;
    // Trust the IP header over the frame length: Ethernet pads short frames.
    let l4_len = total_len.checked_sub(ihl)?;
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    Some((src, dst, ip.get(ihl..)?, l4_len))
}

fn parse_ipv6(frame: &[u8], off: usize) -> Option<(IpAddr, IpAddr, &[u8], usize)> {
    let ip = frame.get(off..)?;
    if ip.len() < 40 || ip[0] >> 4 != 6 {
        return None;
    }
    let payload_len = be16(&ip[4..]) as usize;
    let mut next = ip[6];
    let mut cur = 40usize;
    let mut remaining = payload_len;

    // Walk extension headers. Fragments are refused outright.
    loop {
        match next {
            IPPROTO_TCP => break,
            // Hop-by-hop, routing, destination options, mobility.
            0 | 43 | 60 | 135 => {
                let h = ip.get(cur..cur + 2)?;
                let len = ((h[1] as usize) + 1) * 8;
                next = h[0];
                cur += len;
                remaining = remaining.checked_sub(len)?;
            }
            _ => return None, // includes 44 (fragment) and ESP/AH
        }
    }

    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    s.copy_from_slice(&ip[8..24]);
    d.copy_from_slice(&ip[24..40]);
    Some((
        IpAddr::V6(Ipv6Addr::from(s)),
        IpAddr::V6(Ipv6Addr::from(d)),
        ip.get(cur..)?,
        remaining,
    ))
}

// ---------------------------------------------------------------------------
// Synthesis, used by h2rebuild.
// ---------------------------------------------------------------------------

/// Everything about a direction that stays constant across its packets.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub eth_dst: [u8; 6],
    pub eth_src: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Endpoint {
    pub fn reversed(&self) -> Endpoint {
        Endpoint {
            eth_dst: self.eth_src,
            eth_src: self.eth_dst,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc += be16(&data[i..]) as u32;
        i += 2;
    }
    if i < data.len() {
        acc += (data[i] as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Build one Ethernet + IP + TCP packet. VLAN tags from the original capture
/// are intentionally not reproduced; the normalized pcap is an analysis
/// artifact, not a wire replica.
pub fn build_tcp_packet(
    ep: &Endpoint,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    ip_id: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&ep.src_port.to_be_bytes());
    tcp.extend_from_slice(&ep.dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4); // data offset 5 words, no options
    tcp.push(flags);
    tcp.extend_from_slice(&window.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]); // checksum placeholder
    tcp.extend_from_slice(&[0, 0]); // urgent pointer
    tcp.extend_from_slice(payload);

    let tcp_len = tcp.len();
    let mut pseudo = 0u32;
    match (ep.src_ip, ep.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo = sum16(&s.octets(), pseudo);
            pseudo = sum16(&d.octets(), pseudo);
            pseudo += IPPROTO_TCP as u32;
            pseudo += tcp_len as u32;
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            pseudo = sum16(&s.octets(), pseudo);
            pseudo = sum16(&d.octets(), pseudo);
            pseudo += (tcp_len as u32) >> 16;
            pseudo += (tcp_len as u32) & 0xffff;
            pseudo += IPPROTO_TCP as u32;
        }
        _ => {}
    }
    let ck = fold(sum16(&tcp, pseudo));
    tcp[16..18].copy_from_slice(&ck.to_be_bytes());

    let mut out = Vec::with_capacity(14 + 40 + tcp_len);
    out.extend_from_slice(&ep.eth_dst);
    out.extend_from_slice(&ep.eth_src);

    match (ep.src_ip, ep.dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            out.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
            let total = (20 + tcp_len) as u16;
            let mut ip = Vec::with_capacity(20);
            ip.push(0x45);
            ip.push(0);
            ip.extend_from_slice(&total.to_be_bytes());
            ip.extend_from_slice(&ip_id.to_be_bytes());
            ip.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
            ip.push(64); // ttl
            ip.push(IPPROTO_TCP);
            ip.extend_from_slice(&[0, 0]); // checksum placeholder
            ip.extend_from_slice(&s.octets());
            ip.extend_from_slice(&d.octets());
            let hck = fold(sum16(&ip, 0));
            ip[10..12].copy_from_slice(&hck.to_be_bytes());
            out.extend_from_slice(&ip);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&(tcp_len as u16).to_be_bytes());
            out.push(IPPROTO_TCP);
            out.push(64); // hop limit
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
        }
        _ => return Vec::new(),
    }

    out.extend_from_slice(&tcp);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep_v4() -> Endpoint {
        Endpoint {
            eth_dst: [0x02, 0, 0, 0, 0, 2],
            eth_src: [0x02, 0, 0, 0, 0, 1],
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 41234,
            dst_port: 7777,
        }
    }

    fn ep_v6() -> Endpoint {
        Endpoint {
            eth_dst: [0x02, 0, 0, 0, 0, 2],
            eth_src: [0x02, 0, 0, 0, 0, 1],
            src_ip: "2001:db8::1".parse().unwrap(),
            dst_ip: "2001:db8::2".parse().unwrap(),
            src_port: 41234,
            dst_port: 7777,
        }
    }

    #[test]
    fn v4_round_trip() {
        let ep = ep_v4();
        let frame = build_tcp_packet(&ep, 1000, 2000, tcp_flags::PSH | tcp_flags::ACK, 65535, 7, b"hello");
        let seg = parse_ethernet(&frame).expect("parses");
        assert_eq!(seg.src_ip, ep.src_ip);
        assert_eq!(seg.dst_port, 7777);
        assert_eq!(seg.seq, 1000);
        assert_eq!(seg.ack, 2000);
        assert!(seg.has(tcp_flags::ACK) && seg.has(tcp_flags::PSH));
        assert_eq!(seg.payload, b"hello");
    }

    #[test]
    fn v6_round_trip() {
        let ep = ep_v6();
        let frame = build_tcp_packet(&ep, 5, 6, tcp_flags::ACK, 1024, 0, b"sbi");
        let seg = parse_ethernet(&frame).expect("parses");
        assert_eq!(seg.src_ip, ep.src_ip);
        assert_eq!(seg.payload, b"sbi");
    }

    /// Checksums must be valid: summing a correct header yields zero.
    #[test]
    fn checksums_verify() {
        let frame = build_tcp_packet(&ep_v4(), 1, 1, tcp_flags::ACK, 100, 1, b"abcdefg");
        let ip = &frame[14..34];
        assert_eq!(fold(sum16(ip, 0)), 0, "ipv4 header checksum");

        let tcp = &frame[34..];
        let mut pseudo = 0u32;
        pseudo = sum16(&[10, 0, 0, 1], pseudo);
        pseudo = sum16(&[10, 0, 0, 2], pseudo);
        pseudo += IPPROTO_TCP as u32 + tcp.len() as u32;
        assert_eq!(fold(sum16(tcp, pseudo)), 0, "tcp checksum");
    }

    #[test]
    fn ethernet_padding_does_not_leak_into_payload() {
        let mut frame = build_tcp_packet(&ep_v4(), 1, 1, tcp_flags::ACK, 100, 1, b"hi");
        frame.extend_from_slice(&[0u8; 20]); // NIC padding to minimum frame size
        let seg = parse_ethernet(&frame).unwrap();
        assert_eq!(seg.payload, b"hi", "must trust IP total_length, not frame length");
    }

    #[test]
    fn vlan_tags_are_skipped() {
        let plain = build_tcp_packet(&ep_v4(), 1, 1, tcp_flags::ACK, 100, 1, b"x");
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&plain[..12]);
        tagged.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        tagged.extend_from_slice(&[0x00, 0x64]); // vlan 100
        tagged.extend_from_slice(&plain[12..]);
        let seg = parse_ethernet(&tagged).unwrap();
        assert_eq!(seg.payload, b"x");
        assert_eq!(seg.dst_port, 7777);
    }

    #[test]
    fn non_tcp_and_fragments_are_rejected() {
        let mut frame = build_tcp_packet(&ep_v4(), 1, 1, tcp_flags::ACK, 100, 1, b"x");
        frame[14 + 9] = 17; // UDP
        assert!(parse_ethernet(&frame).is_none());

        let mut frag = build_tcp_packet(&ep_v4(), 1, 1, tcp_flags::ACK, 100, 1, b"x");
        frag[14 + 6] = 0x20; // MF set
        assert!(parse_ethernet(&frag).is_none());
    }
}
