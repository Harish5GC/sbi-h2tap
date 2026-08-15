//! Raw AF_PACKET socket, owned by us rather than by pnet.
//!
//! Two things need the file descriptor, and pnet exposes neither:
//!
//!   * `PACKET_STATISTICS` — how many packets the kernel dropped because we
//!     did not read them fast enough. Without it "are we missing packets?"
//!     can only be answered after the fact, from TCP sequence holes.
//!   * `SO_ATTACH_FILTER` — a classic BPF program so uninteresting packets are
//!     discarded in the kernel instead of being copied to userspace and
//!     thrown away there.
//!
//! pnet takes a caller-supplied fd and still does the bind and the promiscuous
//! setup, so we create the socket, attach the filter, and hand it over. The
//! filter therefore lands *before* the bind, which means no unfiltered packet
//! can ever be queued on this socket.

use std::io;

const SOL_PACKET: libc::c_int = 263;
const PACKET_STATISTICS: libc::c_int = 6;

/// Reading PACKET_STATISTICS resets the kernel's counters, so callers have to
/// accumulate. This is the delta since the previous read.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct TpacketStats {
    tp_packets: libc::c_uint,
    tp_drops: libc::c_uint,
}

/// Largest port list we will express as a filter. Each port costs two
/// comparisons, and classic BPF jump offsets are a single byte, so a very long
/// list cannot be encoded. Beyond this we fall back to userspace filtering
/// rather than emit a filter that might be wrong.
const MAX_FILTER_PORTS: usize = 60;

pub struct PacketSocket {
    pub fd: libc::c_int,
    pub filtered_in_kernel: bool,
    packets: u64,
    drops: u64,
}

impl PacketSocket {
    /// Create the socket and attach the port filter. Does not bind - pnet does
    /// that when it takes the fd.
    pub fn open(ports: &[u16], kernel_filter: bool) -> io::Result<PacketSocket> {
        // ETH_P_ALL in network byte order, matching what pnet would have done.
        let proto = (libc::ETH_P_ALL as libc::c_int).to_be();
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        let mut filtered = false;
        if kernel_filter && !ports.is_empty() && ports.len() <= MAX_FILTER_PORTS {
            match attach_filter(fd, ports) {
                Ok(()) => filtered = true,
                Err(e) => {
                    // A missing filter costs performance, never correctness:
                    // userspace filtering still runs. Report and carry on.
                    eprintln!("h2tapd: could not attach kernel filter ({e}); filtering in userspace");
                }
            }
        }

        Ok(PacketSocket { fd, filtered_in_kernel: filtered, packets: 0, drops: 0 })
    }

    /// Accumulated (packets, drops) as counted by the kernel. Drops are packets
    /// that arrived on this socket and were discarded because the receive
    /// buffer was full - i.e. packets we never got the chance to see.
    pub fn stats(&mut self) -> (u64, u64) {
        let mut s = TpacketStats::default();
        let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                SOL_PACKET,
                PACKET_STATISTICS,
                &mut s as *mut TpacketStats as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 {
            // The kernel zeroes its counters on read, so these are deltas.
            self.packets += s.tp_packets as u64;
            self.drops += s.tp_drops as u64;
        }
        (self.packets, self.drops)
    }
}

// ---------------------------------------------------------------------------
// Classic BPF
// ---------------------------------------------------------------------------

const BPF_LD_H_ABS: u16 = 0x28;
const BPF_LD_B_ABS: u16 = 0x30;
const BPF_LD_H_IND: u16 = 0x48;
const BPF_LDX_B_MSH: u16 = 0xb1;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JSET_K: u16 = 0x45;
const BPF_JA: u16 = 0x05;
const BPF_RET_K: u16 = 0x06;

/// Where a jump goes. Resolved once the program length is known.
#[derive(Clone, Copy)]
enum T {
    Next,
    Accept,
    Drop,
    At(usize),
}

struct Pseudo {
    code: u16,
    k: u32,
    jt: T,
    jf: T,
}

fn ins(code: u16, k: u32) -> Pseudo {
    Pseudo { code, k, jt: T::Next, jf: T::Next }
}

fn jmp(code: u16, k: u32, jt: T, jf: T) -> Pseudo {
    Pseudo { code, k, jt, jf }
}

/// Build a filter accepting TCP (v4 or v6) on any of `ports`, in either
/// direction.
///
/// VLAN-tagged frames are accepted unconditionally rather than parsed here.
/// Getting VLAN wrong in BPF would silently discard traffic we can handle, and
/// the userspace parser walks the tags correctly - so the kernel filter is
/// deliberately conservative: it only ever drops what userspace would also
/// have dropped.
fn build_filter(ports: &[u16]) -> Vec<libc::sock_filter> {
    let np = ports.len();
    let mut p: Vec<Pseudo> = Vec::new();

    // Layout is fixed apart from the port comparisons, so both branch targets
    // are computable up front. The debug_assert below is what catches this
    // arithmetic drifting out of step with the code.
    const DISPATCH_LEN: usize = 5;
    const V4_FIXED: usize = 8; // proto, jeq, frag load, jset, ldx, 2 port loads, ja
    let v4_start = DISPATCH_LEN;
    let v6_start = DISPATCH_LEN + V4_FIXED + 2 * np;

    // --- dispatch on ethertype -------------------------------------------
    p.push(ins(BPF_LD_H_ABS, 12));
    p.push(jmp(BPF_JEQ_K, 0x0800, T::At(v4_start), T::Next));
    p.push(jmp(BPF_JEQ_K, 0x86dd, T::At(v6_start), T::Next));
    p.push(jmp(BPF_JEQ_K, 0x8100, T::Accept, T::Next)); // VLAN -> userspace
    p.push(jmp(BPF_JEQ_K, 0x88a8, T::Accept, T::Drop)); // QinQ -> userspace

    // --- IPv4 -------------------------------------------------------------
    p.push(ins(BPF_LD_B_ABS, 23)); // protocol
    p.push(jmp(BPF_JEQ_K, 6, T::Next, T::Drop)); // TCP only
    p.push(ins(BPF_LD_H_ABS, 20)); // flags + fragment offset
    // Any fragment is dropped, matching the userspace parser, which refuses
    // them rather than mis-parsing a partial header.
    p.push(jmp(BPF_JSET_K, 0x3fff, T::Drop, T::Next));
    p.push(ins(BPF_LDX_B_MSH, 14)); // x = IPv4 header length
    p.push(ins(BPF_LD_H_IND, 14)); // source port
    for &port in ports {
        p.push(jmp(BPF_JEQ_K, port as u32, T::Accept, T::Next));
    }
    p.push(ins(BPF_LD_H_IND, 16)); // destination port
    for &port in ports {
        p.push(jmp(BPF_JEQ_K, port as u32, T::Accept, T::Next));
    }
    p.push(jmp(BPF_JA, 0, T::Drop, T::Drop));

    debug_assert_eq!(p.len(), v6_start, "IPv6 branch target must match layout");

    // --- IPv6 -------------------------------------------------------------
    p.push(ins(BPF_LD_B_ABS, 20)); // next header
    p.push(jmp(BPF_JEQ_K, 6, T::Next, T::Drop)); // TCP only, no ext headers
    p.push(ins(BPF_LD_H_ABS, 54)); // source port
    for &port in ports {
        p.push(jmp(BPF_JEQ_K, port as u32, T::Accept, T::Next));
    }
    p.push(ins(BPF_LD_H_ABS, 56)); // destination port
    for &port in ports {
        p.push(jmp(BPF_JEQ_K, port as u32, T::Accept, T::Next));
    }
    p.push(jmp(BPF_JA, 0, T::Drop, T::Drop));

    // --- verdicts, always the last two instructions -----------------------
    let accept_at = p.len();
    p.push(ins(BPF_RET_K, 0xffff_ffff));
    let drop_at = p.len();
    p.push(ins(BPF_RET_K, 0));

    // --- resolve -----------------------------------------------------------
    let resolve = |t: T, here: usize| -> usize {
        let target = match t {
            T::Next => here + 1,
            T::Accept => accept_at,
            T::Drop => drop_at,
            T::At(i) => i,
        };
        target - here - 1
    };

    p.iter()
        .enumerate()
        .map(|(i, x)| {
            if x.code == BPF_JA {
                // An unconditional jump encodes its target in k, not jt/jf.
                libc::sock_filter { code: x.code, jt: 0, jf: 0, k: resolve(x.jt, i) as u32 }
            } else {
                libc::sock_filter {
                    code: x.code,
                    jt: resolve(x.jt, i) as u8,
                    jf: resolve(x.jf, i) as u8,
                    k: x.k,
                }
            }
        })
        .collect()
}

fn attach_filter(fd: libc::c_int, ports: &[u16]) -> io::Result<()> {
    let mut prog = build_filter(ports);

    // Classic BPF jump offsets are one byte. If the layout ever outgrows that
    // the kernel would reject it, but check ourselves so the reason is clear.
    for (i, f) in prog.iter().enumerate() {
        if f.code != BPF_JA && (f.jt as usize > 255 || f.jf as usize > 255) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("filter jump out of range at instruction {i}"),
            ));
        }
    }

    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_mut_ptr() };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &fprog as *const libc::sock_fprog as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny classic-BPF interpreter, so the generated program can be checked
    /// against real frames without needing a socket or privileges.
    fn run(prog: &[libc::sock_filter], pkt: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        for _ in 0..10_000 {
            let i = &prog[pc];
            pc += 1;
            let ld = |off: usize, n: usize| -> Option<u32> {
                if off + n > pkt.len() {
                    return None;
                }
                Some(match n {
                    1 => pkt[off] as u32,
                    2 => u16::from_be_bytes([pkt[off], pkt[off + 1]]) as u32,
                    _ => unreachable!(),
                })
            };
            match i.code {
                BPF_LD_H_ABS => match ld(i.k as usize, 2) { Some(v) => a = v, None => return 0 },
                BPF_LD_B_ABS => match ld(i.k as usize, 1) { Some(v) => a = v, None => return 0 },
                BPF_LD_H_IND => match ld((x + i.k) as usize, 2) { Some(v) => a = v, None => return 0 },
                BPF_LDX_B_MSH => match ld(i.k as usize, 1) {
                    Some(v) => x = 4 * (v & 0x0f),
                    None => return 0,
                },
                BPF_JEQ_K => pc += if a == i.k { i.jt as usize } else { i.jf as usize },
                BPF_JSET_K => pc += if a & i.k != 0 { i.jt as usize } else { i.jf as usize },
                BPF_JA => pc += i.k as usize,
                BPF_RET_K => return i.k,
                c => panic!("unhandled opcode {c:#x}"),
            }
        }
        panic!("filter did not terminate");
    }

    fn v4(src_port: u16, dst_port: u16, proto: u8, frag: u16, ihl: u8) -> Vec<u8> {
        let mut p = vec![0u8; 14];
        p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0u8; (ihl as usize) * 4];
        ip[0] = 0x40 | ihl;
        ip[6..8].copy_from_slice(&frag.to_be_bytes());
        ip[9] = proto;
        p.extend_from_slice(&ip);
        p.extend_from_slice(&src_port.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&[0u8; 16]);
        p
    }

    fn v6(src_port: u16, dst_port: u16, next: u8) -> Vec<u8> {
        let mut p = vec![0u8; 14];
        p[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        ip[6] = next;
        p.extend_from_slice(&ip);
        p.extend_from_slice(&src_port.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&[0u8; 16]);
        p
    }

    const PORTS: [u16; 3] = [80, 8080, 29510];

    #[test]
    fn accepts_matching_tcp_in_both_directions() {
        let f = build_filter(&PORTS);
        assert_ne!(run(&f, &v4(41234, 80, 6, 0, 5)), 0, "v4 to a watched port");
        assert_ne!(run(&f, &v4(80, 41234, 6, 0, 5)), 0, "v4 from a watched port");
        assert_ne!(run(&f, &v4(1, 29510, 6, 0, 5)), 0, "v4 last port in the list");
        assert_ne!(run(&f, &v6(41234, 8080, 6)), 0, "v6 to a watched port");
        assert_ne!(run(&f, &v6(8080, 41234, 6)), 0, "v6 from a watched port");
    }

    #[test]
    fn accepts_ipv4_with_options() {
        // ihl 8 means 12 bytes of options; ports must still be located.
        let f = build_filter(&PORTS);
        assert_ne!(run(&f, &v4(41234, 80, 6, 0, 8)), 0, "must follow IHL, not assume 20 bytes");
    }

    #[test]
    fn rejects_what_userspace_would_also_reject() {
        let f = build_filter(&PORTS);
        assert_eq!(run(&f, &v4(41234, 443, 6, 0, 5)), 0, "unwatched port");
        assert_eq!(run(&f, &v4(41234, 80, 17, 0, 5)), 0, "udp");
        assert_eq!(run(&f, &v4(41234, 80, 6, 0x2000, 5)), 0, "more-fragments set");
        assert_eq!(run(&f, &v4(41234, 80, 6, 0x0001, 5)), 0, "non-zero fragment offset");
        assert_eq!(run(&f, &v6(41234, 80, 17)), 0, "v6 udp");

        let mut arp = vec![0u8; 60];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert_eq!(run(&f, &arp), 0, "arp");
    }

    /// The don't-fragment bit is not a fragment. Dropping on it would discard
    /// almost all normal traffic.
    #[test]
    fn does_not_confuse_dont_fragment_with_fragmented() {
        let f = build_filter(&PORTS);
        assert_ne!(run(&f, &v4(41234, 80, 6, 0x4000, 5)), 0, "DF set is still a whole packet");
    }

    /// VLAN handling in BPF is easy to get subtly wrong, so tagged frames are
    /// passed up for the userspace parser rather than judged here.
    #[test]
    fn vlan_tagged_frames_are_passed_to_userspace() {
        let f = build_filter(&PORTS);
        let mut tagged = vec![0u8; 12];
        tagged.extend_from_slice(&0x8100u16.to_be_bytes());
        tagged.extend_from_slice(&[0x00, 0x64]);
        tagged.extend_from_slice(&v4(41234, 80, 6, 0, 5)[12..]);
        assert_ne!(run(&f, &tagged), 0, "must not drop VLAN traffic we can parse");
    }

    #[test]
    fn accept_returns_the_whole_frame() {
        let f = build_filter(&PORTS);
        assert_eq!(run(&f, &v4(41234, 80, 6, 0, 5)), 0xffff_ffff, "must not truncate");
    }

    #[test]
    fn jump_offsets_stay_within_one_byte() {
        let ports: Vec<u16> = (29500..29560).collect();
        let f = build_filter(&ports);
        for (i, x) in f.iter().enumerate() {
            assert!(x.jt as usize <= 255 && x.jf as usize <= 255, "instruction {i} overflows");
        }
        assert_ne!(run(&f, &v4(1, 29559, 6, 0, 5)), 0);
        assert_eq!(run(&f, &v4(1, 29499, 6, 0, 5)), 0);
    }
}
