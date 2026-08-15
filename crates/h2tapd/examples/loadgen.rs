//! Traffic generator for finding where h2tapd starts dropping packets.
//!
//! Opens N HTTP/2 connections over loopback and pushes real header blocks
//! through them - HPACK insertions and indexed references, not filler - so the
//! daemon does the same work it would on live SBI traffic. Each write is one
//! packet on the wire, so the write rate is the packet rate.
//!
//!   cargo run --release -p h2tapd --example loadgen -- --port 19080 \
//!       --conns 8 --seconds 20 --rate 5000
//!
//! `--rate` is per connection, per second. 0 means as fast as possible.
//!
//! Point a daemon at the same port to measure it:
//!   h2tapd --iface lo --ports 19080 --api 127.0.0.1:9199

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use h2core::frame::{build_frame, flags, FrameType, PREFACE};

fn arg(name: &str, default: u64) -> u64 {
    let a: Vec<String> = std::env::args().collect();
    a.iter()
        .position(|x| x == name)
        .and_then(|i| a.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// One request: indexed pseudo-headers, one literal-with-indexing insertion to
/// churn the dynamic table, and one reference back into it.
fn request_block(n: u64) -> Vec<u8> {
    let mut b = vec![0x82, 0x87, 0x84]; // :method GET, :scheme https, :path /
    let name = format!("x-load-{:06}", n % 1000);
    let value = format!("imsi-{:015}", n);
    b.push(0x40); // literal, incremental indexing, new name
    b.push(name.len() as u8);
    b.extend_from_slice(name.as_bytes());
    b.push(value.len() as u8);
    b.extend_from_slice(value.as_bytes());
    b.push(0xbe); // index 62: the entry just inserted
    b
}

fn main() {
    let port = arg("--port", 19080) as u16;
    let conns = arg("--conns", 8) as usize;
    let seconds = arg("--seconds", 20);
    let rate = arg("--rate", 0); // per connection per second, 0 = flat out

    let stop = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));

    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    println!("loadgen: {conns} connections to 127.0.0.1:{port} for {seconds}s, rate={rate}/conn/s");

    // Server side: read and discard, and answer each request so both
    // directions carry HPACK.
    {
        let stop = stop.clone();
        thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(mut s) = s else { break };
                let stop = stop.clone();
                thread::spawn(move || {
                    s.set_nodelay(true).ok();
                    let mut buf = vec![0u8; 64 * 1024];
                    let resp = build_frame(FrameType::HEADERS, flags::END_HEADERS, 1, &[0x88]);
                    while !stop.load(Ordering::Relaxed) {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {
                                if s.write_all(&resp).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
    }

    thread::sleep(Duration::from_millis(120));

    let mut handles = Vec::new();
    for _ in 0..conns {
        let (stop, writes, bytes) = (stop.clone(), writes.clone(), bytes.clone());
        handles.push(thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            s.set_nodelay(true).expect("nodelay"); // one write, one packet

            let mut opening = Vec::new();
            opening.extend_from_slice(PREFACE);
            opening.extend_from_slice(&build_frame(FrameType::SETTINGS, 0, 0, &[0, 1, 0, 0, 16, 0]));
            s.write_all(&opening).ok();

            let gap = if rate > 0 {
                Duration::from_nanos(1_000_000_000 / rate)
            } else {
                Duration::ZERO
            };
            let mut n = 0u64;
            let mut sid = 1u32;
            let mut next = Instant::now();

            while !stop.load(Ordering::Relaxed) {
                let frame =
                    build_frame(FrameType::HEADERS, flags::END_HEADERS, sid, &request_block(n));
                if s.write_all(&frame).is_err() {
                    break;
                }
                writes.fetch_add(1, Ordering::Relaxed);
                bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
                n += 1;
                sid = sid.wrapping_add(2).max(1);

                if rate > 0 {
                    next += gap;
                    let now = Instant::now();
                    if next > now {
                        thread::sleep(next - now);
                    } else {
                        next = now; // fell behind; do not accumulate debt
                    }
                }
            }
        }));
    }

    let started = Instant::now();
    thread::sleep(Duration::from_secs(seconds));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    let elapsed = started.elapsed().as_secs_f64();
    let w = writes.load(Ordering::Relaxed);
    let b = bytes.load(Ordering::Relaxed);
    println!(
        "loadgen: {w} requests in {elapsed:.1}s = {:.0} pkt/s client-side ({:.1} MB/s payload)",
        w as f64 / elapsed,
        b as f64 / elapsed / 1e6
    );
    println!("loadgen: the daemon also sees the responses, so its packet rate is roughly double");
}
