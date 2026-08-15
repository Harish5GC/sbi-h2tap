//! h2tapd - passive HPACK dynamic-table keeper for 5G SBI test beds.
//!
//! Runs on the NF hosts. It watches SBI traffic continuously so that the
//! HPACK dynamic tables are always in memory, and on request it starts writing
//! a pcap *and* dumps the tables aligned to that pcap. `h2rebuild` then turns
//! the pair into a capture whose headers decode standalone.
//!
//! The point is that you never have to restart anything: the thing that has to
//! start early is the decoder, not the capture.

mod api;
mod capture;
mod sock;
mod tracker;

use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::thread;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "h2tapd", version, about = "Passive HPACK state keeper for HTTP/2 SBI")]
struct Args {
    /// Interface to watch, e.g. eth0. Must be the same segment the capture is
    /// taken on: a proxy or SEPP in between is a different TCP connection with
    /// a different HPACK context.
    #[arg(short, long)]
    iface: String,

    /// SBI TCP ports. Accepts lists and ranges: 8080,7777,29500-29520.
    /// Empty means every TCP port, which is rarely what you want.
    #[arg(short, long, default_value = "")]
    ports: String,

    /// Control API bind address.
    #[arg(long, default_value = "127.0.0.1:9099")]
    api: String,

    /// Where captures and snapshots land when the request does not say.
    #[arg(long, default_value = "./captures")]
    out_dir: PathBuf,

    /// Rolling packet buffer. Replayed into the pcap when a capture starts so
    /// that partially received frames are complete in the output.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    ring_bytes: usize,

    /// Drop connections idle for this long.
    #[arg(long, default_value_t = 300)]
    idle_secs: u64,

    /// Upper bound on tracked connections. Each costs roughly 8 KiB.
    #[arg(long, default_value_t = 20_000)]
    max_conns: usize,

    /// Put the interface in promiscuous mode (needed on a mirror port, not on
    /// the NF host itself).
    #[arg(long)]
    promiscuous: bool,

    /// Snaplen recorded in the pcap header.
    #[arg(long, default_value_t = 65535)]
    snaplen: u32,

    /// Filter packets in userspace instead of attaching a BPF program to the
    /// capture socket. Slower on busy interfaces, since every packet is then
    /// copied to userspace before being discarded.
    #[arg(long)]
    no_kernel_filter: bool,

    /// Kernel receive buffer for the capture socket. Raise it if
    /// kernel_drops is non-zero in /health.
    #[arg(long, default_value_t = 8 * 1024 * 1024)]
    read_buffer_bytes: usize,

    /// Largest peer dynamic table we will hold in memory, per direction.
    /// The RFC default is 4096; apps may negotiate far more. A peer above this
    /// is reported as untracked rather than allowed to exhaust the host.
    /// Worst-case memory is 2 x this x --max-conns.
    #[arg(long, default_value_t = 4 * 1024 * 1024)]
    max_table_bytes: usize,

    /// How far back the ring buffer reaches. Only needs to cover a partially
    /// received frame; going further pulls dead connections into the capture
    /// that no snapshot describes.
    #[arg(long, default_value_t = 5)]
    ring_secs: u64,
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                let a: u16 = a.trim().parse().map_err(|_| format!("bad port {a:?}"))?;
                let b: u16 = b.trim().parse().map_err(|_| format!("bad port {b:?}"))?;
                if a > b {
                    return Err(format!("empty port range {a}-{b}"));
                }
                out.extend(a..=b);
            }
            None => out.push(part.parse().map_err(|_| format!("bad port {part:?}"))?),
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn main() {
    let args = Args::parse();
    let ports = match parse_ports(&args.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("h2tapd: {e}");
            std::process::exit(2);
        }
    };
    if ports.is_empty() {
        eprintln!("h2tapd: warning: no --ports given, tracking every TCP connection");
    }

    let cfg = capture::Config {
        iface: args.iface,
        ports,
        out_dir: args.out_dir,
        ring_bytes: args.ring_bytes,
        idle_secs: args.idle_secs,
        max_conns: args.max_conns,
        promiscuous: args.promiscuous,
        snaplen: args.snaplen,
        ring_secs: args.ring_secs,
        max_table_bytes: args.max_table_bytes,
        kernel_filter: !args.no_kernel_filter,
        read_buffer_bytes: args.read_buffer_bytes,
    };

    let (tx, rx) = channel();
    let addr = args.api.clone();
    thread::spawn(move || {
        if let Err(e) = api::serve(&addr, tx) {
            eprintln!("h2tapd: api: {e}");
            std::process::exit(1);
        }
    });

    if let Err(e) = capture::run(cfg, rx) {
        eprintln!("h2tapd: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_ports;

    #[test]
    fn parses_lists_and_ranges() {
        assert_eq!(parse_ports("8080").unwrap(), vec![8080]);
        assert_eq!(parse_ports("8080,7777").unwrap(), vec![7777, 8080]);
        assert_eq!(parse_ports("29500-29503").unwrap(), vec![29500, 29501, 29502, 29503]);
        assert_eq!(parse_ports(" 80 , 80 ").unwrap(), vec![80], "deduplicated");
        assert_eq!(parse_ports("").unwrap(), Vec::<u16>::new());
        assert!(parse_ports("nope").is_err());
        assert!(parse_ports("90-80").is_err());
    }
}
