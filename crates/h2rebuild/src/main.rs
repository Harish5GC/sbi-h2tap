//! h2rebuild - rebuild an HTTP/2 capture with HPACK compression removed.
//!
//! Takes a pcap and the snapshot `h2tapd` wrote when that capture started, and
//! produces a pcap in which every header block is self-contained. The output
//! opens in Wireshark, or in whatever already reads your captures, with no
//! dynamic table and no requirement that the capture began at connection setup.

mod rebuild;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "h2rebuild", version, about = "Rebuild an HTTP/2 pcap without HPACK")]
struct Args {
    /// Capture written by h2tapd (or any pcap of the same traffic).
    #[arg(short = 'r', long)]
    pcap: PathBuf,

    /// Snapshot h2tapd wrote when the capture started. Without it, headers on
    /// connections that were already open decode only partially.
    #[arg(short, long)]
    snapshot: Option<PathBuf>,

    /// Normalized output pcap.
    #[arg(short = 'w', long)]
    out: PathBuf,

    /// Also write decoded headers as JSON lines.
    #[arg(long)]
    jsonl: Option<PathBuf>,

    /// Payload bytes per synthesized packet.
    #[arg(long, default_value_t = 1400)]
    mss: usize,
}

fn main() {
    let args = Args::parse();
    let opts = rebuild::Options {
        pcap: args.pcap,
        snapshot: args.snapshot,
        out: args.out.clone(),
        jsonl: args.jsonl,
        mss: args.mss,
    };

    match rebuild::run(opts) {
        Ok(r) => {
            println!("h2rebuild: wrote {}", args.out.display());
            println!("  packets in/out    {} -> {}", r.packets_in, r.packets_out);
            println!("  connections       {} ({} seeded from snapshot)", r.conns, r.conns_seeded);
            println!(
                "  header blocks     {} ({} fully decoded, {} partial)",
                r.header_blocks, r.blocks_exact, r.blocks_partial
            );
            if r.unresolved_refs > 0 {
                println!(
                    "  unresolved refs   {} (pre-capture table entries; shown as @unresolved-idx-N)",
                    r.unresolved_refs
                );
            }
            if r.pre_snapshot_bytes > 0 {
                println!(
                    "  pre-snapshot skip {} bytes on {} direction(s) (backfill from before the \
                     capture point; blocks wholly inside it cannot be decoded)",
                    r.pre_snapshot_bytes, r.pre_snapshot_dirs
                );
            }
            if r.decode_failures > 0 {
                println!("  decode failures   {}", r.decode_failures);
            }
            if r.frames_dropped > 0 {
                println!("  oversized frames dropped {}", r.frames_dropped);
            }
            if r.conns_misaligned > 0 {
                println!(
                    "  MISALIGNED        {} connection(s): the capture starts after the snapshot \
                     point, so their tables were not applied",
                    r.conns_misaligned
                );
            }
        }
        Err(e) => {
            eprintln!("h2rebuild: {e}");
            std::process::exit(1);
        }
    }
}
