# h2tapd / h2rebuild

Capture 5G SBI traffic **without restarting anything**, and get headers that
decode.

> **New here?** There is a plain-language guide covering how it works, how to
> deploy it, and how to use it day to day:
> This README is the technical reference. It assumes you know what HPACK is.
>
## In one minute

HTTP/2 doesn't repeat itself. The first time an NF sends `user-agent: SMF` it
spells it out and both ends write it into a numbered list; after that it just
sends the number. That list is built up as the conversation goes and lives only
in the two processes' memory — it is never sent on the wire.

Start recording halfway through and you have the numbers but not their meanings,
so Wireshark shows `<unknown>`. That is why testing SBI normally means
restarting NFs before every capture.

The fix is that **the thing which has to start early is the decoder, not the
capture**. `h2tapd` runs permanently and keeps the lists; when you start a
capture it writes the pcap and its copy of the lists at the same instant.
`h2rebuild` then replays the recording from that starting point and writes a new
pcap with every header spelled out in full.

Nothing is reconfigured on the NFs. Both tools are passive.

## Scripts

Four scripts cover the whole workflow. Each takes `--help`.

```sh
scripts/build.sh                                        # test + build static binaries
scripts/install.sh --host root@HOST --iface lo \
                   --ports 80 --reset                   # deploy as a systemd service
scripts/capture.sh --host root@HOST --name test1 \
                   --duration 60 --jsonl                # capture, rebuild, fetch results
scripts/run.sh --iface lo --ports 80                    # foreground, no systemd (dev)
scripts/run.sh --list                                   # which interface is the traffic on?
```

| Script | What it does |
|---|---|
| `build.sh` | Runs the tests, then builds static musl binaries (falls back to native). Records where it built so `install.sh` finds them. |
| `install.sh` | Stops any running service first (copying over a running binary silently fails), copies, verifies by checksum, writes the systemd template and per-interface settings, enables and starts, then reports health. `--reset` also forces existing connections to reconnect. |
| `capture.sh` | Starts a capture and **refuses to record if any connection is degraded**, so you find out before the test rather than after. Records, stops, rebuilds on the host, and fetches everything back. Stops the capture even if interrupted. |
| `run.sh` | Foreground run for development or checking an unfamiliar host. `--list` shows interfaces with the reminder that same-host NFs talk over loopback. |

All of them accept `--host user@host` to act on a remote machine over ssh, or
omit it to act locally.

Omit `--duration` on `capture.sh` and it records until you press Enter, which
is usually what you want when driving a test by hand.

## The problem

HTTP/2 compresses headers with HPACK, which keeps a *dynamic table* in each
endpoint's memory. That table is never on the wire. A pcap that starts
mid-connection is missing the insertions that built it, so header fields come
out as `<unknown>` — which is why testing SBI today means restarting NFs or
bouncing connections before every capture.

The table cannot be recovered from a mid-stream pcap. But it *can* be kept in
memory by something watching continuously. The insight is that **the thing that
has to start early is the decoder, not the capture.**

- **`h2tapd`** runs on the NF hosts, watches SBI traffic continuously, and holds
  the HPACK dynamic tables. On request it starts writing a pcap *and* dumps the
  tables aligned to it.
- **`h2rebuild`** takes that pair and produces a normalized pcap in which every
  header block is self-contained — no dynamic table, decodable from any point,
  readable by Wireshark and whatever validation tooling you already run.

Nothing is reconfigured on the NFs. Both tools are passive.

## Why the alignment matters

A dynamic table is only meaningful at an **exact byte position** in the TCP
stream — it mutates on every header block. A table applied at the wrong offset
does not fail loudly; it yields plausible headers that are wrong, which is the
worst possible outcome for validation work.

So every direction snapshot carries `next_frame_seq`: the absolute TCP sequence
number of the next frame boundary, as of which the table is valid. Two things
make that trustworthy:

1. **`h2tapd` writes the pcap itself.** The snapshot is taken at the same packet
   at which pcap writing begins, from the same packet stream. The alignment is
   guaranteed by construction, not by timing luck between two processes.
2. **A rolling ring buffer is replayed into the pcap at capture start.** If a
   direction is holding a partially received frame, the earlier bytes are
   already consumed but must still be in the pcap. Replaying the ring
   guarantees the capture starts at or before every direction's snapshot point.

`h2rebuild` independently checks the alignment and reports `MISALIGNED` rather
than decoding against a table it cannot trust.

## Build

```sh
cargo build --release
```

No `libpcap` needed — capture is via `AF_PACKET`, pcap I/O is pure Rust.

Raw capture needs `CAP_NET_RAW`:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip target/release/h2tapd
```

## Running the daemon

On each NF host, watching the SBI ports:

```sh
h2tapd --iface eth0 --ports 8080,7777,29500-29520 --out-dir /var/lib/h2tapd
```

It must sniff **the same segment the capture covers**. A SEPP, sidecar or any
proxy in between terminates HTTP/2, so the far side is a different TCP
connection with a different HPACK context.

Leave it running. Memory is about 8 KiB per connection.

**Reset the existing connections once, after the daemon is up.** Connections
that predate the daemon decode only partially, and long-lived SBI connections
may never cycle on their own. Either restart the SBI NFs, or kill the sockets:

```sh
ss -K state established dst 192.168.130.0/24 dport = :80
```

They reconnect within seconds, the daemon sees them from SYN, and every capture
after that is fully usable. This is a one-time step, not a per-capture one.

**A daemon restart wipes all HPACK state**, so live connections drop back to
partial until they cycle. If you restart or upgrade `h2tapd`, reset the
connections again afterwards.

### Dynamic tables larger than 4096

The 4096-byte default is only a default; an app may negotiate any 32-bit size,
and must signal it on the wire (RFC 7541 4.2), so the daemon picks it up
automatically. Two things follow:

* **Memory scales with it.** A 4 MB table is ~8 MB per connection. Snapshot
  JSON runs about 1.6x the raw table bytes, so a 4 MB table serializes to
  ~13 MB per connection and `h2rebuild` parses all of it at startup.
* **`--max-table-bytes`** (default 4 MiB) bounds that. A peer negotiating more
  is reported untracked, with headers degrading to placeholders, rather than
  being allowed to exhaust the host. Worst case memory is
  `2 x --max-table-bytes x --max-conns`.

Joining such a connection *mid-stream* is the one case to know about: without
having seen the size update we assume 4096 and under-size our copy. That is
safe rather than silently wrong - our table is always a prefix of the peer's,
so indices we hold are correct and the rest go out of range and error - but the
"table is full, so nothing older can remain" proof would be unsound. It is
therefore gated on `capacity_observed`, recorded per direction in the snapshot.
The cost is that a mid-stream join no longer self-heals unless it observes a
SETTINGS or a size update.

### Capture reliability

`h2tapd` opens the `AF_PACKET` socket itself rather than letting pnet do it,
because two things need the descriptor and pnet exposes neither: the kernel's
drop counter, and `SO_ATTACH_FILTER`. The filter is attached before pnet binds,
so no unfiltered packet can be queued on the socket.

* **`kernel_drops` in `/health`** counts packets the kernel discarded because
  we did not read fast enough. Non-zero means this host cannot keep up with its
  own traffic. It is the early warning; `reassembly_gaps` is the consequence.
* **Kernel BPF filter**, built from `--ports`, so uninteresting packets are
  dropped in the kernel rather than copied to userspace and discarded there.
  `--no-kernel-filter` falls back to userspace filtering. The program is
  deliberately conservative: VLAN-tagged frames are passed up for the userspace
  parser instead of being judged in BPF, so it can only ever drop what
  userspace would have dropped too.
* **`--read-buffer-bytes`** (default 8 MiB) is the knob to raise first if
  `kernel_drops` is non-zero.

Measured ceiling on a Xeon 8260, six loopback connections: **~48,000 packets
per second sustained with zero loss**, saturating around 85,000 pkt/s. Under
extreme overload throughput *falls* to ~61,000 pkt/s, so treat the clean figure
as the limit. For reference, a 5G test bed idling at ~18 pkt/s has roughly a
2,600x margin.

One operational lesson from measuring this: **heavy CPU load on the host can
starve h2tapd and cost it table state.** During the load test the production
daemon on the same box missed packets, poisoned nine directions and correctly
withdrew its exactness claims. Detected, but not prevented - do not run a stress
test on a host where a capture matters.

### Sizing the ring buffer

`--ring-secs` (default 5) matters more than `--ring-bytes`. The backfill exists
only to complete a partially received frame, which takes seconds. A ring that
reaches back hours will pull long-dead connections into the capture that the
snapshot knows nothing about, and they can only decode partially — the capture
looks broken when it is not.

## Taking a capture

```sh
# start: writes the pcap AND the aligned snapshot, atomically
curl -XPOST localhost:9099/captures -d '{"name":"nrf-reg-test"}'
```

```json
{
  "capture_id": "nrf-reg-test",
  "pcap": "/var/lib/h2tapd/nrf-reg-test.pcap",
  "snapshot": "/var/lib/h2tapd/nrf-reg-test.snapshot.json",
  "backfilled_packets": 214,
  "conns_total": 12,
  "conns_usable": 11,
  "conns_degraded": 1,
  "degraded": [
    {"conn_id": "...", "dir": "s2c", "reason": "hpack state lost (packet gap or decode error)"}
  ]
}
```

**Read `conns_degraded` before you run the test.** It tells you up front which
connections cannot be vouched for, rather than after you have spent an hour
analysing output that was never trustworthy.

Run your test traffic, then:

```sh
curl -XDELETE localhost:9099/captures/nrf-reg-test
```

## Rebuilding

```sh
h2rebuild -r nrf-reg-test.pcap \
          -s nrf-reg-test.snapshot.json \
          -w nrf-reg-test-normalized.pcap \
          --jsonl decoded.jsonl
```

```
h2rebuild: wrote nrf-reg-test-normalized.pcap
  packets in/out    18422 -> 19110
  connections       12 (11 seeded from snapshot)
  header blocks     3480 (3480 fully decoded, 0 partial)
```

Open the normalized pcap in Wireshark. Headers decode with no HPACK state, from
any point in the file. `--jsonl` additionally emits one JSON record per header
block if you would rather grep or diff than click.

Connections that began *during* the capture need no snapshot — they are in the
pcap from their SYN, and are decoded from first principles.

## Control API

| | |
|---|---|
| `GET /health` | connection counts, reassembly gaps, poisoned directions, ring state |
| `GET /connections` | per-connection, per-direction: table size, exactness, gaps, resyncs, `next_frame_seq` |
| `POST /captures` | `{"name","pcap","snapshot"}`, all optional. Starts the pcap and snapshots atomically |
| `DELETE /captures/{id}` | stop and report totals |

`GET /health` reports `dirs_exact` against `dirs`: when they are equal, every
tracked direction will snapshot cleanly.

One capture runs at a time.

## Degradation, and where it is reported

The tools are built to fail visibly. A wrong table is worse than no table, so
every path that loses confidence says so:

| Situation | What happens |
|---|---|
| Packet dropped before `h2tapd` saw it | Reassembly gap → direction poisoned, table discarded, snapshot refused with a reason |
| Daemon started after the connection | Direction is not `exact`; snapshot marked unusable. `h2rebuild` decodes partially and emits `@unresolved-idx-N` placeholders |
| Partial frame older than the ring buffer | Snapshot refused for that direction (`--ring-bytes` to widen) |
| Capture starts after the snapshot point | `h2rebuild` reports `MISALIGNED` and does not apply the table |
| Header block will not decode | Emitted as `@hpack-decode-failed` so the message is not silently lost |
| Peer negotiates a table above `--max-table-bytes` | Direction reported untracked with the negotiated size; references degrade to placeholders instead of the daemon allocating it |
| Capacity assumed rather than observed | `capacity_observed: false` in the snapshot; exactness is not claimed on a saturated table |
| Port reuse | New `conn_id`, fresh table — never continues the previous connection's state. `h2rebuild` also refuses to seed any connection whose SYN it saw, since a snapshot entry on that tuple describes an earlier connection |

Without a snapshot the decoder still degrades usefully rather than failing: it
tracks its own observed insertions, whose indices stay exact because
pre-capture entries are always a suffix of the table and always evict first.
Once observed entries fill the table to within 32 bytes, no pre-capture entry
can remain and the decode becomes **provably** exact from that point. That is
the `hpack_exact` flag.

## Limits

Stated plainly, because they matter:

- **The normalized pcap is an analysis artifact, not a wire replica.** Header
  semantics, stream ids, frame order, DATA payloads and timestamps are faithful.
  Packet boundaries, sequence numbers, window behaviour and retransmissions are
  synthesized. Do not use it to argue about anything TCP-level. Keep the
  original for that.
- **Plaintext only.** If SBI runs over TLS, HPACK is inside the encryption and
  none of this applies without keys.
- Pre-capture table entries genuinely cannot be recovered from the wire. The
  placeholders are honest gaps.
- Packet timestamps come from userspace at receive time (`AF_PACKET` gives no
  hardware timestamps here), so expect sub-millisecond skew.
- VLAN tags are parsed but not reproduced in the normalized output.
- IPv6 fragments and ESP/AH are skipped rather than mis-parsed.

## Layout

```
crates/h2core/     hpack, framing, TCP reassembly, packet parse/build, snapshot format
crates/h2tapd/     daemon: capture loop, connection tracker, control API
crates/h2rebuild/  offline normalizer
```

`h2core` is shared deliberately: if the daemon and the rebuilder ever framed
differently, `next_frame_seq` would point at a byte the rebuilder did not
consider a frame boundary, and every header after it would decode to nonsense.

## Tests

```sh
cargo test
```

61 tests. The HPACK layer is checked against the RFC 7541 Appendix C vectors
(C.3 literals, C.4 Huffman, C.5 eviction). The end-to-end tests build a
conversation in which the second request references table entries the first one
inserted, capture only the second request, and assert the rebuilt pcap decodes
those headers correctly — and that without a snapshot the same input produces
visible `@unresolved-idx-N` gaps instead of invented values.
