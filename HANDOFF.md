# Handoff

Everything learned building and deploying `h2tapd` / `h2rebuild`, written for
whoever picks this up next.

`README.md` is the reference manual and `docs/guide.html` is the plain-language
walkthrough. This file is the engineering record: what was decided and why,
what broke, what was measured, and what is left.

---

## TL;DR

A 5G SBI capture that starts mid-conversation cannot decode HTTP/2 headers,
because HPACK keeps a numbered lookup table in each endpoint's memory that is
never sent on the wire. The usual workaround is restarting the NFs before every
capture.

`h2tapd` runs permanently on the NF host and keeps those tables. When you start
a capture it writes the pcap **and** dumps its copy of the tables in the same
step. `h2rebuild` replays the pcap from that exact byte and writes a new pcap
with every header spelled out, so it decodes standalone from any point.

Deployed and running on **10.30.31.112** against Open5GS. Verified: tshark
reports **1,228 unresolvable header fields in an original capture and 0 in the
rebuilt one**.

---

## Current deployment

**Host** 10.30.31.112 — Ubuntu 24.04.4, x86_64, glibc 2.39, 8-core Xeon
Platinum 8260 @ 2.40 GHz. Root access by ssh key.

**Workload** Open5GS, all NFs on the one host.

| | |
|---|---|
| `h2tapd@lo` | API `127.0.0.1:9099`, output `/var/lib/h2tapd/lo` — **this is where SBI is** |
| `h2tapd@enp8s0` | API `127.0.0.1:9100`, output `/var/lib/h2tapd/enp8s0` — idle, standing by |
| Binaries | `/usr/local/bin/h2tapd`, `/usr/local/bin/h2rebuild` |
| Reference | `/usr/local/share/h2tapd/README.md` |
| Unit | `/etc/systemd/system/h2tapd@.service`, settings in `/etc/default/h2tapd-<iface>` |

Both services are `enabled`, so they survive a reboot. Binaries are static musl
with **zero** shared library dependencies — deployment is a copy, nothing to
install. The host does not even have `libpcap-dev`.

### The thing that surprises everyone

**SBI runs over loopback, not the NIC.** The NFs use `192.168.130.10-.22` and
`.39`, which are aliases on `enp8s0` and look routable — but because all the NFs
share the host, Linux routes that traffic via `lo`. `enp8s0` sees **zero**
port-80 packets.

```sh
ip route get 192.168.130.10 from 192.168.130.39
# → local 192.168.130.10 ... dev lo
```

Always check this before choosing an interface. Watching the wrong one gives a
capture that is empty but looks like a tool failure.

### SBI network functions

Restart these to reset connections: `nrfd scpd amfd ausfd bsfd nssfd pcfd smfd
udmd udrd seppd` — eleven services. Restart NRF and SCP first, then the rest.

**Do not restart `open5gs-upfd`.** UPF has no SBI interface (PFCP and GTP-U
only), so restarting it resets no HPACK state and does drop user-plane sessions.

---

## Design decisions worth knowing

These are the choices that are not obvious from reading the code.

### The snapshot must be pinned to an exact byte

A dynamic table mutates on every header block. Applied at the wrong offset it
does not throw an error — it produces **plausible headers that are wrong**,
which is the worst possible outcome for validation work.

So every direction snapshot carries `next_frame_seq`, the absolute TCP sequence
number of the next frame boundary. Everything else follows from needing that to
be trustworthy:

- **`h2tapd` writes the pcap itself** rather than delegating to tcpdump. The
  snapshot is taken at the same packet at which recording begins, from the same
  packet stream, so alignment is guaranteed by construction rather than by two
  processes happening to start together.
- **The reassembly layer is hand-written.** Most libraries hand you bytes and
  hide the sequence numbers; we need them.
- **`h2rebuild` re-checks the alignment** and reports `MISALIGNED` rather than
  applying a table it cannot vouch for.

### h2core is shared deliberately

Both binaries drive the same framing and HPACK code. If they ever framed
differently, `next_frame_seq` would point at a byte the rebuilder did not
consider a frame boundary, and every header after it would decode to nonsense.
Keep it that way.

### Fail visibly, never silently

A wrong table is worse than no table. Every path that loses confidence says so:
gaps poison the direction and refuse the snapshot; unresolvable references
become `@unresolved-idx-N`; an undecodable block becomes `@hpack-decode-failed`
rather than vanishing; `POST /captures` reports `conns_degraded` **before** the
test run.

### The exactness proof

Without a snapshot the decoder still degrades usefully. Entries it observed keep
correct indices, because pre-capture entries are always a *suffix* of the table
and always evict first. Once observed entries fill the table to within 32 bytes
(the minimum entry size), no pre-capture entry can remain and the decode becomes
provably exact.

That proof is only sound if the table capacity is the real one, so it is gated
on `capacity_observed` — see bug 5 below.

---

## Bugs found during deployment

All fixed, all with regression tests. Recorded because each one was invisible in
the lab and only appeared against real traffic.

**1. Block-level `exact` over-claimed.** A block could report `hpack_exact: true`
while containing an `@unresolved-idx-63`, because the table became exact partway
*through* that block. Now computed as `is_exact() && unresolved == 0`.

**2. Stale snapshot applied to a reused 5-tuple.** Open5GS cycles short-lived
connections and reuses ports. The rebuilder was applying the *old* connection's
table to a *new* connection on the same tuple — exactly the wrong-offset failure
the design exists to prevent. It now refuses to seed any connection whose SYN it
saw. Caught by noticing the rebuild reported *more* directions seeded than the
snapshot contained.

**3. Ring buffer reached back hours.** Sized only in bytes, 32 MB held roughly
four hours at this traffic rate, so every capture dragged in long-dead
connections no snapshot described. Captures looked broken when they were not.
Now bounded by age as well: `--ring-secs`, default 5.

**4. Varint decoder rejected large table sizes.** `SETTINGS_HEADER_TABLE_SIZE`
is a full `u32`, but the integer guard capped out near 268 million. Fixed to the
whole range.

**5. Exactness proof unsound on an assumed capacity.** Joining mid-stream a
connection that negotiated a larger table meant assuming 4096 and under-sizing
our copy, so "the table is full" proved nothing. Now gated on
`capacity_observed`. The failure mode was already safe rather than wrong — our
table is always a prefix of the peer's, so held indices are correct and the rest
go out of range and error — but the claim was wrong.

**Trade-off introduced by 5:** a mid-stream join no longer self-heals unless it
observes a SETTINGS frame or a size update. Correctness was judged more
important than the fallback, and every connection here is seen from SYN anyway.
If that fallback is ever wanted back, it should be a flag, not a default.

---

## What was verified, and how

- **61 tests.** HPACK is checked against the RFC 7541 Appendix C vectors (C.3
  literals, C.4 Huffman, C.5 eviction). End-to-end tests capture only the
  *second* of two requests and assert the first request's table entries are
  recovered — and that without a snapshot the same input produces visible
  `@unresolved-idx-N` gaps instead of invented values.
- **Independent dissector.** tshark on the same connection: original capture
  1,513 named header fields and **1,228 `<unknown>`**; rebuilt capture 2,701
  named and **0 unknown**. All IP and TCP checksums validate as good.
- **Long capture.** Nine minutes, 9,994 packets, **2,052 of 2,052 header blocks
  decoded, zero gaps**. The busiest direction decoded **540 consecutive header
  blocks from a single snapshot** taken at the start — with tables at 99.9% of
  capacity, so every insertion evicted and the table rolled over many times.
  This is the evidence that one snapshot covers an arbitrarily long capture.
- **Real SBI decodes correctly**, e.g. SMF and UDM heartbeat PATCHes to NRF with
  `3gpp-sbi-max-rsp-time`, `:authority: nrf.5gc.mnc001.mcc001.3gppnetwork.org`.

### A number that is expected, not a fault

`pre-snapshot skip N bytes on M direction(s)` is normal. The ring backfill
includes packets from just *before* the capture point; a header block wholly
inside that region cannot be decoded, because that would need the table as it
was *earlier* than the snapshot. It is traffic from before you pressed start,
not part of your test.

---

## Performance

### Sizes and idle cost

| | |
|---|---|
| `h2tapd` / `h2rebuild` | 2.0 MB / 1.5 MB, static |
| Daemon RSS | ~3 MB idle, unchanged while capturing |
| Daemon CPU | 0.10% at this bed's 18 pkt/s |
| Per connection | ~8 KB (two 4 KB HPACK tables) |
| Storage | ~9 MB per hour at 18 pkt/s |

### Rebuild throughput

Xeon 8260, single-threaded, 231,840 packets across 1,920 connections:

| | |
|---|---|
| pcap only | 0.76 s → **0.33 ms per 100 packets**, ~45 MB/s |
| with `--jsonl` | 1.95 s → 0.84 ms per 100 packets |
| Fixed startup | ~0.14 s, almost entirely parsing the snapshot JSON |
| Marginal cost | ~2.67 µs/packet, ~13.6 µs/header block |
| Memory | **~24 MB + 2.2 × pcap size** — a 1 GB capture wants ~2.2 GB RAM |

### Capture ceiling, and the comparison with tcpdump

Same core, same load, same 8 MiB buffer, load pinned to separate cores:

| Offered/s | Tool | Drops | CPU | RSS |
|---|---|---|---|---|
| ~48k | tcpdump | 0 (0.00%) | 2.0% | 14.7 MB |
| | h2tapd | 0 (0.00%) | 20.7% | 29.6 MB |
| ~127k | tcpdump | 0 (0.00%) | 6.8% | 14.7 MB |
| | h2tapd | 292,695 (22.97%) | 56.6% | 56.7 MB |
| ~276k | tcpdump | 0 (0.00%) | 11.6% | 14.8 MB |
| | h2tapd | 1,660,128 (60.14%) | 94.3% | 84.8 MB |

**h2tapd sustains ~48,000 pkt/s with zero loss.** This bed runs at 18 pkt/s, so
the margin is roughly 2,600×. But be honest about the comparison: **tcpdump is
far better at pure capture** — no drops at 276k pkt/s on a tenth the CPU, with
flat memory.

### The bottleneck

The giveaway is the middle row: h2tapd dropped 23% while using only 56.6% of a
core. It was not CPU-starved; it could not drain the socket fast enough during
bursts. `perf` at saturation:

```
47.70%  memcpy
17.70%  h2core::reassembly::Reassembler::push
 9.38%  h2core::reassembly::Reassembler::drain_ooo
 2.43%  free
```

1. **Per-packet syscalls — the real limiter.** `pnet_datalink` does `poll()` +
   `recvfrom()` per packet. libpcap uses `PACKET_MMAP` (TPACKET_V3), where the
   kernel writes into a shared ring and userspace reads with no syscall and no
   copy per packet. That one architectural difference explains most of the gap.
2. **`memcpy` at 47.7%** — largely the ring buffer doing `data.to_vec()` per
   packet, one allocation each, plus the reassembly buffer copy.
3. **`drain_ooo` at 9.4%** — called on every in-order push just to scan an empty
   list. A one-line early return.

h2tapd also does TCP reassembly, HTTP/2 framing and HPACK decoding, which
tcpdump does not do at all — but that work is not what causes the drops.

---

## Operational runbook

### After deploying, restarting or upgrading the daemon

**A daemon restart wipes all HPACK state.** Live connections fall back to
partial decoding until they reconnect, and long-lived SBI connections may never
renew on their own. Reset them once:

```sh
systemctl restart open5gs-nrfd open5gs-scpd    # then the other nine
# or, quicker:
ss -K state established dst 192.168.130.0/24 dport = :80
```

Then confirm `exact` equals `dirs`:

```sh
curl -s localhost:9099/health
```

### Before every capture

`POST /captures` returns `conns_degraded`. If it is not zero, each degraded
direction comes with a reason. `scripts/capture.sh` refuses to record unless you
pass `--allow-degraded`, deliberately — finding out now costs nothing, finding
out afterwards costs the analysis.

### Health fields that matter

| Field | Healthy | Meaning |
|---|---|---|
| `exact` vs `dirs` | equal | Every direction fully understood |
| `kernel_drops` | 0 | Early warning: the host cannot keep up |
| `reassembly_gaps` | 0 | The consequence: a direction lost its place |
| `dirs_poisoned` | 0 | Tables no longer trustworthy |

`kernel_drops` is the leading indicator; raise `--read-buffer-bytes` first if it
moves. Also check `/proc/net/dev` — NIC-level drops are counted nowhere in the
tool, and a mirror port dropping upstream is invisible on the host entirely.

### Do not stress-test a host where a capture matters

Learned the hard way. A load test on this host starved the production daemon,
which lost packets and correctly poisoned **9 of 20 directions**. The tool
behaved properly — it noticed and withdrew its exactness claims — but the state
was gone and needed an NF restart to recover.

Repeating the test with the load pinned to cores 6–7 and the capture tool to
core 5 caused **no** collateral damage. Pin your load.

---

## Known limits

- **Plaintext only.** If SBI runs over TLS the compression is inside the
  encryption, and none of this works without keys. SEPP N32 on port 443 is out
  of scope.
- **The rebuilt pcap is an analysis artifact, not a wire replica.** Headers,
  payloads, stream IDs, ordering and timestamps are faithful; the TCP layer is
  synthesized, so sequence numbers, packet boundaries and retransmissions are
  not the originals. Keep the original for anything at that level.
- **Pre-capture table entries are unrecoverable.** The placeholders are honest
  gaps, not failures.
- **Timestamps come from userspace** at read time, not the kernel, so expect
  sub-millisecond skew that can widen under load.
- **Watch the same segment as the capture.** A SEPP, proxy or service mesh in
  between is a different TCP connection with a different HPACK context.
- **One capture at a time** per daemon instance.
- VLAN tags are parsed but not reproduced in the normalized output. IPv6
  fragments and ESP/AH are skipped rather than mis-parsed.

---

## Open items

Ranked by value. None of them block anything today.

1. **`PACKET_MMAP` / TPACKET_V3 read path.** The real fix for the capture
   ceiling, and what would close the gap with tcpdump. Requires bypassing
   `pnet_datalink`'s read loop or replacing it.
2. **Stop allocating a `Vec` per packet in the ring buffer.** One circular byte
   buffer with offsets. Should be a large fraction of that 47.7% memcpy.
3. **Early return in `drain_ooo`** when the out-of-order list is empty. One
   line, ~9% of profile.
4. **No git remote configured.** Nothing has been pushed anywhere.
5. **`h2tapd@enp8s0` is idle** — no port-80 traffic on the NIC. Harmless, and
   in place should external SBI ever appear.
6. Optional flag to restore optimistic self-healing for mid-stream joins, if the
   trade-off in bug 5 ever proves inconvenient.

---

## Repo

```
crates/h2core/      hpack, framing, TCP reassembly, packet parse/build, snapshot format
crates/h2tapd/      daemon: capture loop, raw socket, connection tracker, control API
crates/h2rebuild/   offline normalizer
scripts/            build, install, run, capture
docs/guide.html     plain-language guide (published; link in README)
```

```sh
cargo test              # 61 tests
scripts/build.sh        # test + static build
scripts/install.sh --host root@HOST --iface lo --ports 80 --reset
scripts/capture.sh --host root@HOST --name test1 --duration 60 --jsonl
```

Captures and any `*.pcap` / `*.jsonl` / `*.snapshot.json` are gitignored on
purpose: they are binary, regenerable, and carry real SBI traffic (SUPIs, NF
instance IDs) that should not enter source history.

---

## Notes for the next person

Three things that cost time and are easy to hit again:

- `ldd` on a static-pie binary can try to **execute** it. Use `readelf -d`.
- `pkill -f <pattern>` matches your own command line and will kill your ssh
  session. Kill by PID, or `pgrep -x`.
- Copying over a running binary fails with `Text file busy` and silently leaves
  the old version running. `install.sh` stops the service first and verifies by
  checksum afterwards, for exactly this reason.
