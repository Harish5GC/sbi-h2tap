#!/usr/bin/env bash
#
# Install h2tapd and h2rebuild on a host as a systemd service.
#
#   scripts/install.sh --iface lo --ports 80
#   scripts/install.sh --host root@10.30.31.112 --iface lo --ports 80 --reset
#
# Options
#   --host USER@HOST   install on a remote host over ssh (default: this machine)
#   --iface NAME       interface to watch. Required.
#   --ports SPEC       SBI ports, lists and ranges: 80,8080,29500-29520. Required.
#   --api ADDR         control API bind address (default 127.0.0.1:9099)
#   --out-dir DIR      where captures land (default /var/lib/h2tapd/<iface>)
#   --ring-secs N      how far back the packet ring reaches (default 5)
#   --reset            after starting, force existing SBI connections to
#                      reconnect so they are seen from the beginning
#
# The interface matters more than people expect. If all your NFs share a host
# they talk over loopback even though their addresses look routable. Check with:
#   ip route get <peer-ip> from <local-ip>
#
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

IFACE=""; PORTS=""; RING_SECS=5; RESET=0; OUTDIR=""

while (( $# )); do
  case "$1" in
    --host)      H2_HOST="$2"; shift ;;
    --iface)     IFACE="$2"; shift ;;
    --ports)     PORTS="$2"; shift ;;
    --api)       H2_API="$2"; shift ;;
    --out-dir)   OUTDIR="$2"; shift ;;
    --ring-secs) RING_SECS="$2"; shift ;;
    --reset)     RESET=1 ;;
    -h|--help)   sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           die "unknown option: $1" ;;
  esac
  shift
done

[[ -n "$IFACE" ]] || die "--iface is required (e.g. --iface lo)"
[[ -n "$PORTS" ]] || die "--ports is required (e.g. --ports 80)"
OUTDIR="${OUTDIR:-/var/lib/h2tapd/$IFACE}"

BUILD_DIR="$(cat "$REPO_ROOT/target/.h2-last-build" 2>/dev/null || echo "target/x86_64-unknown-linux-musl/release")"
TAPD="$REPO_ROOT/$BUILD_DIR/h2tapd"
REBUILD="$REPO_ROOT/$BUILD_DIR/h2rebuild"
need_binaries "$TAPD" "$REBUILD"

UNIT="h2tapd@$IFACE"
info "installing on $(where): iface=$IFACE ports=$PORTS api=$H2_API"

# Stop first. Copying over a running binary fails with "Text file busy" and
# leaves the old version in place, which is a confusing way to lose an hour.
h2_sh "systemctl stop $UNIT 2>/dev/null || true; rm -f /usr/local/bin/h2tapd /usr/local/bin/h2rebuild; mkdir -p /usr/local/bin '$OUTDIR' /usr/local/share/h2tapd"

info "copying binaries"
h2_put "$TAPD" /usr/local/bin/h2tapd
h2_put "$REBUILD" /usr/local/bin/h2rebuild
[[ -f "$REPO_ROOT/README.md" ]] && h2_put "$REPO_ROOT/README.md" /usr/local/share/h2tapd/README.md
h2_sh "chmod +x /usr/local/bin/h2tapd /usr/local/bin/h2rebuild"

# Verify what landed is what we sent.
LOCAL_SUM="$(md5sum "$TAPD" | cut -d' ' -f1)"
REMOTE_SUM="$(h2_sh "md5sum /usr/local/bin/h2tapd | cut -d' ' -f1")"
[[ "$LOCAL_SUM" == "$REMOTE_SUM" ]] || die "checksum mismatch after copy: $LOCAL_SUM != $REMOTE_SUM"
ok "binaries verified ($LOCAL_SUM)"

info "writing systemd unit and settings"
h2_sh "cat > /etc/systemd/system/h2tapd@.service <<'UNIT'
[Unit]
Description=h2tapd HPACK dynamic-table keeper on %i
Documentation=file:///usr/local/share/h2tapd/README.md
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/default/h2tapd-%i
ExecStart=/usr/local/bin/h2tapd --iface %i --ports \${H2_PORTS} --api \${H2_API} \\
          --out-dir \${H2_OUTDIR} --ring-bytes \${H2_RING} --ring-secs \${H2_RING_SECS}
Restart=always
RestartSec=2
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

# NOTE: a restart wipes all HPACK state. Live connections fall back to partial
# decoding until they reconnect, so reset them after any restart or upgrade.
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/default/h2tapd-$IFACE <<ENV
H2_PORTS=$PORTS
H2_API=$H2_API
H2_OUTDIR=$OUTDIR
H2_RING=33554432
H2_RING_SECS=$RING_SECS
ENV
systemctl daemon-reload
systemctl enable --now $UNIT"

sleep 4
STATE="$(h2_sh "systemctl is-active $UNIT || true")"
[[ "$STATE" == "active" ]] || die "$UNIT is $STATE
     check: journalctl -u $UNIT -n 30"
ok "$UNIT active and enabled at boot"

if (( RESET )); then
  info "resetting existing SBI connections so they are seen from the start"
  PORT_LIST="$(echo "$PORTS" | tr ',' ' ')"
  for p in $PORT_LIST; do
    [[ "$p" == *-* ]] && continue   # ss cannot take a range
    h2_sh "ss -K state established '( dport = :$p or sport = :$p )' >/dev/null 2>&1 || true"
  done
  ok "sockets killed; NFs reconnect within seconds"
  sleep 12
else
  warn "existing connections predate the daemon and will decode only partially."
  warn "run again with --reset, or restart the SBI NFs, once."
fi

echo
info "health"
h2_api GET /health | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  conns={d['conns']} dirs={d['dirs']} exact={d['dirs_exact']} poisoned={d['dirs_poisoned']} gaps={d['reassembly_gaps']}\")
if d['dirs'] and d['dirs_exact'] == d['dirs']:
    print('  ready: every direction is fully understood')
elif d['dirs']:
    print('  not all directions are exact yet - reset the connections, or wait for them to renew')
else:
    print('  no connections seen yet on this interface - is the traffic really here?')
"
