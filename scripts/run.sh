#!/usr/bin/env bash
#
# Run h2tapd in the foreground, without systemd. For development, a quick look
# at an unfamiliar host, or checking you picked the right interface.
#
#   scripts/run.sh --iface lo --ports 80
#   scripts/run.sh --list                 show interfaces and where TCP is flowing
#
# Options
#   --iface NAME   interface to watch. Required unless --list.
#   --ports SPEC   SBI ports, lists and ranges (default 80)
#   --api ADDR     control API bind address (default 127.0.0.1:9099)
#   --out-dir DIR  where captures land (default ./captures)
#   --list         list interfaces with addresses, then exit
#
# For a permanent deployment use install.sh instead - this runs until you press
# ctrl-c, and everything it has learned is lost when it stops.
#
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

IFACE=""; PORTS="80"; OUTDIR="./captures"; LIST=0

while (( $# )); do
  case "$1" in
    --iface)   IFACE="$2"; shift ;;
    --ports)   PORTS="$2"; shift ;;
    --api)     H2_API="$2"; shift ;;
    --out-dir) OUTDIR="$2"; shift ;;
    --list)    LIST=1 ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         die "unknown option: $1" ;;
  esac
  shift
done

if (( LIST )); then
  info "interfaces"
  ip -br -4 addr | sed 's/^/  /'
  echo
  info "if your NFs share this host they talk over loopback, not the NIC"
  info "confirm with:  ip route get <peer-ip> from <local-ip>"
  exit 0
fi

[[ -n "$IFACE" ]] || die "--iface is required (try --list to see what is available)"

BUILD_DIR="$(cat "$REPO_ROOT/target/.h2-last-build" 2>/dev/null || echo "target/release")"
TAPD="$REPO_ROOT/$BUILD_DIR/h2tapd"
need_binaries "$TAPD"

# Raw capture needs privileges. Say so before the confusing permission error.
if [[ $EUID -ne 0 ]]; then
  if ! getcap "$TAPD" 2>/dev/null | grep -q cap_net_raw; then
    warn "raw capture needs CAP_NET_RAW. Either run as root, or grant it once:"
    warn "  sudo setcap cap_net_raw,cap_net_admin=eip $TAPD"
  fi
fi

mkdir -p "$OUTDIR"
info "watching $IFACE ports $PORTS, api on $H2_API, captures in $OUTDIR"
info "ctrl-c to stop. State is lost on exit."
echo
exec "$TAPD" --iface "$IFACE" --ports "$PORTS" --api "$H2_API" --out-dir "$OUTDIR"
