#!/usr/bin/env bash
#
# Take a capture and turn it into a pcap you can actually read.
#
# Starts the capture, waits, stops it, rebuilds it with the headers spelled out,
# and fetches the results.
#
#   scripts/capture.sh --name nrf-reg-test --duration 60
#   scripts/capture.sh --host root@10.30.31.112 --name test1     # wait for Enter
#
# Options
#   --host USER@HOST    capture on a remote host (default: this machine)
#   --name NAME         capture name. Required.
#   --duration SECONDS  how long to record. Omit to stop on Enter.
#   --api ADDR          control API address (default 127.0.0.1:9099)
#   --out DIR           where to put the results locally (default ./captures)
#   --jsonl             also decode headers to JSON lines (roughly 3x slower)
#   --allow-degraded    capture even if some connections cannot be vouched for
#
# The check before recording is the point: conns_degraded tells you up front
# which connections will not decode. Finding out now costs nothing.
#
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

NAME=""; DURATION=""; OUT="./captures"; JSONL=0; ALLOW_DEGRADED=0

while (( $# )); do
  case "$1" in
    --host)           H2_HOST="$2"; shift ;;
    --name)           NAME="$2"; shift ;;
    --duration)       DURATION="$2"; shift ;;
    --api)            H2_API="$2"; shift ;;
    --out)            OUT="$2"; shift ;;
    --jsonl)          JSONL=1 ;;
    --allow-degraded) ALLOW_DEGRADED=1 ;;
    -h|--help)        sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                die "unknown option: $1" ;;
  esac
  shift
done

[[ -n "$NAME" ]] || die "--name is required"
[[ "$NAME" == */* ]] && die "--name must not contain a path separator"
[[ -n "$DURATION" && ! "$DURATION" =~ ^[0-9]+$ ]] && die "--duration must be whole seconds"
mkdir -p "$OUT"

# ---- start -----------------------------------------------------------------

info "starting capture '$NAME' on $(where)"
START_JSON="$(h2_api POST /captures "{\"name\":\"$NAME\"}")"
[[ -n "$START_JSON" ]] || die "no response from the daemon at $H2_API - is it running?"

ERR="$(printf '%s' "$START_JSON" | json_field error || true)"
[[ -n "$ERR" ]] && die "daemon refused: $ERR"

PCAP="$(printf '%s' "$START_JSON" | json_field pcap)"
SNAP="$(printf '%s' "$START_JSON" | json_field snapshot)"
DEGRADED="$(printf '%s' "$START_JSON" | json_field conns_degraded)"

printf '%s' "$START_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  connections  {d['conns_total']} total, {d['conns_usable']} usable, {d['conns_degraded']} degraded\")
for x in d.get('degraded', []):
    print(f\"    - {x['conn_id']} {x['dir']}: {x['reason']}\")
"

if [[ "${DEGRADED:-0}" != "0" ]] && (( ! ALLOW_DEGRADED )); then
  h2_api DELETE "/captures/$NAME" >/dev/null || true
  die "$DEGRADED connection(s) cannot be vouched for, so the capture was stopped.
     Reset those connections (restart the SBI NFs, or ss -K) and try again,
     or pass --allow-degraded to record anyway with gaps marked in the output."
fi

# Stop the capture even if this script is interrupted, so the daemon is not
# left recording indefinitely.
cleanup() { h2_api DELETE "/captures/$NAME" >/dev/null 2>&1 || true; }
trap cleanup INT TERM

# ---- record ----------------------------------------------------------------

if [[ -n "$DURATION" ]]; then
  info "recording for ${DURATION}s"
  sleep "$DURATION"
else
  info "recording. Run your test traffic, then press Enter to stop."
  read -r _
fi

trap - INT TERM
info "stopping"
STOP_JSON="$(h2_api DELETE "/captures/$NAME")"
printf '%s' "$STOP_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f\"  captured     {d['packets']} packets, {d['bytes']} bytes\")
" || true

# ---- rebuild ---------------------------------------------------------------

READABLE="${PCAP%.pcap}-readable.pcap"
JSONL_PATH="${PCAP%.pcap}.jsonl"
REBUILD_CMD="/usr/local/bin/h2rebuild -r '$PCAP' -s '$SNAP' -w '$READABLE'"
(( JSONL )) && REBUILD_CMD="$REBUILD_CMD --jsonl '$JSONL_PATH'"

info "rebuilding with headers spelled out"
h2_sh "$REBUILD_CMD" | sed 's/^/  /'

# ---- collect ---------------------------------------------------------------

info "fetching results into $OUT"
for f in "$PCAP" "$SNAP" "$READABLE"; do
  h2_get "$f" "$OUT/$(basename "$f")"
  printf '  %s\n' "$OUT/$(basename "$f")"
done
if (( JSONL )); then
  h2_get "$JSONL_PATH" "$OUT/$(basename "$JSONL_PATH")"
  printf '  %s\n' "$OUT/$(basename "$JSONL_PATH")"
fi

echo
ok "open $OUT/$(basename "$READABLE") in Wireshark - headers decode from any point"
