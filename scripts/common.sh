#!/usr/bin/env bash
# Shared helpers. Sourced by the other scripts, not run directly.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT

# H2_HOST empty  -> act on this machine
# H2_HOST set    -> act on that host over ssh, e.g. root@10.30.31.112
H2_HOST="${H2_HOST:-}"
H2_API="${H2_API:-127.0.0.1:9099}"
H2_OUTDIR="${H2_OUTDIR:-/var/lib/h2tapd}"

_bold=$'\033[1m'; _dim=$'\033[2m'; _red=$'\033[31m'; _grn=$'\033[32m'; _ylw=$'\033[33m'; _off=$'\033[0m'
[[ -t 1 ]] || { _bold=""; _dim=""; _red=""; _grn=""; _ylw=""; _off=""; }

info() { printf '%s==>%s %s\n' "$_bold" "$_off" "$*"; }
ok()   { printf '%s  ok%s %s\n' "$_grn" "$_off" "$*"; }
warn() { printf '%swarn%s %s\n' "$_ylw" "$_off" "$*" >&2; }
die()  { printf '%sfail%s %s\n' "$_red" "$_off" "$*" >&2; exit 1; }

# Where we are acting, for log lines.
where() { [[ -n "$H2_HOST" ]] && echo "$H2_HOST" || echo "localhost"; }

# Run a shell command string locally or on H2_HOST.
h2_sh() {
  if [[ -n "$H2_HOST" ]]; then
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$H2_HOST" "$1"
  else
    bash -c "$1"
  fi
}

# Copy a local file to a path on the target.
h2_put() {
  local src="$1" dst="$2"
  if [[ -n "$H2_HOST" ]]; then
    scp -q -o BatchMode=yes "$src" "$H2_HOST:$dst"
  else
    install -m 0755 -D "$src" "$dst"
  fi
}

# Copy a file from the target back to a local path.
h2_get() {
  local src="$1" dst="$2"
  if [[ -n "$H2_HOST" ]]; then
    scp -q -o BatchMode=yes "$H2_HOST:$src" "$dst"
  else
    cp "$src" "$dst"
  fi
}

# Call the control API. It binds to loopback, so curl always runs on the target.
h2_api() {
  local method="$1" path="$2" body="${3:-}"
  local cmd="curl -s --max-time 15 -X $method http://$H2_API$path"
  [[ -n "$body" ]] && cmd="$cmd -d '$body'"
  h2_sh "$cmd"
}

# Pull one field out of a JSON object on stdin. Falls back to a clear error
# rather than a confusing empty string.
json_field() {
  python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit('not valid json')
k='$1'
sys.stdout.write(str(d[k]) if k in d else '')
"
}

need_binaries() {
  local missing=()
  for b in "$@"; do
    [[ -x "$b" ]] || missing+=("$b")
  done
  if (( ${#missing[@]} )); then
    die "missing binaries: ${missing[*]}
     run scripts/build.sh first"
  fi
}
