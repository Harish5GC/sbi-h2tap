#!/usr/bin/env bash
#
# Build h2tapd and h2rebuild, and run the test suite.
#
# Prefers a static musl build so the binaries drop onto any Linux host with no
# dependencies at all - not even libpcap. Falls back to a native build if the
# musl target is not installed.
#
#   scripts/build.sh                 build static (if possible) and test
#   scripts/build.sh --native        force a native build
#   scripts/build.sh --no-tests      skip the test suite
#
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

MUSL="x86_64-unknown-linux-musl"
RUN_TESTS=1
FORCE_NATIVE=0

while (( $# )); do
  case "$1" in
    --native)   FORCE_NATIVE=1 ;;
    --no-tests) RUN_TESTS=0 ;;
    -h|--help)  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          die "unknown option: $1" ;;
  esac
  shift
done

cd "$REPO_ROOT"

if (( RUN_TESTS )); then
  info "running tests"
  cargo test --workspace --quiet
  ok "tests passed"
fi

TARGET_ARGS=()
OUT="target/release"
if (( ! FORCE_NATIVE )) && rustup target list --installed 2>/dev/null | grep -qx "$MUSL"; then
  TARGET_ARGS=(--target "$MUSL")
  OUT="target/$MUSL/release"
  info "building static ($MUSL)"
else
  if (( ! FORCE_NATIVE )); then
    warn "musl target not installed, building native"
    warn "for portable binaries: rustup target add $MUSL"
  else
    info "building native"
  fi
fi

cargo build --release "${TARGET_ARGS[@]}"

echo
info "binaries"
for b in h2tapd h2rebuild; do
  p="$OUT/$b"
  [[ -x "$p" ]] || die "expected $p to exist"
  printf '  %-10s %8s  %s\n' "$b" "$(du -h "$p" | cut -f1)" "$p"
done

# Record where the freshest build landed so install.sh finds it without
# needing the same flags.
echo "$OUT" > target/.h2-last-build
ok "build complete"
