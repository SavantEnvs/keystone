#!/usr/bin/env bash
#
# keystone/mayhem/test.sh — RUN keystone's known-answer golden test (built by mayhem/build.sh with
# NORMAL flags) and emit a CTRF summary. exit 0 iff no case failed.
#
# PATCH-grade oracle: mayhem-tests/golden_test assembles fixed asm strings across multiple arches and
# asserts BYTE-EXACT encodings (keystone's own documented golden bytes), plus a negative case that an
# invalid instruction is rejected. A no-op / exit(0) patch (or any change that alters the encoder's
# output) cannot pass. This script only RUNS the pre-built binary; it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "${SRC:-/mayhem}"

GOLDEN="${SRC:-/mayhem}/mayhem-tests/golden_test"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$GOLDEN" ]; then
  echo "missing $GOLDEN — run mayhem/build.sh first" >&2
  emit_ctrf "keystone-golden" 0 1 0; exit 2
fi

echo "=== running keystone golden test ($GOLDEN) ==="
out="$("$GOLDEN" 2>&1)"; rc=$?
echo "$out"

PASSED=$(printf '%s\n' "$out" | grep -c '^RESULT pass ')
FAILED=$(printf '%s\n' "$out" | grep -c '^RESULT fail ')
: "${PASSED:=0}" "${FAILED:=0}"

# Cross-check the binary's own SUMMARY line against the RESULT tally; mismatch => treat as failure.
SUM_FAILED=$(printf '%s\n' "$out" | sed -n 's/.*SUMMARY .*failed=\([0-9][0-9]*\).*/\1/p' | tail -1)
if [ -n "${SUM_FAILED:-}" ] && [ "$SUM_FAILED" != "$FAILED" ]; then
  echo "WARNING: SUMMARY failed=$SUM_FAILED disagrees with RESULT tally failed=$FAILED" >&2
  FAILED=$(( FAILED > SUM_FAILED ? FAILED : SUM_FAILED ))
fi

# No parseable RESULT lines => fall back to the binary's exit code.
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "no RESULT lines parsed; using golden_test exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "keystone-golden" 1 0 0; exit 0; }
  emit_ctrf "keystone-golden" 0 1 0; exit 1
fi

emit_ctrf "keystone-golden" "$PASSED" "$FAILED" 0
