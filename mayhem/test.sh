#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
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

# Upstream's own suite: tests/*.phpt through PHP's run-tests.php, against the yar.so and the
# php CLI copy that build.sh left in mayhem/out-test. Each .phpt diffs the script's output
# against its --EXPECT-- section (many start a `php -S` Yar_Server on 127.0.0.1 and call it
# through Yar_Client / Yar_Concurrent_Client), so a neutered extension or php fails them.
OUT_TEST="$SRC/mayhem/out-test"
[ -x "$OUT_TEST/php" ] && [ -f "$OUT_TEST/src/modules/yar.so" ] || { echo "test build missing (run mayhem/build.sh)" >&2; exit 1; }
cd "$OUT_TEST/src"
TESTS=${YAR_TESTS:-$(cd tests && ls *.phpt | sed 's/\.phpt$//')}
args=()
for t in $TESTS; do args+=("tests/$t.phpt"); done
log=$(mktemp)
NO_INTERACTION=1 TEST_PHP_EXECUTABLE="$OUT_TEST/php" timeout 900 "$OUT_TEST/php" run-tests.php -q \
  -d extension="$OUT_TEST/src/modules/yar.so" "${args[@]}" 2>&1 | tee "$log"
count() { local v; v=$(sed 's/\x1b\[[0-9;]*m//g' "$log" | grep -E "^Tests $1 *:" | head -1 | sed -E 's/^[^:]*: *([0-9]+).*/\1/'); echo "${v:-0}"; }
passed=$(count passed)
failed=$(count failed)
skipped=$(count skipped)
total=$(echo $TESTS | wc -w)
other=$(( total - passed - failed - skipped ))
[ "$other" -lt 0 ] && other=0
failed=$(( failed + other ))
rm -f "$log"
emit_ctrf "php-run-tests" "$passed" "$failed" "$skipped"
