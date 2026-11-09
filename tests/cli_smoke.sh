#!/usr/bin/env bash
# cli_smoke.sh -- black-box test of the real rtp_gen / rtp_scope executables.
#
# What it checks: exit codes, error messages on bad input, and that the main
# output modes (text, --json, --simulate, --sweep) produce the expected markers.
# The numeric correctness of the analysis is covered by test_e2e (library level)
# and scripts/validate.sh (binary level, 100+ traces).
#
# Usage: cli_smoke.sh <directory containing rtp_gen and rtp_scope>
set -u
bin="$1"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failures=0

expect() {  # expect <description> <command...>   (command must succeed)
  local what="$1"; shift
  if ! "$@" >/dev/null 2>&1; then echo "FAIL: $what"; failures=$((failures + 1)); fi
}
expect_rc() {  # expect_rc <description> <exit code> <command...>
  local what="$1" want="$2"; shift 2
  "$@" >/dev/null 2>"$tmp/stderr"; local rc=$?
  if [ "$rc" -ne "$want" ]; then echo "FAIL: $what (exit $rc, wanted $want)"; failures=$((failures + 1)); fi
}

# --- generate and analyse a trace ---
expect "rtp_gen runs" "$bin/rtp_gen" --out "$tmp/a.pcap" --packets 300 --seed 4 --loss 0.1 --jitter-ms 10 --wrap
expect "truth file written" test -s "$tmp/a.pcap.truth"
"$bin/rtp_scope" "$tmp/a.pcap" >"$tmp/text" 2>&1
grep -q "streams: 1" "$tmp/text" || { echo "FAIL: text report lacks 'streams: 1'"; failures=$((failures + 1)); }
"$bin/rtp_scope" --json "$tmp/a.pcap" >"$tmp/json" 2>&1
grep -q '"streams": \[' "$tmp/json" || { echo "FAIL: json lacks streams array"; failures=$((failures + 1)); }
"$bin/rtp_scope" --simulate "$tmp/a.pcap" >"$tmp/sim" 2>&1
grep -q "adaptive-k4" "$tmp/sim" || { echo "FAIL: --simulate lacks adaptive row"; failures=$((failures + 1)); }
"$bin/rtp_scope" --sweep "$tmp/a.pcap" >"$tmp/sweep" 2>&1
head -n 1 "$tmp/sweep" | grep -qx "strategy,avg_latency_ms,late_or_lost_pct" || { echo "FAIL: sweep header"; failures=$((failures + 1)); }

# --- error handling ---
printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\0\0\0\0\0\0\0\0\xff\xff\0\0\x65\0\0\0' >"$tmp/rawip.pcap"   # link type 101
"$bin/rtp_scope" "$tmp/rawip.pcap" >/dev/null 2>"$tmp/err"; rc=$?
{ [ $rc -eq 1 ] && grep -q "unsupported link type 101" "$tmp/err"; } || { echo "FAIL: unsupported link type handling (rc=$rc)"; failures=$((failures + 1)); }
printf 'hello, definitely not a pcap file' >"$tmp/junk.pcap"
expect_rc "garbage file -> exit 1" 1 "$bin/rtp_scope" "$tmp/junk.pcap"
expect_rc "missing file -> exit 1" 1 "$bin/rtp_scope" "$tmp/does-not-exist.pcap"
expect_rc "no arguments -> exit 2" 2 "$bin/rtp_scope"
expect_rc "unknown option -> exit 2" 2 "$bin/rtp_scope" --bogus "$tmp/a.pcap"
expect_rc "bad --clock-rate -> exit 2" 2 "$bin/rtp_scope" --clock-rate nope "$tmp/a.pcap"
expect_rc "--json with --sweep -> exit 2" 2 "$bin/rtp_scope" --json --sweep "$tmp/a.pcap"
expect_rc "rtp_gen without --out -> exit 2" 2 "$bin/rtp_gen" --packets 5
expect_rc "rtp_gen bad probability -> exit 2" 2 "$bin/rtp_gen" --out "$tmp/x.pcap" --loss 1.5
expect_rc "--help -> exit 0" 0 "$bin/rtp_scope" --help

# truncated file still analyses what it has
head -c 3000 "$tmp/a.pcap" >"$tmp/cut.pcap"
"$bin/rtp_scope" "$tmp/cut.pcap" >"$tmp/cut.out" 2>&1; rc=$?
{ [ $rc -eq 0 ] && grep -q "truncated" "$tmp/cut.out"; } || { echo "FAIL: truncated capture handling (rc=$rc)"; failures=$((failures + 1)); }

if [ "$failures" -eq 0 ]; then echo "cli_smoke: all checks passed"; exit 0; fi
echo "cli_smoke: $failures check(s) failed"; exit 1
