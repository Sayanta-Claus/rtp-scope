#!/usr/bin/env bash
# fuzz.sh -- mutation robustness test of the real rtp_scope executable.
#
# Takes valid captures made by rtp_gen, damages them with pcap_mutate (bit
# flips, byte overwrites, truncation, chunk delete/insert, extreme field values;
# fixed seeds 1..N so every case is reproducible), and runs rtp_scope on each
# damaged file with a 10 s timeout. Every third case also runs --simulate.
#
# Allowed outcomes: exit 0 (analysed) or exit 1 (rejected with an error message).
# Failures: any other exit status (crash/abort, timeout = 124, sanitizer exit
# codes 98/99), or an AddressSanitizer / UBSan message on stderr.
# Meant to be run against a -DSANITIZE=ON build.
#
# Usage: scripts/fuzz.sh [--bin DIR] [--count N]     (defaults: build-san, 1000)
set -u
bin=build-san
count=1000
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) bin="$2"; shift 2 ;;
    --count) count="$2"; shift 2 ;;
    *) echo "usage: $0 [--bin DIR] [--count N]" >&2; exit 2 ;;
  esac
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Distinct exit codes so a sanitizer report can never be mistaken for our own "exit 1".
export ASAN_OPTIONS="exitcode=99:detect_leaks=1"
export UBSAN_OPTIONS="halt_on_error=1:exitcode=98:print_stacktrace=1"

echo "# scripts/fuzz.sh --bin $bin --count $count"
"$bin/rtp_gen" --out "$tmp/c0.pcap" --packets 150 --seed 11 --loss 0.1 --duplicate 0.1 --reorder 0.1 --jitter-ms 15 --wrap >/dev/null
"$bin/rtp_gen" --out "$tmp/c1.pcap" --packets 150 --seed 12 --loss 0.05 --duplicate 0.05 --vlan --nano --big-endian --talk-on-ms 400 --talk-off-ms 300 >/dev/null
"$bin/rtp_gen" --out "$tmp/c2.pcap" --packets 150 --seed 13 --loss 0.2 --reorder 0.2 --sll --pt 111 >/dev/null
for c in 0 1 2; do
  "$bin/rtp_scope" "$tmp/c$c.pcap" >/dev/null 2>&1 || { echo "corpus file c$c.pcap is not accepted by rtp_scope"; exit 1; }
done

ok=0; rejected=0; bad=0
for ((i = 1; i <= count; i++)); do
  src="$tmp/c$((i % 3)).pcap"
  "$bin/pcap_mutate" "$src" "$tmp/m.pcap" "$i" || { echo "pcap_mutate failed for seed $i"; exit 1; }
  extra=()
  [ $((i % 3)) -eq 0 ] && extra=(--simulate)
  timeout 10 "$bin/rtp_scope" "${extra[@]}" "$tmp/m.pcap" >/dev/null 2>"$tmp/stderr"
  rc=$?
  if grep -qE "AddressSanitizer|runtime error|LeakSanitizer" "$tmp/stderr"; then rc=97; fi
  case $rc in
    0) ok=$((ok + 1)) ;;
    1) rejected=$((rejected + 1)) ;;
    *) bad=$((bad + 1)); echo "BAD seed=$i source=c$((i % 3)) exit=$rc"; head -n 5 "$tmp/stderr" ;;
  esac
done

echo "mutations run     : $count"
echo "analysed (exit 0) : $ok"
echo "rejected (exit 1) : $rejected"
echo "crashes/hangs/sanitizer reports : $bad"
[ "$bad" -eq 0 ]
