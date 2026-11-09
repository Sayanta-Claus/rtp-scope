#!/usr/bin/env bash
# validate.sh -- check rtp_scope against the ground truth written by rtp_gen.
#
# For each of N parameter combinations (seed, loss, jitter, reorder, duplicate,
# sequence start incl. wraparound, pcap flavour, talkspurts) it
#   1. runs rtp_gen          -> trace.pcap + trace.pcap.truth (exact counts)
#   2. runs rtp_scope --json -> the analyzer's counts
#   3. compares: packets received, unique received, expected, lost, duplicates,
#      out-of-order (= reordered) and the extended highest sequence number.
# Every field must match exactly; there is no tolerance. Prints one line per
# trace and a final "X/N traces matched". Exit status 1 if any trace differs.
#
# Usage: scripts/validate.sh [--count N] [--bin DIR]
#   --count N  number of combinations (default 120)
#   --bin DIR  directory with rtp_gen and rtp_scope (default: build)
set -u
count=120
bin=build
while [ $# -gt 0 ]; do
  case "$1" in
    --count) count="$2"; shift 2 ;;
    --bin) bin="$2"; shift 2 ;;
    *) echo "usage: $0 [--count N] [--bin DIR]" >&2; exit 2 ;;
  esac
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

loss_set=(0 0.01 0.05 0.10 0.20 0.30)
reorder_set=(0 0.02 0.05 0.10 0.20)
dup_set=(0 0.01 0.05 0.15)
jitter_set=(0 3 10 30 60)
packets_set=(400 900 1500 2500)

truth() { grep "^$1=" "$tmp/t.pcap.truth" | cut -d= -f2; }
scope() { grep -m1 "\"$1\":" "$tmp/out.json" | sed 's/.*: *//; s/,$//'; }

echo "# scripts/validate.sh --count $count --bin $bin"
echo "# fields compared exactly: received unique expected lost duplicates reordered ext_highest"
matched=0
for ((i = 1; i <= count; i++)); do
  loss=${loss_set[$((i % 6))]}
  reorder=${reorder_set[$(((i / 3) % 5))]}
  dup=${dup_set[$(((i / 5) % 4))]}
  jitter=${jitter_set[$(((i / 2) % 5))]}
  packets=${packets_set[$(((i / 7) % 4))]}
  args=(--seed "$i" --packets "$packets" --loss "$loss" --reorder "$reorder" --duplicate "$dup" --jitter-ms "$jitter")

  # sequence start: every third trace wraps early; others start at an arbitrary value
  if [ $((i % 3)) -eq 0 ]; then args+=(--wrap); start="wrap"; else start=$(((i * 4093) % 65536)); args+=(--start-seq "$start"); fi
  # alternate jitter distribution, pcap flavour and talkspurts
  if [ $((i % 2)) -eq 0 ]; then args+=(--jitter-dist normal); fi
  flavour=""
  if [ $((i % 4)) -eq 1 ]; then args+=(--nano); flavour+="nano "; fi
  if [ $((i % 5)) -eq 2 ]; then args+=(--big-endian); flavour+="be "; fi
  if [ $((i % 6)) -eq 4 ]; then args+=(--vlan); flavour+="vlan "; fi
  # SLL framing has no VLAN tag, so it is only chosen when --vlan was not
  if [ $((i % 7)) -eq 3 ] && [ $((i % 6)) -ne 4 ]; then args+=(--sll); flavour+="sll "; fi
  if [ $((i % 8)) -eq 5 ]; then args+=(--talk-on-ms 600 --talk-off-ms 400); flavour+="talkspurts "; fi
  if [ $((i % 9)) -eq 6 ]; then args+=(--start-ts 4294966000); flavour+="ts-wrap "; fi

  if ! "$bin/rtp_gen" --out "$tmp/t.pcap" "${args[@]}" >/dev/null 2>"$tmp/gen.err"; then
    echo "FAIL #$i: rtp_gen failed: $(cat "$tmp/gen.err")"; continue
  fi
  if ! "$bin/rtp_scope" --json "$tmp/t.pcap" >"$tmp/out.json" 2>"$tmp/scope.err"; then
    echo "FAIL #$i: rtp_scope failed: $(cat "$tmp/scope.err")"; continue
  fi

  mismatch=""
  compare() {  # compare <name> <truth value> <rtp_scope value>
    if [ "$2" != "$3" ]; then mismatch+=" $1(truth=$2 scope=$3)"; fi
  }
  if [ "$(truth packets_received)" = "0" ]; then
    # nothing arrived: the analyzer must find no stream at all
    grep -q '"streams": \[\]' "$tmp/out.json" || mismatch+=" streams(expected none)"
  else
    compare received "$(truth packets_received)" "$(scope packets_received)"
    compare unique "$(truth packets_unique_received)" "$(scope unique_received)"
    compare expected "$(truth packets_expected)" "$(scope expected)"
    compare lost "$(truth packets_lost)" "$(scope lost)"
    compare duplicates "$(truth packets_duplicated)" "$(scope duplicates)"
    compare reordered "$(truth packets_reordered)" "$(scope out_of_order)"
    compare ext_highest "$(truth ext_highest_seq)" "$(scope extended_highest_seq)"
  fi

  desc="seed=$i packets=$packets loss=$loss reorder=$reorder dup=$dup jitter=${jitter}ms start=$start ${flavour}"
  if [ -z "$mismatch" ]; then
    matched=$((matched + 1))
    printf 'ok   #%-3d %s| sent=%s dropped=%s dup=%s reordered=%s\n' "$i" "$desc" \
      "$(truth packets_sent)" "$(truth packets_dropped)" "$(truth packets_duplicated)" "$(truth packets_reordered)"
  else
    printf 'FAIL #%-3d %s|%s\n' "$i" "$desc" "$mismatch"
  fi
done

echo "$matched/$count traces matched"
[ "$matched" -eq "$count" ]
