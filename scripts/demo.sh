#!/usr/bin/env bash
# demo.sh -- a short end-to-end demo: rtp_gen -> rtp_scope -> --simulate.
# Run it directly, or record it with:
#     asciinema rec -c scripts/demo.sh results/demo.cast
# Usage: scripts/demo.sh [--bin DIR]       (default: build)
set -eu
bin=build
if [ "${1:-}" = "--bin" ]; then bin="$2"; fi
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
say() { printf '\n\033[1m$ %s\033[0m\n' "$*"; sleep 1; }

say "rtp_gen: 30 s of G.711 with 3% loss, 20 ms jitter, reordering, duplicates, sequence wraparound"
cmd=("$bin/rtp_gen" --out "$tmp/demo.pcap" --duration 30 --seed 42 --loss 0.03 --jitter-ms 20 --jitter-dist normal --reorder 0.01 --duplicate 0.01 --wrap)
echo "${cmd[*]##*/}" | sed "s|$tmp/||"; "${cmd[@]}"
say "cat demo.pcap.truth   # what the generator actually did (ground truth)"
grep -E 'packets_(sent|dropped|duplicated|reordered)' "$tmp/demo.pcap.truth"
sleep 2
say "rtp_scope demo.pcap   # what the analyzer measured"
"$bin/rtp_scope" "$tmp/demo.pcap"
sleep 3
say "rtp_scope --simulate demo.pcap   # jitter-buffer strategies"
"$bin/rtp_scope" --simulate "$tmp/demo.pcap" | sed -n '/jitter-buffer simulation/,$p'
sleep 3
