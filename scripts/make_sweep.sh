#!/usr/bin/env bash
# make_sweep.sh -- reproduce results/sweep.csv and the latency-vs-loss chart.
#
# Generates a 120 s trace with realistic impairments (2% loss, normal jitter
# of 25 ms, 0.5% reordering, talkspurts of 3 s speech / 1 s silence), runs the
# jitter-buffer sweep on it and plots the result.
# Usage: scripts/make_sweep.sh [--bin DIR] [--out DIR]    (defaults: build, results)
set -eu
bin=build
out=results
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) bin="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) echo "usage: $0 [--bin DIR] [--out DIR]" >&2; exit 2 ;;
  esac
done
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"
"$bin/rtp_gen" --out "$tmp/sweep.pcap" --duration 120 --seed 3 --loss 0.02 --jitter-ms 25 \
  --jitter-dist normal --talk-on-ms 3000 --talk-off-ms 1000 --reorder 0.005 >/dev/null
"$bin/rtp_scope" --sweep "$tmp/sweep.pcap" >"$out/sweep.csv"
python3 "$here/plot_sweep.py" "$out/sweep.csv" "$out/sweep.png"
