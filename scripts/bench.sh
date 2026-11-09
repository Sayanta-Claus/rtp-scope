#!/usr/bin/env bash
# bench.sh -- generate a large synthetic capture, run rtp_bench several times,
# print the median of each metric together with the machine description.
#
# Usage: scripts/bench.sh [--packets N] [--runs R] [--bin DIR]
#   --packets N   packets in the generated capture (default 1000000)
#   --runs R      repetitions; the median is reported (default 5)
#   --bin DIR     build directory containing rtp_gen and rtp_bench (default: build)
#
# The capture is written to a temporary directory (not the repo), read once to
# warm the page cache, then each run is a fresh rtp_bench process so the peak
# memory figure belongs to that run alone.
set -eu
packets=1000000
runs=5
bin=build
while [ $# -gt 0 ]; do
  case "$1" in
    --packets) packets="$2"; shift 2 ;;
    --runs) runs="$2"; shift 2 ;;
    --bin) bin="$2"; shift 2 ;;
    *) echo "usage: $0 [--packets N] [--runs R] [--bin DIR]" >&2; exit 2 ;;
  esac
done
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "# scripts/bench.sh --packets $packets --runs $runs --bin $bin"
"$here/machine_info.sh"

"$bin/rtp_gen" --out "$tmp/bench.pcap" --packets "$packets" --seed 1 --loss 0.01 --reorder 0.005 \
  --duplicate 0.002 --jitter-ms 5 --jitter-dist normal --wrap >/dev/null
cat "$tmp/bench.pcap" >/dev/null   # warm the page cache

for ((r = 1; r <= runs; r++)); do "$bin/rtp_bench" "$tmp/bench.pcap" >"$tmp/run$r.txt"; done

median() {  # median <key>: median of that key over all runs
  grep -h "^$1=" "$tmp"/run*.txt | cut -d= -f2 | sort -g | awk '{v[NR]=$1} END {print v[int((NR+1)/2)]}'
}
first() { grep -h "^$1=" "$tmp/run1.txt" | cut -d= -f2-; }

echo "compiler : $(first compiler)"
echo "flags    : $(first flags)"
echo "capture  : $packets packets sent by the generator (1% loss, 0.5% reorder, 0.2% duplicate) ->"
echo "           $(first packets) packets in the file, $(first file_mb) MB (Ethernet/IPv4/UDP/RTP, 160-byte payloads)"
echo "runs     : $runs (median reported)"
echo
printf '%-22s %14s %12s\n' "stage" "packets/sec" "MB/s"
printf '%-22s %14s %12s\n' "parse only"       "$(median parse_pps)"   "$(median parse_mbps)"
printf '%-22s %14s %12s\n' "parse + analysis" "$(median analyze_pps)" "$(median analyze_mbps)"
echo
echo "median parse time    : $(median parse_seconds) s"
echo "median analysis time : $(median analyze_seconds) s"
echo "peak memory (median) : $(median peak_rss_kb_proc) kB  (VmHWM; getrusage ru_maxrss: $(median peak_rss_kb_rusage) kB)"
echo
echo "individual runs (analyze packets/sec): $(grep -h '^analyze_pps=' "$tmp"/run*.txt | cut -d= -f2 | tr '\n' ' ')"
