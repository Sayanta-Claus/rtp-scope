#!/usr/bin/env bash
# crosscheck_tshark.sh -- compare rtp_scope with Wireshark's RTP stream analysis.
#
# For several generated captures it runs
#     tshark -r FILE -q -d udp.port==5004,rtp -z rtp,streams
# and rtp_scope --json on the same file, then prints packets, lost and jitter
# side by side. If tshark is not installed the script says so and exits with
# status 3 without printing any comparison.
#
# Columns:
#   packets : tshark "Pkts"            vs rtp_scope packets_received (all RTP packets incl. duplicates)
#   lost    : tshark "Lost"            vs rtp_scope lost_rfc_signed  (expected - received, may be negative)
#   jitter  : tshark mean / max jitter vs rtp_scope jitter_mean_ms / jitter_max_ms
#             (mean and max of the RFC 3550 running estimate over the packets)
#
# Usage: scripts/crosscheck_tshark.sh [--bin DIR]       (default: build)
set -u
bin=build
if [ "${1:-}" = "--bin" ]; then bin="$2"; fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark is not installed: cross-check not run (no output fabricated)." >&2
  exit 3
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "# scripts/crosscheck_tshark.sh --bin $bin"
echo "# $(tshark --version | head -n 1)"
printf '%-34s | %8s %8s | %9s %9s | %-21s | %-21s\n' "scenario" "pkts(ts)" "pkts(rs)" "lost(ts)" "lost(rs)" \
  "jitter mean ms (ts/rs)" "jitter max ms (ts/rs)"

run_case() {  # run_case <label> <rtp_gen args...>
  local label="$1"; shift
  "$bin/rtp_gen" --out "$tmp/c.pcap" "$@" >/dev/null || { echo "rtp_gen failed for $label"; return; }
  local row
  row="$(tshark -r "$tmp/c.pcap" -q -d udp.port==5004,rtp -z rtp,streams 2>/dev/null | grep -m1 ' 0x')"
  # shellcheck disable=SC2086
  set -- $row
  local ts_pkts="$9" ts_lost="${10}" ts_mean="${16}" ts_max="${17}"
  "$bin/rtp_scope" --json "$tmp/c.pcap" >"$tmp/c.json"
  js() { grep -m1 "\"$1\":" "$tmp/c.json" | sed 's/.*: *//; s/,$//'; }
  printf '%-34s | %8s %8s | %9s %9s | %9s / %-9.3f | %9s / %-9.3f\n' "$label" \
    "$ts_pkts" "$(js packets_received)" "$ts_lost" "$(js lost_rfc_signed)" \
    "$ts_mean" "$(js jitter_mean_ms)" "$ts_max" "$(js jitter_max_ms)"
}

run_case "clean network"                    --duration 20 --seed 1
run_case "5% loss"                          --duration 20 --seed 2 --loss 0.05
run_case "loss + normal jitter 15ms"        --duration 20 --seed 3 --loss 0.03 --jitter-ms 15 --jitter-dist normal
run_case "uniform jitter 40ms"              --duration 20 --seed 4 --jitter-ms 40
run_case "seq wraparound + loss"            --duration 20 --seed 5 --loss 0.05 --wrap --jitter-ms 10
run_case "reorder 5% + dup 5% + loss"       --duration 20 --seed 6 --loss 0.03 --reorder 0.05 --duplicate 0.05 --jitter-ms 10
run_case "Opus-like PT 111 (48 kHz) jitter" --duration 20 --seed 7 --pt 111 --interval-ms 20 --jitter-ms 20 --jitter-dist normal --loss 0.02
