#!/usr/bin/env python3
"""crosscheck_pcap.py -- compare rtp_scope with tshark on arbitrary capture files.

For each pcap it runs
    tshark -r FILE -q -o rtp.heuristic_rtp:TRUE -z rtp,streams
and `rtp_scope --json FILE`, pairs the streams by (source, destination, SSRC)
and prints packets, lost and jitter side by side. Streams found by only one of
the tools are listed too, so a detection difference cannot hide.

Columns (tshark / rtp_scope):
  packets : tshark "Pkts"      / packets_received
  lost    : tshark "Lost"      / lost_rfc_signed (expected - received incl. duplicates)
  jitter  : tshark mean, max   / jitter_mean_ms, jitter_max_ms

Usage: scripts/crosscheck_pcap.py [--bin DIR] FILE.pcap [FILE.pcap ...]
Exit status: 0 if every stream matched on packets and lost, 1 if not, 3 if
tshark is missing (nothing is printed in that case, nothing is invented).
"""
import json
import re
import shutil
import subprocess
import sys

ROW = re.compile(
    r"^\s*([\d.]+)\s+([\d.]+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+0x([0-9A-Fa-f]+)\s+(\S+)\s+(\d+)\s+(-?\d+)\s+\((-?[\d.]+)%\)"
    r"\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)\s+(-?[\d.]+)")


def tshark_streams(path):
    out = subprocess.run(
        ["tshark", "-r", path, "-q", "-o", "rtp.heuristic_rtp:TRUE", "-z", "rtp,streams"],
        capture_output=True, text=True, check=False).stdout
    streams = {}
    for line in out.splitlines():
        m = ROW.match(line)
        if not m:
            continue
        g = m.groups()
        key = (g[2], int(g[3]), g[4], int(g[5]), int(g[6], 16))
        streams[key] = {"payload": g[7], "pkts": int(g[8]), "lost": int(g[9]),
                        "mean_jitter": float(g[15]), "max_jitter": float(g[16])}
    return streams


def scope_streams(binary, path):
    out = subprocess.run([binary, "--json", path], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        sys.exit("rtp_scope failed on %s: %s" % (path, out.stderr.strip()))
    streams = {}
    for s in json.loads(out.stdout)["streams"]:
        src_ip, src_port = s["source"].rsplit(":", 1)
        dst_ip, dst_port = s["destination"].rsplit(":", 1)
        key = (src_ip, int(src_port), dst_ip, int(dst_port), s["ssrc"])
        streams[key] = {"payload": s["payload_type_name"], "pkts": s["packets_received"],
                        "lost": s["lost_rfc_signed"], "mean_jitter": s["jitter_mean_ms"],
                        "max_jitter": s["jitter_max_ms"]}
    return streams


def main(argv):
    binary = "build/rtp_scope"
    if len(argv) >= 2 and argv[0] == "--bin":
        binary = argv[1].rstrip("/") + "/rtp_scope"
        argv = argv[2:]
    if not argv:
        sys.exit(__doc__)
    if shutil.which("tshark") is None:
        sys.stderr.write("tshark is not installed: cross-check not run (no output fabricated).\n")
        return 3

    version = subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    print("# scripts/crosscheck_pcap.py --bin %s %s" % (binary.rsplit("/", 1)[0], " ".join(argv)))
    print("# " + version + "   (tshark run with -o rtp.heuristic_rtp:TRUE)")
    all_ok = True
    for path in argv:
        ts, rs = tshark_streams(path), scope_streams(binary, path)
        print("\n%s: tshark finds %d stream(s), rtp_scope finds %d" % (path.rsplit("/", 1)[-1], len(ts), len(rs)))
        print("  %-42s %-8s | %11s | %9s | %-19s | %-19s" % (
            "stream (source -> destination, SSRC)", "payload", "pkts ts/rs", "lost ts/rs",
            "mean jitter ms ts/rs", "max jitter ms ts/rs"))
        for key in sorted(set(ts) | set(rs), key=str):
            label = "%s:%d -> %s:%d  %08x" % (key[0], key[1], key[2], key[3], key[4])
            a, b = ts.get(key), rs.get(key)
            if a is None or b is None:
                all_ok = False
                print("  %-42s only found by %s" % (label, "rtp_scope" if a is None else "tshark"))
                continue
            if a["pkts"] != b["pkts"] or a["lost"] != b["lost"]:
                all_ok = False
            print("  %-42s %-8s | %5d/%-5d | %4d/%-4d | %8.3f / %-8.3f | %8.3f / %-8.3f" % (
                label, a["payload"], a["pkts"], b["pkts"], a["lost"], b["lost"],
                a["mean_jitter"], b["mean_jitter"], a["max_jitter"], b["max_jitter"]))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
