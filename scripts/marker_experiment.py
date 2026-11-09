#!/usr/bin/env python3
"""marker_experiment.py -- why tshark's mean/max jitter differs when RTP marker bits are set.

On one real H.263 video capture tshark's mean jitter was lower than rtp_scope's
(15.505 vs 17.659 ms) while the max matched. This script isolates the cause with
small synthetic video-like traces (40 frames, 1 or 3 packets per frame, random
arrival jitter) where only the marker bit changes, and compares three numbers:

  tshark     : `tshark -z rtp,streams` mean / max jitter
  rtp_scope  : jitter_mean_ms / jitter_max_ms from `rtp_scope --json`
  model      : a re-implementation of the rule inferred from tshark's output:
               the jitter value J is computed per packet exactly as RFC 3550
               6.4.1 says, but a packet with the marker bit set does not
               contribute to the mean or the max; it still counts in the
               divisor of the mean (mean = (mean*n + J)/(n + 1), n counts every
               packet, mean is left unchanged by a marker packet).

This model was fitted to tshark's output, not read from Wireshark's source, so
treat it as "consistent with" rather than "is". With an optional capture file
argument the model is also compared on that file.

Usage: scripts/marker_experiment.py [--bin DIR] [CAPTURE.pcap]
"""
import json
import random
import struct
import subprocess
import sys
import tempfile
import os

CLOCK = 90000.0


def frame(seq, ts, marker, ssrc=0x1234, pt=34):
    rtp = struct.pack("!BBHII", 0x80, (marker << 7) | pt, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc) + bytes(100)
    udp = struct.pack("!HHHH", 5004, 5004, 8 + len(rtp), 0) + rtp
    ip = struct.pack("!BBHHHBBHII", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0, 0x0A000001, 0x0A000002)
    s = sum(struct.unpack("!10H", ip))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    ip = ip[:10] + struct.pack("!H", (~s) & 0xFFFF) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]) + b"\x08\x00"
    return eth + ip + udp


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, fr in packets:
            sec = int(t)
            f.write(struct.pack("<IIII", sec, int(round((t - sec) * 1e6)), len(fr), len(fr)))
            f.write(fr)


def synth(per_frame, marker_mode, frames=40, seed=5):
    rng = random.Random(seed)
    out, seq = [], 100
    for k in range(frames):
        ts = 900000 + k * 3000  # 30 frames/s at 90 kHz
        base = 1000.0 + k / 30.0 + rng.uniform(0, 0.006)
        for j in range(per_frame):
            marker = {"none": 0, "last": int(j == per_frame - 1), "first": int(j == 0), "all": 1}[marker_mode]
            out.append((base + j * 0.0004 + rng.uniform(0, 0.0002), seq, ts, marker))
            seq += 1
    out.sort()
    return out


def model(times, stamps, markers):
    """Return (mean_ms, max_ms) under the inferred marker rule."""
    j, mean, n, mx = 0.0, 0.0, 0, 0.0
    for i in range(1, len(times)):
        d = (times[i] - times[i - 1]) * CLOCK - (stamps[i] - stamps[i - 1])
        j += (abs(d) - j) / 16.0
        if not markers[i]:
            mean = (mean * n + j) / (n + 1)
            mx = max(mx, j)
        n += 1
    return mean * 1000 / CLOCK, mx * 1000 / CLOCK


def tshark_jitter(path):
    out = subprocess.run(["tshark", "-r", path, "-q", "-o", "rtp.heuristic_rtp:TRUE", "-z", "rtp,streams"],
                         capture_output=True, text=True).stdout
    row = [l.split() for l in out.splitlines() if " 0x" in l][0]
    return float(row[15]), float(row[16])


def scope_jitter(binary, path):
    s = json.loads(subprocess.run([binary, "--json", path], capture_output=True, text=True).stdout)["streams"][0]
    return s["jitter_mean_ms"], s["jitter_max_ms"]


def main(argv):
    binary = "build/rtp_scope"
    if len(argv) >= 2 and argv[0] == "--bin":
        binary, argv = argv[1].rstrip("/") + "/rtp_scope", argv[2:]
    print("# scripts/marker_experiment.py --bin %s %s" % (binary.rsplit("/", 1)[0], " ".join(argv)))
    print("# " + subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout.splitlines()[0])
    print("%-40s | %-17s | %-17s | %-17s" % ("trace (mean / max jitter, ms)", "tshark", "rtp_scope", "model of tshark"))
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "t.pcap")
        for per_frame, mode in [(1, "none"), (3, "none"), (3, "last"), (3, "first"), (1, "all"), (3, "all")]:
            pk = synth(per_frame, mode)
            write_pcap(path, [(t, frame(seq, ts, m)) for t, seq, ts, m in pk])
            t, s = tshark_jitter(path), scope_jitter(binary, path)
            m = model([p[0] for p in pk], [p[2] for p in pk], [p[3] for p in pk])
            ok &= abs(m[0] - t[0]) < 0.0015 and abs(m[1] - t[1]) < 0.0015
            print("%-40s | %7.3f / %-7.3f | %7.3f / %-7.3f | %7.3f / %-7.3f" % (
                "%d packet(s)/frame, marker on %s" % (per_frame, mode), t[0], t[1], s[0], s[1], m[0], m[1]))
        if argv:
            out = subprocess.run(["tshark", "-r", argv[0], "-o", "rtp.heuristic_rtp:TRUE", "-Y", "rtp", "-T", "fields",
                                  "-e", "frame.time_epoch", "-e", "rtp.timestamp", "-e", "rtp.marker"],
                                 capture_output=True, text=True).stdout
            rows = [l.split("\t") for l in out.splitlines()]
            m = model([float(r[0]) for r in rows], [int(r[1]) for r in rows], [r[2] in ("1", "True") for r in rows])
            t, s = tshark_jitter(argv[0]), scope_jitter(binary, argv[0])
            ok &= abs(m[0] - t[0]) < 0.0015 and abs(m[1] - t[1]) < 0.0015
            print("%-40s | %7.3f / %-7.3f | %7.3f / %-7.3f | %7.3f / %-7.3f" % (
                os.path.basename(argv[0]), t[0], t[1], s[0], s[1], m[0], m[1]))
    print("model matches tshark (within 0.0015 ms) on every row: %s" % ("yes" if ok else "NO"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
