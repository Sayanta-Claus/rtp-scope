# Real captures: rtp_scope vs tshark

Three small public sample captures were run through both tools. The captures themselves are not in the repo, and IP addresses are left out of this table. All numbers are "rtp_scope / tshark".

| Capture | Source | Stream | Packets | Lost | Jitter mean (ms) | Jitter max (ms) |
|---|---|---|---:|---:|---:|---:|
| MagicJack-_short_call.pcap | wiki sample (see note) | PCMU, direction A to B, SSRC 0x2a173650 | 642 / 642 | 0 / 0 | 12.234 / 12.234 | 12.838 / 12.838 |
| MagicJack-_short_call.pcap | wiki sample (see note) | PCMU, direction B to A, SSRC 0x31be1e0e | 626 / 626 | 0 / 0 | 0.229 / 0.229 | 0.832 / 0.832 |
| aaa.pcap | not recorded (see note) | PCMA, SSRC 0x3796cb71 | 9 / 9 | 0 / 0 | 5.646 / 5.646 | 7.799 / 7.799 |
| h263-over-rtp.pcap | wiki sample (see note) | H.263 video, SSRC 0x5482ece0 | 45 / 45 | 0 / 0 | **17.659 / 15.505** | 32.187 / 32.186 |

Note on sources: the file names for MagicJack and h263 match entries on the [Wireshark SampleCaptures wiki](https://wiki.wireshark.org/SampleCaptures), but I did not record where each file was downloaded from, and I don't know the origin of `aaa.pcap`. Confirm the source and terms of each file before relying on this column.

## What agrees and what doesn't

Both tools found the same 4 streams and agree on packets and loss in every case. "Lost" is the RFC 3550 value (expected minus received, duplicates counted as received), which is what tshark prints. Jitter agrees to three decimals on 3 of the 4 streams.

Differences:

- **H.263 mean jitter, 17.659 vs 15.505 ms: cause not found.** The max matches, so the per-packet jitter values are right and only the averaging differs; the video frames are split into several packets that share one RTP timestamp, which the other three streams don't do. I tried several averaging formulas on tshark's own packet data and none reproduced 15.505.
- **H.263 max jitter, 32.187 vs 32.186 ms: last digit.** My value is 32.1865 and rounds up; tshark shows 32.186. Probably rounding or truncation; I didn't investigate further.
- **Fixed before this table (not a current difference):** the first run found extra "streams" in two files, DNS and NetBIOS packets that looked like RTP, and rejected the H.263 file because of its loopback link type. Both were fixed in rtp_scope (see the README).

## How to reproduce

tshark 3.6.2; rtp_scope as of commit `e550855`. Put the three files in `captures/` (git-ignored), then:

```
cmake -S . -B build && cmake --build build -j
python3 scripts/crosscheck_pcap.py --bin build \
    captures/MagicJack-_short_call.pcap captures/aaa.pcap captures/h263-over-rtp.pcap
```

For each file the script runs these two commands and pairs the streams by addresses, ports and SSRC:

```
tshark -r FILE -q -o rtp.heuristic_rtp:TRUE -z rtp,streams
build/rtp_scope --json FILE
```

The `-o rtp.heuristic_rtp:TRUE` option makes tshark detect RTP on any UDP port, so this checks the numbers, not rtp_scope's RTP detection. The script's raw output contains addresses, so the repo does not keep it.
