# Real capture cross-check

rtp_scope vs tshark 3.6.2 on three small public captures. The capture files are not in the repo (they contain IP addresses), so streams are identified by SSRC; A→B is the direction whose packets appear first in the capture. Numbers are copied from the output of:

```
python3 scripts/crosscheck_pcap.py --bin build captures/MagicJack-_short_call.pcap captures/aaa.pcap captures/h263-over-rtp.pcap
```

which runs the two commands listed under each capture. `-o rtp.heuristic_rtp:TRUE` makes tshark detect RTP on any UDP port, so this checks the numbers, not rtp_scope's RTP detection. "Lost" is the RFC 3550 value (expected minus received, duplicates counted as received), which is what tshark prints.

Overall: 3 captures, 4 RTP streams. Packets, loss and max jitter are identical on all 4 streams; mean jitter is identical on 3 and differs on the H.263 stream, for the reason given below. None of the captures has packet loss or reordering.

## MagicJack-_short_call.pcap

Source: Wireshark SampleCaptures wiki, https://wiki.wireshark.org/SampleCaptures

Commands:
```
./build/rtp_scope --json MagicJack-_short_call.pcap
tshark -r MagicJack-_short_call.pcap -q -o rtp.heuristic_rtp:TRUE -z rtp,streams
```

| Stream (SSRC) | Packets (yours / tshark) | Lost (yours / tshark) | Mean jitter ms (yours / tshark) | Max jitter ms (yours / tshark) |
|---|---|---|---|---|
| 0x2a173650 PCMU A→B | 642 / 642 | 0 / 0 | 12.234 / 12.234 | 12.838 / 12.838 |
| 0x31be1e0e PCMU B→A | 626 / 626 | 0 / 0 | 0.229 / 0.229 | 0.832 / 0.832 |

Differences: none.

## aaa.pcap

Source: Wireshark SampleCaptures wiki, https://wiki.wireshark.org/SampleCaptures

Commands:
```
./build/rtp_scope --json aaa.pcap
tshark -r aaa.pcap -q -o rtp.heuristic_rtp:TRUE -z rtp,streams
```

| Stream (SSRC) | Packets (yours / tshark) | Lost (yours / tshark) | Mean jitter ms (yours / tshark) | Max jitter ms (yours / tshark) |
|---|---|---|---|---|
| 0x3796cb71 PCMA | 9 / 9 | 0 / 0 | 5.646 / 5.646 | 7.799 / 7.799 |

Differences: none.

## h263-over-rtp.pcap

Source: Wireshark SampleCaptures wiki, https://wiki.wireshark.org/SampleCaptures

Commands:
```
./build/rtp_scope --json h263-over-rtp.pcap
tshark -r h263-over-rtp.pcap -q -o rtp.heuristic_rtp:TRUE -z rtp,streams
```

| Stream (SSRC) | Packets (yours / tshark) | Lost (yours / tshark) | Mean jitter ms (yours / tshark) | Max jitter ms (yours / tshark) |
|---|---|---|---|---|
| 0x5482ece0 H.263 video | 45 / 45 | 0 / 0 | **17.659 / 15.505** | 32.186 / 32.186 |

Differences: mean jitter, 17.659 (rtp_scope) vs 15.505 (tshark). Cause: tshark leaves packets with the RTP marker bit set out of its mean and max jitter (they still count in the divisor of its mean), while rtp_scope averages over every packet. H.263 sets the marker on the last packet of each video frame, 10 of the 45 packets here. Evidence: on traces I built where only the marker bit changes, tshark and rtp_scope agree exactly when no packet has the bit set, and tshark reports 0 jitter when every packet has it. A model of that rule reproduces tshark's mean and max on all 7 rows of [results/marker-experiment.txt](marker-experiment.txt), this file included. I fitted the rule to tshark's output and have not read Wireshark's source, so it is inferred, not confirmed.

## Reproducing the marker-bit finding

```
python3 scripts/marker_experiment.py --bin build captures/h263-over-rtp.pcap | tee results/marker-experiment.txt
```

It builds synthetic video-like traces where only the marker bit changes and prints tshark, rtp_scope and the inferred model side by side (output in [marker-experiment.txt](marker-experiment.txt)).
