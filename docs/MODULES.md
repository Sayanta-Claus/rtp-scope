# rtp-scope: module guide

Plain-English tour of every module, with the questions each design choice tends to raise.

## Data flow

```
 capture.pcap
      |
      v
 +-------------+   frame bytes    +-------------+   UDP payload   +-----------+
 | pcap_reader | ---------------> | net_decode  | --------------> | classify  |
 | (file fmt)  |  + timestamp     | Eth/VLAN/   |  (+ip,ports)    | RTP? RTCP?|
 +-------------+                  | SLL,IPv4,UDP|                 +-----------+
                                  +-------------+                       |
        every read goes through byte_reader (bounds + endianness)       | RtpHeader
                                                                         v
                                                              +-----------------+
                                                              |   analyzer      |
                                                              | counters (M1)   |
                                                              +-----------------+
 (pcap_writer is the mirror image: it builds frames/pcaps for rtp_gen and tests.)
```


---

## byte_reader (`src/byte_reader.hpp`)

**How it works.** A non-owning cursor over `[data, data+size)`. `read_u16/u32(Endian, out)` check `remaining()`, then build the value from individual bytes with shifts. On failure they return `false` and change nothing.

**Why not cast to a struct?** A `reinterpret_cast<Header*>(buf)` is undefined behaviour (alignment, strict aliasing), depends on struct padding and host endianness, and has no bounds check.

**Questions and answers**
- *Why is network data "big-endian"?* Network byte order is a convention (RFC 1700 era) that every protocol header uses; the pcap file header is the exception: it uses the writer's native order.
- *What happens on a short read?* It returns false, the caller marks the packet malformed and moves on; there is no exception and no UB.

## pcap_reader (`src/pcap_reader.*`)

**How it works.** Reads the 24-byte global header, reads the magic as big-endian and matches one of four values to learn byte order and microsecond/nanosecond timestamps. Then it streams 16-byte record headers + data through one reusable buffer. Link types 0 (BSD loopback), 1 (Ethernet) and 113 (Linux SLL) are accepted; others are rejected with a message.

**Questions**
- *How do you detect byte order?* The magic `0xa1b2c3d4` is written in the writer's native order, so reading it as big-endian gives either `a1b2c3d4` (file is BE) or `d4c3b2a1` (file is LE).
- *What if the file is cut off?* A truncated last record is flagged (`capture_truncated`) and earlier packets are kept; this is what you get when tcpdump is killed.
- *What if a record claims 4 GB?* Anything over 16 MiB is treated as corrupt before allocating.
- *Why stream rather than load the file?* Memory stays O(one packet), so a multi-GB capture works.

## net_decode (`src/net_decode.*`)

**How it works.** Skips the link header (Ethernet 14 bytes plus any number of 802.1Q/802.1ad tags, the 16-byte SLL pseudo header, or the 4-byte BSD loopback header), checks the ethertype is IPv4, parses the IPv4 header using IHL*4 as its length, rejects fragments, and parses the UDP header. The IP `total_length` (not the captured length) bounds the payload, so Ethernet padding is ignored.

**Questions**
- *Why can't you just assume a 20-byte IP header?* IP options make it 20 to 60 bytes; IHL gives the length in 32-bit words.
- *Why skip fragments?* Only the first fragment has the UDP header; reassembly is out of scope, so they are counted and reported.
- *Why does a VLAN tag matter?* It shifts everything by 4 bytes and changes where the real ethertype sits.

## rtp_header (`src/rtp_header.*`)

**How it works.** Byte 0 = `VV P X CCCC`, byte 1 = `M PPPPPPP`, then 16-bit sequence, 32-bit timestamp, 32-bit SSRC, CC x 32-bit CSRCs, an optional extension (4 + 4*length bytes), and padding whose count is the last byte. `payload_length = total - header - padding`, all checked.

**Questions**
- *Why does RTP run over UDP, not TCP?* Media is real-time: a retransmitted packet arrives too late to play, so TCP's reliability and head-of-line blocking only add latency. RTP carries its own sequence numbers and timestamps so the receiver can detect loss and reorder or conceal it.
- *What is the SSRC?* A random 32-bit id of a synchronisation source (one stream), so many streams can share ports.
- *What does the marker bit mean?* Profile-specific; for audio it marks the start of a talkspurt, which the jitter buffer later uses.

## classify (`src/classify.*`)

**How it works.** RTP has no magic number, so we use rules: version == 2, an RTCP packet type (200 to 204) goes to RTCP, the RTCP-colliding byte range is rejected, and the RTP header must be structurally consistent. Version-2-looking packets with impossible lengths are `Malformed`, others `NotRtp`.

**Questions**
- *How does Wireshark find RTP on arbitrary ports?* Same idea: heuristics (plus signalling such as SDP when available).
- *Why check RTCP first?* A Sender Report also has version 2, and its byte 1 (200) would look like marker + payload type 72.
- *What can go wrong?* Random UDP can pass the structural test: DNS and NetBIOS packets start with a random transaction id, so one in four has "version 2". My first run on real captures showed exactly that (fake "streams" with SSRC 0). The fix is in `analyzer`, below; the classifier itself stays a cheap per-packet check.

## analyzer (`src/analyzer.*`)

**How it works.** Loops over records: decode, classify, and increment exactly one counter, so `frames` always equals the sum of every bucket. Two extra rules keep look-alike UDP out of the stream list: packets to or from ports of other well-known protocols (DNS 53, NetBIOS 137/138, DHCP, NTP, ...) are never RTP, and at the end a stream is kept only if it showed two packets with consecutive sequence numbers (RFC 3550 A.1 "probation", MIN_SEQUENTIAL = 2). Packets of dropped streams move from `rtp` to `non_rtp_udp` and are counted in `rtp_unconfirmed`, so the totals still add up.

**Questions**
- *Why count rather than print warnings?* Counters show up in the report and tests; you can see where every packet went.
- *Why judge a stream at the end instead of dropping its first packets until it is confirmed?* Then no early packet of a real stream is lost from its loss and jitter numbers, and there is no buffering of unconfirmed packets.
- *Why a port list as well as the sequence check?* A NetBIOS client that increments its transaction id can look sequential, and the port list is cheap and mirrors how Wireshark lets a port-assigned dissector win. The cost is that RTP on those ports is missed.
- *What stops a flood of random UDP from using all the memory?* Each distinct (addresses, ports, SSRC) is a stream, so the number of streams is capped at 100,000 and a stream costs a couple hundred bytes.

## pcap_writer (`src/pcap_writer.*`)

**How it works.** Serialises RTP, wraps it in UDP/IPv4 (with a correct IP checksum) and Ethernet, SLL or loopback framing, optionally with a VLAN tag, and writes pcap files in either byte order and resolution.

**Questions**
- *Why write it yourself?* Test data produced by independent code (a writer) checks the reader; it is also the basis of `rtp_gen`.
- *How is the IPv4 checksum computed?* Ones'-complement sum of the header's 16-bit words (checksum field zero), fold carries, invert.

---

# Statistics modules

Data flow:

```
 RtpHeader + arrival time
        |
        v
 +----------------+  seq16   +--------------+
 | stream_stats   | -------> | seq_tracker  |  extended seq, dup / ooo / loss
 | (one per SSRC  |          +--------------+
 |  + 5-tuple)    |  ts,t    +--------------+
 |                | -------> | jitter       |  J += (|D|-J)/16
 +----------------+          +--------------+
        ^   clock rate  <--- clock_rate (PT table + --clock-rate)
        |
        v
 +----------------+
 | report         |  text tables / hand-written JSON
 +----------------+
```

## seq_tracker (`src/seq_tracker.*`)

**How it works.** Implements RFC 3550 Appendix A.1. `udelta = (uint16)(seq - max_seq)` is the forward distance mod 65536. Small forward steps (< 3000) are in-order (a gap means lost packets, and `seq < max_seq` means the counter wrapped so `cycles++`). A step that lands just *behind* the max (within 100) is late or duplicate. Anything else is a suspicious jump: it is rejected unless the very next packet continues from it (then the source restarted). A 256-bit "seen" ring (a packet is at most 100 behind the max, so 256 slots are plenty) distinguishes duplicates from reordered packets. `expected = ext_highest - base + 1`; `lost = expected - unique received`.

**Questions and answers**
- *Why does the sequence number need an extended 32-bit (here 64-bit) counter?* The field is 16 bits and wraps after 65536 packets, about 22 minutes at 50 packets/s. Without counting wraps you cannot compute "packets expected", so loss over a long call is wrong. RFC 3550 keeps `cycles` in the high 16 bits.
- *How do you tell a wrap from a reordered packet?* Compare modulo 2^16: a small positive `udelta` is forward (even if the number is numerically smaller), a `udelta` near 65536 is a packet slightly behind.
- *Why MAX_DROPOUT = 3000 and MAX_MISORDER = 100?* They bound how much loss or reordering we believe before suspecting a restart or a corrupt/foreign packet.
- *Why can loss be negative in the RFC?* Duplicates count as received. We clamp to 0 and report duplicates on their own.
- *What is the difference between lost and out-of-order?* An out-of-order packet arrives late; it is received, so it does not count as lost once it arrives.

## jitter (`src/jitter.*`)

**How it works.** For consecutive packets, `D = (arrival_i - arrival_{i-1}) - (ts_i - ts_{i-1})` in timestamp units; then `J += (|D| - J)/16`. Arrival gaps are converted from ns to timestamp units, and the timestamp difference is a signed 32-bit value so it survives the 2^32 wrap.

**Questions**
- *Why is jitter smoothed by 1/16?* It is a low-pass filter: single outliers move J by only 1/16 of their size, but a sustained change is tracked within tens of packets.
- *Why do clocks not need to be synchronised?* Only differences between packets are used, so a constant clock offset or constant network delay cancels.
- *Why is jitter in timestamp units?* Because the receiver can compute it without knowing wall-clock time; divide by the clock rate to get seconds (we also print ms).

## clock_rate (`src/clock_rate.*`)

**How it works.** A table of static payload types (RFC 3551) with a default of 48000 for dynamic types; `--clock-rate PT=HZ` overrides it.

**Questions**
- *G.722 is 16 kHz audio, so why 8000?* A historical error in the RFC was kept for compatibility: its RTP clock is 8000.
- *Why can't the clock rate be read from the packet?* Dynamic payload types are bound to codecs in signalling (SDP), not in the RTP header.

## stream_stats (`src/stream_stats.*`)

**How it works.** One object per `(src ip, src port, dst ip, dst port, SSRC)`. Each packet updates byte and time totals, the sequence tracker and, unless it is a duplicate, the jitter estimator. Bitrate = RTP bytes x 8 / (last arrival - first arrival). Optionally records every arrival for the simulator.

**Questions**
- *Why include the SSRC in the key?* Several streams (audio, video, different participants) can share ports in a mixer or bundle.
- *Why ignore duplicates in the jitter calculation?* A duplicate carries the same RTP timestamp as the original, so it is not a new measurement of the media's delay: arriving right away it adds `D = 0` (pulling J down), arriving much later it adds a spike the media never experienced. (Wireshark includes them, which is the only reason its jitter differs from ours on traces with duplicates; I verified that by including them temporarily and matching tshark to four decimals.)

## report (`src/report.*`)

**How it works.** Text and JSON are produced from the same accessors. JSON is written by hand; `json_escape` handles `"`, `\` and control characters (`\u00XX`).

**Questions**
- *Why hand-write JSON?* The project is dependency-free; JSON output is simple, and the only tricky part is string escaping (RFC 8259).
- *Why never print nan/inf?* They are not valid JSON numbers.

## cli_args (`src/cli_args.*`)

**How it works.** `parse_uint` / `parse_double` accept only fully-numeric strings (decimal or `0x` hex for integers).

**Questions**
- *Why not `atoi`?* It returns 0 for garbage and ignores trailing text, hiding command-line typos.

---

# Traffic generator

```
 GenConfig (seed, loss, jitter, reorder, dup, wrap...)
      |
      v
 +---------------+  arrivals   +--------------+  frames  +-------------+
 | trace_gen     | ----------> | pcap_writer  | -------> | out.pcap    |
 | (sender+net)  |             +--------------+          +-------------+
 |      |        |  GroundTruth                           (analyzer reads it back)
 +------+--------+------------> out.pcap.truth  (key=value)
        ^
        | numbers
 +---------------+
 | traffic_model |  xoshiro256** + uniform/normal
 +---------------+
```

## traffic_model (`src/traffic_model.*`)

**How it works.** xoshiro256** is seeded through splitmix64. `uniform()` takes the top 53 bits of a 64-bit output; `normal()` is Box-Muller. Loss, delay, reorder and duplicate decisions each get their own independent stream of the same seed.

**Questions**
- *Why not `std::normal_distribution`?* The standard fixes engines but not distributions, so the same seed gives different numbers on libstdc++ vs libc++. Ours is identical everywhere, so published results are reproducible.
- *Why separate streams per effect?* Changing `--loss` must not silently change the jitter values for the same seed.

## trace_gen (`src/trace_gen.*`) and rtp_gen (`tools/rtp_gen.cpp`)

**How it works.** (1) The sender emits packet n at `n*interval` with `seq = start + n` and a timestamp from the clock rate. (2) Each packet is dropped with probability `loss`. (3) Delivered packets get `base + jitter` delay but the path is FIFO, so jitter alone never reorders. (4) With probability `reorder`, a packet swaps places with the next delivered one (arrival *times* stay in place so the capture stays time-ordered). (5) With probability `duplicate`, an identical copy follows. Every step is counted into `GroundTruth`.

**Questions**
- *How do you know your analyzer is right?* The generator is an independent oracle: it knows exactly how many packets it dropped, duplicated and reordered. The end-to-end test and `scripts/validate.sh` require exact agreement.
- *What does "reordered" mean here?* One reordered packet = one packet that arrives after a packet with a higher sequence number; with adjacent swaps that is exactly one per swap, and it is what a receiver can observe.
- *Why is "lost" the observable loss?* A receiver cannot know about packets dropped before the first or after the last delivered one, so `packets_lost` counts drops between the lowest and highest delivered packet (the truth file also has `packets_dropped` for everything).
- *Why `--wrap`?* Starting at 65500 makes the 16-bit sequence number wrap after 36 packets, exercising the extended-sequence logic.

---

# Jitter-buffer simulator

```
 StreamStats.arrivals --> make_trace --> PlayoutTrace --+--> simulate_fixed    --> SimResult --+--> table (--simulate)
 (arrival time, RTP ts,                (arrival_s,      |                                        |
  marker, duplicate)                    media_s, marker)+--> simulate_adaptive --> SimResult --+--> CSV   (--sweep)
```

## jitter_buffer (`src/jitter_buffer.*`)

**How it works.** For each packet, *transit* `n = arrival - media time` (media time comes from the unwrapped RTP timestamp, both measured from the first packet). A buffer with playout delay `D` plays the packet at `media + D`; if `n <= D` it is on time and waits `D - n` in the buffer, otherwise it is late and discarded. Lost = expected minus arrived. **Fixed** uses a constant `D`. **Adaptive** (Ramjee et al. 1994, algorithm 1) keeps an EWMA of the transit `d` and of its deviation `v` and targets `D = d + k*v`; the delay jumps to the target at talkspurt boundaries (marker bit, or a long gap in media time) and otherwise creeps towards it by at most 0.5 ms per packet, so playback never glitches.

**Questions and answers**
- *What does a jitter buffer trade off?* Latency against late-packet loss: a bigger buffer absorbs more network jitter but delays the audio (interactive calls want under ~150-200 ms end to end). The `--sweep` output draws exactly this curve.
- *Why adapt only at talkspurt boundaries?* Changing delay in the middle of speech means stretching or squeezing audio (audible). Silence between talkspurts can be lengthened or shortened unnoticed.
- *Why mean + k * deviation?* If transit were roughly normal, k = 4 covers almost all of the distribution; a larger k means fewer late packets and more latency.
- *Why the bias-corrected weight in the estimator?* With alpha = 0.998 a plain EWMA would take ~500 packets (10 s of audio) to forget its start value; using `min(alpha, 1 - 1/count)` makes the first samples a running average.
- *What about packets that are lost?* A jitter buffer cannot fix them; they are reported separately (and a real codec would conceal them with packet-loss concealment).
- *How is lateness judged causally?* The delay applied to a packet is the one chosen before that packet's own transit enters the estimate.

---

# Tests, robustness, benchmark, cross-check

```
 tests/ (ctest)                        scripts/
   test_harness.hpp  CHECK/TEST          validate.sh   rtp_gen --truth  vs  rtp_scope --json  (120 traces, exact)
   test_*.cpp (12)   unit + e2e          fuzz.sh       pcap_mutate -> rtp_scope under ASan/UBSan (1000 mutants)
   cli_smoke.sh      real binaries       bench.sh      rtp_gen 1M pkts -> rtp_bench x5 -> median
   mutator.hpp  <--- shared by test_mutation.cpp and tools/pcap_mutate.cpp
                                         crosscheck_tshark.sh   tshark -z rtp,streams  vs  rtp_scope
                                         make_sweep.sh + plot_sweep.py   --sweep CSV -> chart
```

## Test harness (`tests/test_harness.hpp`)

**How it works.** `TEST(name)` registers a function at static-initialisation time; `CHECK` / `CHECK_EQ` record failures with file:line and keep going; `TEST_MAIN()` runs everything and returns non-zero on any failure, which is all `ctest` needs.

**Questions**
- *Why no GoogleTest?* The project is dependency-free, and a 60-line harness is easy to explain. It lacks fixtures and mocking, which these tests do not need.
- *What do the tests cover?* Sequence wraparound, truncated and malformed packets, bad RTP version, VLAN, both pcap byte orders and both timestamp resolutions, duplicates and reordering, a hand-computed jitter example, jitter-buffer arithmetic, and generator-vs-analyzer agreement.

## Ground-truth validation (`scripts/validate.sh`) and the oracle idea

**How it works.** `rtp_gen` knows how many packets it dropped/duplicated/reordered; `rtp_scope` measures the same from the file. 120 parameter combinations must agree exactly on received, unique, expected, lost, duplicates, reordered and highest extended sequence number.

**Questions**
- *Is that circular?* Partly: both tools encode my definitions of "reordered" and "lost". That is why the definitions are written down in the README and why the independent Wireshark cross-check exists.
- *Why is "lost" the *observable* loss?* A receiver cannot know about packets dropped before the first or after the last delivered packet.

## Mutation robustness (`tests/mutator.hpp`, `test_mutation.cpp`, `scripts/fuzz.sh`)

**How it works.** Deterministic corruptions (bit flips, byte overwrites, truncation, chunk delete/insert, extreme 16/32-bit values, half of them in the first 256 bytes where the headers are) are applied to valid captures; each must be analysed or rejected with an error, never crash, hang or trip ASan/UBSan. `fuzz.sh` does it on the real binary with distinct exit codes for sanitizer failures.

**Questions**
- *Is this fuzzing?* It is mutation testing with fixed seeds, not coverage-guided; good at catching missing bounds checks, not a proof. A real fuzzer (libFuzzer/AFL) would be the next step.
- *What did designing it teach me?* A damaged record length of ~16 MB made the reader allocate that much before noticing the file was short; it now reads in 64 KiB chunks.
- *What do ASan and UBSan catch?* Out-of-bounds and use-after-free memory errors, and undefined behaviour such as signed overflow or misaligned access; `-fno-sanitize-recover` makes any finding a hard failure.

## Benchmark (`bench/bench.cpp`, `scripts/bench.sh`)

**How it works.** `rtp_gen` writes a 1M-packet capture; `rtp_bench` (always built with `-O2`) times a parse-only pass and a full-analysis pass and reads its own peak RSS from `/proc/self/status`; the script runs it 5 times in fresh processes and prints the median.

**Questions**
- *Why the median?* One slow run (cache, scheduler noise) must not skew the result; the median ignores outliers.
- *Why is memory flat?* Records are streamed through one buffer, and per-stream state is a couple hundred bytes (the duplicate ring is 256 bits).
- *What does it not measure?* Disk speed (the capture is in the page cache) and anything on bare metal (it ran under WSL2).

## Wireshark cross-check (`scripts/crosscheck_tshark.sh`, `scripts/crosscheck_pcap.py`)

**How it works.** Same generated files through `tshark -z rtp,streams` and `rtp_scope --json`; packets, lost and mean/max jitter printed side by side.

**Questions**
- *Why do they differ on duplicates?* Wireshark includes duplicates in the jitter estimate; rtp_scope does not (documented in `stream_stats`).
- *Why does tshark show 0 jitter for payload type 111?* Dynamic payload types have no fixed clock rate without SDP.

**Real captures.** `scripts/crosscheck_pcap.py` does the same comparison per stream on any pcap (pairing streams by addresses, ports and SSRC, and listing streams only one tool found). On three public captures both tools found the same 4 streams with identical packets and loss; the one difference is the mean jitter of an H.263 video stream, which comes from how tshark treats packets with the RTP marker bit set (see below).

**Questions**
- *What did real captures teach you that generated traffic could not?* That RTP detection needs more than the header check (see `analyzer`), and that a link type I had never generated (BSD loopback) shows up in practice.
- *Why does tshark's mean jitter differ on the H.263 video stream?* tshark leaves marker-bit packets out of its mean and max jitter (they still count in the divisor of its mean); rtp_scope averages every packet. I found it by building traces where only the marker bit changes (`scripts/marker_experiment.py`): with no marker bits the two tools agree exactly, with the bit on every packet tshark reports 0. The rule is fitted to tshark's output, not read from its source, so I call it inferred.
- *Why not copy tshark's averaging?* Marker bits mean different things (end of a video frame, start of a talkspurt), and leaving those packets out of the mean makes the number depend on the codec's marker convention. The plain mean over all packets is easier to state and to check.
