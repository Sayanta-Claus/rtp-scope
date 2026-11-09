# rtp-scope: module guide

Plain-English tour of every module, with the questions an interviewer is likely to ask.

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

_Later milestones add: seq_tracker, jitter, stream_stats, report, rtp_gen, jitter_buffer._

---

## byte_reader (`src/byte_reader.hpp`)

**How it works.** A non-owning cursor over `[data, data+size)`. `read_u16/u32(Endian, out)` check `remaining()`, then build the value from individual bytes with shifts. On failure they return `false` and change nothing.

**Why not cast to a struct?** A `reinterpret_cast<Header*>(buf)` is undefined behaviour (alignment, strict aliasing), depends on struct padding and host endianness, and has no bounds check.

**Questions an interviewer might ask**
- *Why is network data "big-endian"?* Network byte order is a convention (RFC 1700 era) that every protocol header uses; the pcap file header is the exception: it uses the writer's native order.
- *What happens on a short read?* It returns false, the caller marks the packet malformed and moves on; there is no exception and no UB.

## pcap_reader (`src/pcap_reader.*`)

**How it works.** Reads the 24-byte global header, reads the magic as big-endian and matches one of four values to learn byte order and microsecond/nanosecond timestamps. Then it streams 16-byte record headers + data through one reusable buffer. Link types 1 (Ethernet) and 113 (Linux SLL) are accepted; others are rejected with a message.

**Questions**
- *How do you detect byte order?* The magic `0xa1b2c3d4` is written in the writer's native order, so reading it as big-endian gives either `a1b2c3d4` (file is BE) or `d4c3b2a1` (file is LE).
- *What if the file is cut off?* A truncated last record is flagged (`capture_truncated`) and earlier packets are kept; this is what you get when tcpdump is killed.
- *What if a record claims 4 GB?* Anything over 16 MiB is treated as corrupt before allocating.
- *Why stream rather than load the file?* Memory stays O(one packet), so a multi-GB capture works.

## net_decode (`src/net_decode.*`)

**How it works.** Skips the link header (Ethernet 14 bytes plus any number of 802.1Q/802.1ad tags, or the 16-byte SLL pseudo header), checks the ethertype is IPv4, parses the IPv4 header using IHL*4 as its length, rejects fragments, and parses the UDP header. The IP `total_length` (not the captured length) bounds the payload, so Ethernet padding is ignored.

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
- *What can go wrong?* Random UDP can pass the weak test (false positive); the README lists this as a known limitation.

## analyzer (`src/analyzer.*`)

**How it works.** Loops over records: decode, classify, and increment exactly one counter, so `frames` always equals the sum of every bucket.

**Questions**
- *Why count rather than print warnings?* Counters show up in the report and tests; you can see where every packet went.

## pcap_writer (`src/pcap_writer.*`)

**How it works.** Serialises RTP, wraps it in UDP/IPv4 (with a correct IP checksum) and Ethernet or SLL, optionally with a VLAN tag, and writes pcap files in either byte order and resolution.

**Questions**
- *Why write it yourself?* Test data produced by independent code (a writer) checks the reader; it is also the basis of `rtp_gen`.
- *How is the IPv4 checksum computed?* Ones'-complement sum of the header's 16-bit words (checksum field zero), fold carries, invert.
