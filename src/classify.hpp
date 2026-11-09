// classify.hpp -- decide whether a UDP payload is RTP, RTCP or something else.
//
// What it does:
//   RTP has no magic number and runs on arbitrary UDP ports, so we guess from
//   the bytes. This is the same kind of heuristic Wireshark uses when it is
//   not told which ports carry RTP.
//
// Where it sits in the data flow:
//   UdpDatagram.payload --> classify_payload() --> {Rtp, Rtcp, NotRtp, Malformed}
//   Rtp results also carry the parsed RtpHeader.
//
// The rules (in order):
//   1. fewer than 8 bytes, or version != 2        -> NotRtp
//   2. second byte 200..204 (SR/RR/SDES/BYE/APP)  -> Rtcp (counted, not parsed)
//   3. second byte 192..207 otherwise             -> NotRtp  (RTCP range: see below)
//   4. fewer than 12 bytes                        -> NotRtp
//   5. fixed header parses but CSRC/extension/padding do not fit -> Malformed
//   6. otherwise                                  -> Rtp
//
// Why bytes 192..207: RTCP packet types occupy 192..223 in the byte that RTP
// uses for marker+payload-type. With the marker bit set, RTP payload types
// 64..79 would collide with that range (RFC 5761 section 4), so we treat that
// range as RTCP/non-RTP rather than mis-reading RTCP as an RTP stream.
//
// Design decision:
//   Version 2 plus a length-consistent header is deliberately a *weak* test:
//   random UDP could pass. The limitation is documented in the README; we
//   prefer false positives (visible in the stream table) over silently
//   dropping real streams.
#pragma once

#include <cstddef>
#include <cstdint>

#include "rtp_header.hpp"

namespace rtpscope {

enum class PacketClass { Rtp, Rtcp, NotRtp, Malformed };

PacketClass classify_payload(const uint8_t* data, size_t length, RtpHeader& header);

}  // namespace rtpscope
