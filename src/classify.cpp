// classify.cpp -- RTP / RTCP / non-RTP heuristic (see classify.hpp for rules).
//
// What it does:
//   Looks at the first two payload bytes (version, and the byte that is
//   marker+PT for RTP but packet-type for RTCP) and then defers to parse_rtp()
//   for the structural check.
//
// Data flow: UDP payload --> PacketClass (+ RtpHeader when Rtp).
//
// Design decision:
//   RTCP detection happens *before* the RTP parse because a Sender Report has
//   version 2 too and would otherwise parse as a bogus "RTP packet" whose
//   payload type is 72..76.
#include "classify.hpp"

namespace rtpscope {

PacketClass classify_payload(const uint8_t* data, size_t length, RtpHeader& header) {
    if (length < 8) return PacketClass::NotRtp;
    if ((data[0] >> 6) != 2) return PacketClass::NotRtp;

    const uint8_t second = data[1];
    if (second >= 200 && second <= 204) return PacketClass::Rtcp;
    if (second >= 192 && second <= 207) return PacketClass::NotRtp;
    if (length < 12) return PacketClass::NotRtp;

    switch (parse_rtp(data, length, header)) {
        case RtpParse::Ok: return PacketClass::Rtp;
        case RtpParse::Malformed: return PacketClass::Malformed;
        default: return PacketClass::NotRtp;
    }
}

}  // namespace rtpscope
