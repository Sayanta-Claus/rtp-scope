// net_decode.hpp -- peel Ethernet/SLL -> IPv4 -> UDP off a captured frame.
//
// What it does:
//   Given the raw bytes of one captured frame and the capture's link type,
//   finds the UDP datagram inside (if there is one) and reports its addresses,
//   ports and payload span.
//
// Where it sits in the data flow:
//   PcapRecord.data --> decode_frame() --> UdpDatagram --> RTP classifier.
//
// Key concepts:
//   * Ethernet II: dst(6) src(6) ethertype(2). 802.1Q (0x8100) and 802.1ad
//     (0x88a8, 0x9100) insert a 4-byte tag: TCI(2) + the real ethertype(2).
//     Tags can stack (QinQ), so we loop.
//   * Linux cooked v1 (SLL, link type 113): a fixed 16-byte pseudo header whose
//     last two bytes are the ethertype.
//   * IPv4: the header length is IHL*4 (IHL is the low nibble, in 32-bit
//     words) and may exceed 20 because of options -- never assume 20.
//   * Fragments: only the first fragment carries the UDP header and later
//     fragments carry no ports, so we skip any fragment and count it.
//
// Design decision:
//   decode_frame() returns a status enum instead of throwing, so the caller can
//   keep separate counters for "not IPv4", "not UDP", "fragment" and "malformed".
//   A frame whose IP total length exceeds the captured bytes (snaplen cut it
//   short) is "malformed": the RTP length checks would otherwise be guesses.
#pragma once

#include <cstddef>
#include <cstdint>

namespace rtpscope {

struct UdpDatagram {
    uint32_t src_ip = 0;  // host-order value of the 4 address bytes (a.b.c.d -> a<<24|...)
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    const uint8_t* payload = nullptr;
    size_t payload_length = 0;
};

enum class DecodeStatus {
    Udp,        // a full, unfragmented UDP datagram was found
    NotIpv4,    // ARP, IPv6, ... (we only handle IPv4)
    NotUdp,     // IPv4 but TCP/ICMP/...
    Fragment,   // IPv4 fragment: skipped (counted by the caller)
    Malformed,  // truncated or internally inconsistent headers
};

DecodeStatus decode_frame(uint32_t link_type, const uint8_t* frame, size_t length,
                          UdpDatagram& out);

}  // namespace rtpscope
