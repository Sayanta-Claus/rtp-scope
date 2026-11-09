// rtp_header.hpp -- RTP fixed header parsing (RFC 3550 section 5.1).
//
// What it does:
//   Decodes the 12-byte RTP fixed header, the optional CSRC list and the
//   optional header extension, and works out how long the media payload is
//   after removing any padding.
//
// Where it sits in the data flow:
//   UdpDatagram.payload --> parse_rtp() --> RtpHeader --> stream statistics.
//
// Wire layout (RFC 3550 5.1), most significant bit first:
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
//   |                           timestamp                           |
//   |           synchronization source (SSRC) identifier            |
//   |            contributing source (CSRC) identifiers  (CC x 4)   |
//   |  optional extension: profile(16) length-in-words(16) data...  |
//
// Design decision:
//   The parser validates that every variable-length part (CSRCs, extension,
//   padding) actually fits in the datagram and reports Malformed otherwise.
//   Padding is trusted only if the last byte is a sane count; a lying pad
//   count would otherwise yield a negative payload length.
#pragma once

#include <cstddef>
#include <cstdint>

namespace rtpscope {

struct RtpHeader {
    uint8_t version = 0;
    bool padding = false;
    bool extension = false;
    uint8_t csrc_count = 0;
    bool marker = false;
    uint8_t payload_type = 0;
    uint16_t sequence = 0;
    uint32_t timestamp = 0;
    uint32_t ssrc = 0;
    size_t header_length = 0;   // fixed header + CSRCs + extension
    size_t padding_length = 0;  // bytes of padding at the end of the packet
    size_t payload_length = 0;  // media bytes after header and padding
};

enum class RtpParse {
    Ok,
    TooShort,    // fewer than 12 bytes: cannot even hold a fixed header
    BadVersion,  // version field is not 2
    Malformed,   // CSRC list, extension or padding does not fit the packet
};

RtpParse parse_rtp(const uint8_t* data, size_t length, RtpHeader& out);

}  // namespace rtpscope
