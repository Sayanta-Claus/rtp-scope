// rtp_header.cpp -- byte-by-byte RTP header decoder.
//
// What it does:
//   Extracts V/P/X/CC/M/PT from the first two bytes with shifts and masks,
//   then the 16-bit sequence number and 32-bit timestamp and SSRC in network
//   (big-endian) order, then skips CSRCs and the extension, and strips padding.
//
// Data flow: UDP payload bytes --> RtpHeader (with header_length/payload_length).
//
// RFC 3550 section 5.1:
//   * byte0 = VV P X CCCC  -> version = b0>>6, P = (b0>>5)&1, X = (b0>>4)&1,
//     CC = b0 & 0x0f.
//   * byte1 = M PPPPPPP    -> marker = b1>>7, payload type = b1 & 0x7f.
//   * Extension (X=1): after the CSRCs come 16 bits "defined by profile" and a
//     16-bit length counting *32-bit words of extension data*, excluding these
//     4 bytes. So the extension occupies 4 + 4*length bytes.
//   * Padding (P=1): the final octet of the packet says how many octets of
//     padding (including itself) to ignore; it must be at least 1.
#include "rtp_header.hpp"

#include "byte_reader.hpp"

namespace rtpscope {

RtpParse parse_rtp(const uint8_t* data, size_t length, RtpHeader& out) {
    ByteReader r(data, length);
    uint8_t b0 = 0, b1 = 0;
    uint16_t seq = 0;
    uint32_t ts = 0, ssrc = 0;
    if (!r.read_u8(b0) || !r.read_u8(b1) || !r.read_u16(Endian::Big, seq) ||
        !r.read_u32(Endian::Big, ts) || !r.read_u32(Endian::Big, ssrc)) {
        return RtpParse::TooShort;
    }

    RtpHeader h;
    h.version = static_cast<uint8_t>(b0 >> 6);
    if (h.version != 2) return RtpParse::BadVersion;
    h.padding = ((b0 >> 5) & 1) != 0;
    h.extension = ((b0 >> 4) & 1) != 0;
    h.csrc_count = static_cast<uint8_t>(b0 & 0x0f);
    h.marker = (b1 >> 7) != 0;
    h.payload_type = static_cast<uint8_t>(b1 & 0x7f);
    h.sequence = seq;
    h.timestamp = ts;
    h.ssrc = ssrc;

    // Each CSRC is one 32-bit identifier.
    if (!r.skip(static_cast<size_t>(h.csrc_count) * 4)) return RtpParse::Malformed;

    if (h.extension) {
        uint16_t profile = 0, words = 0;
        if (!r.read_u16(Endian::Big, profile) || !r.read_u16(Endian::Big, words)) {
            return RtpParse::Malformed;
        }
        if (!r.skip(static_cast<size_t>(words) * 4)) return RtpParse::Malformed;
    }
    h.header_length = r.position();

    size_t pad = 0;
    if (h.padding) {
        // The pad count lives in the very last byte of the packet.
        if (length <= h.header_length) return RtpParse::Malformed;
        pad = data[length - 1];
        if (pad == 0 || pad > length - h.header_length) return RtpParse::Malformed;
    }
    h.padding_length = pad;
    h.payload_length = length - h.header_length - pad;
    out = h;
    return RtpParse::Ok;
}

}  // namespace rtpscope
