// pcap_writer.cpp -- serialise RTP/UDP/IPv4/Ethernet frames and pcap files.
//
// What it does:
//   Appends big-endian fields to a byte vector for the frame, and writes pcap
//   headers in the byte order the caller picked.
//
// Data flow: specs --> std::vector<uint8_t> frame --> PcapWriter --> ostream.
//
// Notes on the formats written:
//   * RTP: RFC 3550 5.1 (see rtp_header.hpp). Padding sets the P bit and the
//     last byte holds the pad count. Extension sets the X bit.
//   * IPv4 header checksum (RFC 791): ones'-complement sum of the header's
//     16-bit words with the checksum field zeroed, then inverted.
//   * pcap record: ts_sec, ts_frac(us or ns), incl_len, orig_len.
#include "pcap_writer.hpp"

#include <array>

namespace rtpscope {

namespace {

void put8(std::vector<uint8_t>& v, uint8_t x) { v.push_back(x); }
void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xff));
}
void put32(std::vector<uint8_t>& v, uint32_t x) {
    put16(v, static_cast<uint16_t>(x >> 16));
    put16(v, static_cast<uint16_t>(x & 0xffff));
}

uint16_t ipv4_checksum(const uint8_t* header, size_t length) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < length; i += 2) sum += static_cast<uint32_t>((header[i] << 8) | header[i + 1]);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);  // fold carries back in
    return static_cast<uint16_t>(~sum & 0xffff);
}

}  // namespace

std::vector<uint8_t> build_rtp_packet(const RtpPacketSpec& s) {
    std::vector<uint8_t> p;
    const size_t cc = s.csrcs.size() > 15 ? 15 : s.csrcs.size();
    const bool has_pad = s.padding_bytes > 0;
    put8(p, static_cast<uint8_t>((s.version << 6) | (has_pad ? 0x20 : 0) | (s.extension ? 0x10 : 0) | cc));
    put8(p, static_cast<uint8_t>((s.marker ? 0x80 : 0) | (s.payload_type & 0x7f)));
    put16(p, s.sequence);
    put32(p, s.timestamp);
    put32(p, s.ssrc);
    for (size_t i = 0; i < cc; ++i) put32(p, s.csrcs[i]);
    if (s.extension) {
        put16(p, 0xbede);  // arbitrary profile id
        put16(p, s.extension_words);
        for (size_t i = 0; i < static_cast<size_t>(s.extension_words) * 4; ++i) put8(p, 0);
    }
    for (size_t i = 0; i < s.payload_bytes; ++i) put8(p, static_cast<uint8_t>(i & 0xff));
    if (has_pad) {
        for (size_t i = 1; i < s.padding_bytes; ++i) put8(p, 0);
        put8(p, static_cast<uint8_t>(s.padding_bytes));
    }
    return p;
}

std::vector<uint8_t> build_udp_frame(const FrameSpec& s, const std::vector<uint8_t>& udp_payload) {
    std::vector<uint8_t> f;
    if (s.sll) {
        put16(f, 0);       // packet type: unicast to us
        put16(f, 1);       // ARPHRD_ETHER
        put16(f, 6);       // address length
        for (int i = 0; i < 8; ++i) put8(f, static_cast<uint8_t>(i == 0 ? 0x02 : 0));
        put16(f, 0x0800);  // protocol = IPv4
    } else {
        for (int i = 0; i < 6; ++i) put8(f, static_cast<uint8_t>(i == 0 ? 0x02 : 0x11));  // dst MAC
        for (int i = 0; i < 6; ++i) put8(f, static_cast<uint8_t>(i == 0 ? 0x02 : 0x22));  // src MAC
        if (s.vlan) {
            put16(f, 0x8100);
            put16(f, static_cast<uint16_t>(s.vlan_id & 0x0fff));  // PCP=0, DEI=0
        }
        put16(f, 0x0800);
    }

    const size_t ip_start = f.size();
    const uint16_t udp_len = static_cast<uint16_t>(8 + udp_payload.size());
    const uint16_t total_len = static_cast<uint16_t>(20 + udp_len);
    put8(f, 0x45);  // version 4, IHL 5
    put8(f, 0);     // DSCP/ECN
    put16(f, total_len);
    put16(f, 0);       // identification
    put16(f, 0x4000);  // flags: Don't Fragment
    put8(f, 64);       // TTL
    put8(f, 17);       // UDP
    put16(f, 0);       // checksum placeholder
    put32(f, s.src_ip);
    put32(f, s.dst_ip);
    const uint16_t csum = ipv4_checksum(f.data() + ip_start, 20);
    f[ip_start + 10] = static_cast<uint8_t>(csum >> 8);
    f[ip_start + 11] = static_cast<uint8_t>(csum & 0xff);

    put16(f, s.src_port);
    put16(f, s.dst_port);
    put16(f, udp_len);
    put16(f, 0);  // UDP checksum omitted (legal for IPv4)
    f.insert(f.end(), udp_payload.begin(), udp_payload.end());
    return f;
}

void PcapWriter::put_u16(uint16_t v) {
    const char b[2] = {static_cast<char>(opt_.big_endian ? v >> 8 : v & 0xff),
                       static_cast<char>(opt_.big_endian ? v & 0xff : v >> 8)};
    out_.write(b, 2);
}

void PcapWriter::put_u32(uint32_t v) {
    std::array<char, 4> b{};
    for (int i = 0; i < 4; ++i) {
        const int shift = opt_.big_endian ? 24 - 8 * i : 8 * i;
        b[static_cast<size_t>(i)] = static_cast<char>((v >> shift) & 0xff);
    }
    out_.write(b.data(), 4);
}

void PcapWriter::write_header() {
    // The magic is written in the file's own byte order -- that is exactly how
    // a reader later discovers the order.
    put_u32(opt_.nanosecond ? 0xa1b23c4du : 0xa1b2c3d4u);
    put_u16(2);
    put_u16(4);
    put_u32(0);  // thiszone
    put_u32(0);  // sigfigs
    put_u32(opt_.snaplen);
    put_u32(opt_.link_type);
}

void PcapWriter::write_record(uint64_t timestamp_ns, const std::vector<uint8_t>& frame) {
    const uint64_t sec = timestamp_ns / 1000000000ull;
    const uint64_t frac_ns = timestamp_ns % 1000000000ull;
    put_u32(static_cast<uint32_t>(sec));
    put_u32(static_cast<uint32_t>(opt_.nanosecond ? frac_ns : frac_ns / 1000ull));
    put_u32(static_cast<uint32_t>(frame.size()));
    put_u32(static_cast<uint32_t>(frame.size()));
    out_.write(reinterpret_cast<const char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
}

}  // namespace rtpscope
