// net_decode.cpp -- Ethernet / Linux-SLL / VLAN / IPv4 / UDP header decoding.
//
// What it does:
//   Walks the headers of one frame with a bounds-checked ByteReader and
//   returns the UDP payload span, or a status explaining why not.
//
// Data flow:
//   frame bytes --> link layer --> ethertype --> IPv4 header --> UDP header
//   --> UdpDatagram{ips, ports, payload pointer+length}.
//
// RFC references: RFC 791 (IPv4 header, IHL, fragment flags/offset),
// RFC 768 (UDP), IEEE 802.1Q (VLAN tag).
//
// Design decisions:
//   * The IP total_length, not the captured length, bounds the payload.
//     Ethernet pads short frames to 60 bytes, so bytes after total_length are
//     padding and must not be treated as RTP payload.
//   * Fragment test: flags/fragment-offset is a 16-bit field; bit 0x2000 is
//     "More Fragments" and the low 13 bits are the offset. Any non-zero value
//     in (0x2000 | 0x1fff) means this is part of a fragmented datagram.
#include "net_decode.hpp"

#include "byte_reader.hpp"

namespace rtpscope {

namespace {

constexpr uint16_t kEthertypeIpv4 = 0x0800;
constexpr uint16_t kEthertypeVlan = 0x8100;
constexpr uint16_t kEthertypeQinQ = 0x88a8;
constexpr uint16_t kEthertypeQinQOld = 0x9100;
constexpr uint8_t kProtoUdp = 17;

bool is_vlan_tag(uint16_t ethertype) {
    return ethertype == kEthertypeVlan || ethertype == kEthertypeQinQ ||
           ethertype == kEthertypeQinQOld;
}

// Reads the link-layer header and leaves the reader at the start of the
// network-layer payload. Returns false if the header is truncated.
bool parse_link(uint32_t link_type, ByteReader& r, uint16_t& ethertype) {
    if (link_type == 0) {
        // BSD loopback: a 4-byte address family in the capturing host's byte
        // order (AF_INET = 2), so accept 2 in either order. Anything else (IPv6
        // has several values) is "not IPv4".
        uint32_t family = 0;
        if (!r.read_u32(Endian::Little, family)) return false;
        ethertype = (family == 2 || family == 0x02000000u) ? kEthertypeIpv4 : 0;
        return true;
    }
    if (link_type == 113) {
        // SLL: packet_type(2) arphrd(2) addr_len(2) addr(8) protocol(2)
        return r.skip(14) && r.read_u16(Endian::Big, ethertype);
    }
    // Ethernet II
    if (!r.skip(12) || !r.read_u16(Endian::Big, ethertype)) return false;
    while (is_vlan_tag(ethertype)) {
        uint16_t tci = 0;
        if (!r.read_u16(Endian::Big, tci)) return false;  // priority/DEI/VLAN id (unused)
        if (!r.read_u16(Endian::Big, ethertype)) return false;
    }
    return true;
}

}  // namespace

DecodeStatus decode_frame(uint32_t link_type, const uint8_t* frame, size_t length,
                          UdpDatagram& out) {
    ByteReader r(frame, length);
    uint16_t ethertype = 0;
    if (!parse_link(link_type, r, ethertype)) return DecodeStatus::Malformed;
    if (ethertype != kEthertypeIpv4) return DecodeStatus::NotIpv4;

    // ---- IPv4 header ----
    uint8_t ver_ihl = 0, tos = 0, ttl = 0, proto = 0;
    uint16_t total_length = 0, ident = 0, flags_frag = 0, checksum = 0;
    uint32_t src = 0, dst = 0;
    if (!r.read_u8(ver_ihl) || !r.read_u8(tos) || !r.read_u16(Endian::Big, total_length) ||
        !r.read_u16(Endian::Big, ident) || !r.read_u16(Endian::Big, flags_frag) ||
        !r.read_u8(ttl) || !r.read_u8(proto) || !r.read_u16(Endian::Big, checksum) ||
        !r.read_u32(Endian::Big, src) || !r.read_u32(Endian::Big, dst)) {
        return DecodeStatus::Malformed;
    }
    if ((ver_ihl >> 4) != 4) return DecodeStatus::Malformed;
    const size_t header_len = static_cast<size_t>(ver_ihl & 0x0f) * 4;  // IHL is in 32-bit words
    if (header_len < 20 || total_length < header_len) return DecodeStatus::Malformed;
    // The whole IP datagram must be present in the capture.
    if (r.remaining() + 20 < total_length) return DecodeStatus::Malformed;
    if (!r.skip(header_len - 20)) return DecodeStatus::Malformed;  // IP options

    if ((flags_frag & 0x3fff) != 0) return DecodeStatus::Fragment;
    if (proto != kProtoUdp) return DecodeStatus::NotUdp;

    // ---- UDP header ----
    const size_t ip_payload_len = total_length - header_len;
    uint16_t sport = 0, dport = 0, udp_len = 0, udp_csum = 0;
    if (ip_payload_len < 8 || !r.read_u16(Endian::Big, sport) ||
        !r.read_u16(Endian::Big, dport) || !r.read_u16(Endian::Big, udp_len) ||
        !r.read_u16(Endian::Big, udp_csum)) {
        return DecodeStatus::Malformed;
    }
    if (udp_len < 8 || udp_len > ip_payload_len) return DecodeStatus::Malformed;

    out.src_ip = src;
    out.dst_ip = dst;
    out.src_port = sport;
    out.dst_port = dport;
    out.payload = r.cursor();
    out.payload_length = static_cast<size_t>(udp_len) - 8;
    return DecodeStatus::Udp;
}

}  // namespace rtpscope
