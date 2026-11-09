// pcap_writer.hpp -- build Ethernet/IPv4/UDP/RTP frames and write .pcap files.
//
// What it does:
//   The inverse of the parsing modules: it serialises an RTP packet, wraps it
//   in UDP + IPv4 (+ optional 802.1Q tag, or a Linux-SLL header) and writes it
//   into a classic pcap file in either byte order and timestamp resolution.
//
// Where it sits in the data flow:
//   rtp_gen / unit tests --> build_rtp_packet --> build_udp_frame
//   --> PcapWriter --> .pcap file --> (the analyzer reads it back).
//   Writing with an independent code path is what lets the tests check the
//   reader against known answers.
//
// Design decision:
//   Fields are serialised with explicit shifts (put_u16/put_u32) just like the
//   reader, and the IPv4 header checksum is computed properly so third-party
//   tools (Wireshark/tshark) accept the generated files. The UDP checksum is
//   left at 0, which RFC 768 allows for IPv4 ("no checksum").
#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <vector>

namespace rtpscope {

struct RtpPacketSpec {
    uint8_t version = 2;
    bool marker = false;
    uint8_t payload_type = 0;
    uint16_t sequence = 0;
    uint32_t timestamp = 0;
    uint32_t ssrc = 0;
    std::vector<uint32_t> csrcs;   // CC is set from the list size (max 15)
    bool extension = false;        // adds a header extension...
    uint16_t extension_words = 0;  // ...with this many 32-bit data words
    size_t payload_bytes = 160;
    size_t padding_bytes = 0;      // 0 = no padding bit
};

std::vector<uint8_t> build_rtp_packet(const RtpPacketSpec& spec);

struct FrameSpec {
    uint32_t src_ip = 0x0a000001;  // 10.0.0.1
    uint32_t dst_ip = 0x0a000002;  // 10.0.0.2
    uint16_t src_port = 5004;
    uint16_t dst_port = 5004;
    bool vlan = false;             // insert an 802.1Q tag
    uint16_t vlan_id = 100;
    bool sll = false;              // Linux cooked header instead of Ethernet
};

std::vector<uint8_t> build_udp_frame(const FrameSpec& spec, const std::vector<uint8_t>& udp_payload);

struct PcapWriteOptions {
    bool big_endian = false;
    bool nanosecond = false;
    uint32_t link_type = 1;
    uint32_t snaplen = 65535;
};

class PcapWriter {
public:
    PcapWriter(std::ostream& out, const PcapWriteOptions& options) : out_(out), opt_(options) {}
    void write_header();
    void write_record(uint64_t timestamp_ns, const std::vector<uint8_t>& frame);

private:
    void put_u16(uint16_t v);
    void put_u32(uint32_t v);
    std::ostream& out_;
    PcapWriteOptions opt_;
};

}  // namespace rtpscope
