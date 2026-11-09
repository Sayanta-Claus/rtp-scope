// test_net_decode.cpp -- Ethernet/VLAN/SLL/IPv4/UDP decoding edge cases.
#include "net_decode.hpp"
#include "pcap_writer.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"

using namespace support;
using rtpscope::DecodeStatus;
using rtpscope::UdpDatagram;

namespace {
DecodeStatus decode(const std::vector<uint8_t>& f, UdpDatagram& u, uint32_t link = 1) {
    return rtpscope::decode_frame(link, f.data(), f.size(), u);
}
}  // namespace

TEST(plain_ethernet_udp) {
    const auto f = rtp_frame(5);
    UdpDatagram u;
    CHECK(decode(f, u) == DecodeStatus::Udp);
    CHECK_EQ(u.src_ip, 0x0a000001u);
    CHECK_EQ(u.dst_ip, 0x0a000002u);
    CHECK_EQ(u.src_port, 5004);
    CHECK_EQ(u.payload_length, 172u);  // 12-byte RTP header + 160 payload
}

TEST(vlan_tagged_frame_is_decoded) {
    FrameSpec fs;
    fs.vlan = true;
    fs.vlan_id = 42;
    UdpDatagram u;
    const auto f = rtp_frame(5, 0, 1, fs);
    CHECK(decode(f, u) == DecodeStatus::Udp);
    CHECK_EQ(u.payload_length, 172u);

    // Through the whole analyzer too.
    rtpscope::Analyzer a;
    std::string err;
    std::istringstream in(make_pcap({{0, f}}), std::ios::binary);
    CHECK(a.analyze(in, err));
    CHECK_EQ(a.counters().rtp, 1u);
}

TEST(stacked_qinq_tags_are_skipped) {
    auto f = rtp_frame(5);
    // Rewrite ethertype (offset 12) as 0x88a8 + tag(2) + inner 0x8100 + tag(2) + 0x0800.
    const std::vector<uint8_t> tags = {0x88, 0xa8, 0x00, 0x0a, 0x81, 0x00, 0x00, 0x14};
    f.erase(f.begin() + 12, f.begin() + 14);
    f.insert(f.begin() + 12, tags.begin(), tags.end());
    f.insert(f.begin() + 12 + static_cast<long>(tags.size()), {0x08, 0x00});
    UdpDatagram u;
    CHECK(decode(f, u) == DecodeStatus::Udp);
}

TEST(ipv4_options_are_honoured_via_ihl) {
    auto f = rtp_frame(5);
    // Make IHL 6 (24-byte header): insert 4 option bytes after the 20-byte header.
    f[14] = 0x46;
    f.insert(f.begin() + 14 + 20, {1, 1, 1, 0});
    const uint16_t total = static_cast<uint16_t>(f.size() - 14);
    f[16] = static_cast<uint8_t>(total >> 8);
    f[17] = static_cast<uint8_t>(total & 0xff);
    UdpDatagram u;
    CHECK(decode(f, u) == DecodeStatus::Udp);
    CHECK_EQ(u.src_port, 5004);
    CHECK_EQ(u.payload_length, 172u);
}

TEST(fragments_are_skipped_and_counted) {
    auto first = rtp_frame(1);
    first[14 + 6] = 0x20;  // More Fragments flag, offset 0
    auto later = rtp_frame(1);
    later[14 + 6] = 0x00;
    later[14 + 7] = 0x10;  // fragment offset 16 (non-zero)
    UdpDatagram u;
    CHECK(decode(first, u) == DecodeStatus::Fragment);
    CHECK(decode(later, u) == DecodeStatus::Fragment);

    rtpscope::Analyzer a;
    std::string err;
    std::istringstream in(make_pcap({{0, first}, {1, later}, {2, rtp_frame(2)}}), std::ios::binary);
    CHECK(a.analyze(in, err));
    CHECK_EQ(a.counters().fragments, 2u);
    CHECK_EQ(a.counters().rtp, 1u);
}

TEST(non_ipv4_and_non_udp_are_not_malformed) {
    auto arp = rtp_frame(1);
    arp[12] = 0x08;
    arp[13] = 0x06;
    auto tcp = rtp_frame(1);
    tcp[14 + 9] = 6;
    UdpDatagram u;
    CHECK(decode(arp, u) == DecodeStatus::NotIpv4);
    CHECK(decode(tcp, u) == DecodeStatus::NotUdp);
}

TEST(truncated_frames_are_malformed_at_every_length) {
    const auto f = rtp_frame(1);
    UdpDatagram u;
    // Cutting the frame anywhere before its end must never crash and, once the
    // IP datagram is incomplete, must report Malformed (or NotIpv4 when the
    // ethertype itself is gone -- never Udp).
    for (size_t len = 0; len < f.size(); ++len) {
        const DecodeStatus s = rtpscope::decode_frame(1, f.data(), len, u);
        CHECK(s != DecodeStatus::Udp);
    }
    CHECK(rtpscope::decode_frame(1, f.data(), f.size(), u) == DecodeStatus::Udp);
}

TEST(ethernet_padding_after_ip_total_length_is_ignored) {
    auto f = rtp_frame(1);
    f.insert(f.end(), 10, 0);  // trailing Ethernet pad bytes
    UdpDatagram u;
    CHECK(decode(f, u) == DecodeStatus::Udp);
    CHECK_EQ(u.payload_length, 172u);
}

TEST(inconsistent_lengths_are_malformed) {
    auto bad_ihl = rtp_frame(1);
    bad_ihl[14] = 0x43;  // IHL 3 < 5
    auto bad_udp = rtp_frame(1);
    bad_udp[14 + 20 + 4] = 0xff;  // UDP length far beyond IP payload
    auto bad_ver = rtp_frame(1);
    bad_ver[14] = 0x65;  // version 6 under an IPv4 ethertype
    UdpDatagram u;
    CHECK(decode(bad_ihl, u) == DecodeStatus::Malformed);
    CHECK(decode(bad_udp, u) == DecodeStatus::Malformed);
    CHECK(decode(bad_ver, u) == DecodeStatus::Malformed);
}

TEST_MAIN()
