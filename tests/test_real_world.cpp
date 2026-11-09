// test_real_world.cpp -- behaviour learned from real captures: UDP that merely
// looks like RTP must not become a stream, and loopback captures must work.
//
// DNS and NetBIOS packets start with a random transaction id, so one in four
// has "version 2" in its first byte and passes a naive RTP check.
#include <sstream>

#include "report.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"

using namespace support;

namespace {
rtpscope::Analyzer analyze(const std::string& pcap) {
    std::istringstream in(pcap, std::ios::binary);
    rtpscope::Analyzer a;
    std::string err;
    a.analyze(in, err);
    return a;
}
// A UDP payload shaped like an RTP header (version 2) with the given seq/ssrc.
std::vector<uint8_t> rtp_like(uint16_t seq, uint32_t ssrc) {
    RtpPacketSpec s;
    s.sequence = seq;
    s.ssrc = ssrc;
    s.payload_bytes = 20;
    return rtpscope::build_rtp_packet(s);
}
}  // namespace

TEST(well_known_ports_are_never_rtp) {
    FrameSpec dns;
    dns.src_port = 3333;
    dns.dst_port = 53;
    FrameSpec nbns;
    nbns.src_port = 137;
    nbns.dst_port = 137;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> f;
    for (uint16_t i = 0; i < 4; ++i) {  // consecutive "sequence numbers" on purpose
        f.emplace_back(i, rtpscope::build_udp_frame(dns, rtp_like(i, 0)));
        f.emplace_back(i, rtpscope::build_udp_frame(nbns, rtp_like(i, 0)));
    }
    const auto a = analyze(make_pcap(f));
    CHECK_EQ(a.streams().size(), 0u);
    CHECK_EQ(a.counters().rtp, 0u);
    CHECK_EQ(a.counters().non_rtp_udp, 8u);
}

TEST(rtp_like_udp_without_consecutive_sequence_numbers_is_not_a_stream) {
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> f;
    const uint16_t random_ids[] = {0x8f12, 0x8ab4, 0x9021, 0x85ee, 0xa001};
    for (size_t i = 0; i < 5; ++i) f.emplace_back(i, rtpscope::build_udp_frame(FrameSpec(), rtp_like(random_ids[i], 7)));
    const auto a = analyze(make_pcap(f));
    CHECK_EQ(a.streams().size(), 0u);
    CHECK_EQ(a.counters().rtp, 0u);
    CHECK_EQ(a.counters().rtp_unconfirmed, 5u);
    CHECK_EQ(a.counters().non_rtp_udp, 5u);
    CHECK_EQ(a.counters().frames, 5u);
}

TEST(a_real_stream_beside_noise_keeps_all_its_packets) {
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> f;
    f.emplace_back(0, rtpscope::build_udp_frame(FrameSpec(), rtp_like(500, 1)));  // noise from another source
    for (uint16_t s = 10; s < 20; ++s) {
        f.emplace_back(s * 20000000ull, rtp_frame(s, s * 160u, 0xabc));  // the real stream, from its first packet
    }
    const auto a = analyze(make_pcap(f));
    CHECK_EQ(a.streams().size(), 1u);
    CHECK_EQ(a.streams()[0]->packets(), 10u);
    CHECK_EQ(a.streams()[0]->expected(), 10u);
    CHECK_EQ(a.counters().rtp, 10u);
    CHECK_EQ(a.counters().rtp_unconfirmed, 1u);
}

TEST(bsd_loopback_link_type_is_supported) {
    FrameSpec fs;
    fs.loopback = true;
    PcapWriteOptions opt;
    opt.link_type = 0;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> f;
    for (uint16_t s = 1; s <= 5; ++s) f.emplace_back(s * 20000000ull, rtp_frame(s, s * 160u, 9, fs));
    const auto a = analyze(make_pcap(f, opt));
    CHECK_EQ(a.link_type(), 0u);
    CHECK_EQ(a.streams().size(), 1u);
    CHECK_EQ(a.counters().rtp, 5u);

    // An IPv6 family value (not 2) is "not IPv4", not an error.
    auto v6 = f[0].second;
    v6[0] = 30;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> g = {{0, v6}};
    const auto b = analyze(make_pcap(g, opt));
    CHECK_EQ(b.counters().non_ipv4, 1u);
}

TEST(many_distinct_streams_are_bounded_in_memory_and_reported_honestly) {
    // 3000 one-packet "streams" from one source: all unconfirmed, none reported.
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> f;
    for (uint32_t i = 0; i < 3000; ++i) f.emplace_back(i, rtpscope::build_udp_frame(FrameSpec(), rtp_like(1, 1000 + i)));
    const auto a = analyze(make_pcap(f));
    CHECK_EQ(a.streams().size(), 0u);
    CHECK_EQ(a.counters().rtp_unconfirmed, 3000u);
    CHECK_EQ(a.counters().frames, 3000u);
}

TEST_MAIN()
