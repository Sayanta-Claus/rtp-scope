// test_stats.cpp -- end-to-end stream statistics through the Analyzer, using
// small synthetic pcaps with known answers.
#include <cmath>
#include <sstream>

#include "test_harness.hpp"
#include "test_support.hpp"

using namespace support;

namespace {

using Frames = std::vector<std::pair<uint64_t, std::vector<uint8_t>>>;
constexpr uint64_t kMs = 1000000;

rtpscope::Analyzer analyze(const Frames& frames, const rtpscope::ClockRates& rates = rtpscope::ClockRates()) {
    std::istringstream in(make_pcap(frames), std::ios::binary);
    rtpscope::Analyzer a(rates);
    std::string err;
    a.analyze(in, err);
    return a;
}

}  // namespace

TEST(loss_duplicates_reordering_and_wrap_in_one_stream) {
    Frames f;
    uint64_t t = 0;
    // Sequence 65533 .. 3, 20 ms apart. Dropped: 65535. Duplicated: 0.
    // Reordered: 2 arrives after 3.
    const std::vector<uint16_t> arrival_order = {65533, 65534, 0, 0, 1, 3, 2};
    uint32_t ts = 1000;
    for (uint16_t s : arrival_order) {
        f.emplace_back(t, rtp_frame(s, ts));
        t += 20 * kMs;
        ts += 160;
    }
    const auto a = analyze(f);
    CHECK_EQ(a.streams().size(), 1u);
    const auto& s = *a.streams()[0];
    CHECK_EQ(s.packets(), 7u);
    CHECK_EQ(s.extended_highest(), 65536 + 3);
    CHECK_EQ(s.expected(), 7u);        // 65533 .. 65539
    CHECK_EQ(s.unique_received(), 6u);
    CHECK_EQ(s.lost(), 1u);
    CHECK_EQ(s.duplicates(), 1u);
    CHECK_EQ(s.out_of_order(), 1u);
    CHECK(std::fabs(s.loss_percent() - 100.0 / 7.0) < 1e-9);
}

TEST(negative_loss_is_clamped_but_visible_in_signed_value) {
    Frames f;
    for (uint16_t s : {1, 2, 3, 3, 3, 3}) f.emplace_back(f.size() * 20 * kMs, rtp_frame(s, s * 160u));
    const auto a = analyze(f);
    const auto& s = *a.streams()[0];
    CHECK_EQ(s.lost(), 0u);
    CHECK_EQ(s.lost_signed(), -3);  // expected 3 - received 6 (RFC 3550 style)
    CHECK_EQ(s.duplicates(), 3u);
}

TEST(bitrate_and_duration) {
    Frames f;
    for (uint16_t i = 0; i <= 100; ++i) f.emplace_back(i * 20 * kMs, rtp_frame(i, i * 160u));
    const auto a = analyze(f);
    const auto& s = *a.streams()[0];
    CHECK(std::fabs(s.duration_s() - 2.0) < 1e-9);
    // 101 packets x 172 bytes (12 header + 160 payload) x 8 bits / 2 s
    CHECK(std::fabs(s.bitrate_kbps() - 101.0 * 172.0 * 8.0 / 2.0 / 1000.0) < 1e-9);
}

TEST(streams_are_separated_by_ssrc_and_by_ports) {
    FrameSpec other_port;
    other_port.src_port = 6000;
    Frames f;
    f.emplace_back(0, rtp_frame(1, 0, 0xaaaa));
    f.emplace_back(1, rtp_frame(1, 0, 0xbbbb));              // same ports, other SSRC
    f.emplace_back(2, rtp_frame(1, 0, 0xaaaa, other_port));  // same SSRC, other source port
    f.emplace_back(3, rtp_frame(2, 160, 0xaaaa));
    const auto a = analyze(f);
    CHECK_EQ(a.streams().size(), 3u);
    CHECK_EQ(a.streams()[0]->packets(), 2u);  // first-seen order
    CHECK_EQ(a.streams()[0]->key().ssrc, 0xaaaau);
}

TEST(clock_rate_defaults_and_override) {
    auto frame_with_pt = [](uint8_t pt) {
        RtpPacketSpec rs;
        rs.payload_type = pt;
        rs.ssrc = pt;
        return rtpscope::build_udp_frame(FrameSpec(), rtpscope::build_rtp_packet(rs));
    };
    Frames f = {{0, frame_with_pt(0)}, {1, frame_with_pt(8)}, {2, frame_with_pt(9)},
                {3, frame_with_pt(111)}, {4, frame_with_pt(96)}, {5, frame_with_pt(34)}};
    rtpscope::ClockRates rates;
    std::string err;
    CHECK(rates.add_override("96=90000", err));
    const auto a = analyze(f, rates);
    CHECK_EQ(a.streams().size(), 6u);
    CHECK_EQ(a.streams()[0]->clock_rate(), 8000u);   // PCMU
    CHECK_EQ(a.streams()[1]->clock_rate(), 8000u);   // PCMA
    CHECK_EQ(a.streams()[2]->clock_rate(), 8000u);   // G722 (timestamp rate)
    CHECK_EQ(a.streams()[3]->clock_rate(), 48000u);  // dynamic, e.g. Opus
    CHECK_EQ(a.streams()[4]->clock_rate(), 90000u);  // overridden
    CHECK_EQ(a.streams()[5]->clock_rate(), 90000u);  // H263 video
}

TEST(clock_rate_override_rejects_garbage) {
    rtpscope::ClockRates rates;
    std::string err;
    CHECK(!rates.add_override("96", err));
    CHECK(!rates.add_override("200=8000", err));
    CHECK(!rates.add_override("96=0", err));
    CHECK(!rates.add_override("x=y", err));
    CHECK(!rates.add_override("96=8000abc", err));
}

TEST(jitter_in_ms_uses_the_stream_clock_rate) {
    // 8 kHz: 20 ms packets, the third arrives 5 ms late -> J = 2.5 units = 0.3125 ms
    Frames f = {{0, rtp_frame(1, 0)}, {20 * kMs, rtp_frame(2, 160)}, {45 * kMs, rtp_frame(3, 320)}};
    const auto a = analyze(f);
    const auto& s = *a.streams()[0];
    CHECK(std::fabs(s.jitter_units() - 2.5) < 1e-9);
    CHECK(std::fabs(s.jitter_ms() - 0.3125) < 1e-9);
}

TEST(every_frame_lands_in_exactly_one_bucket) {
    Frames f;
    f.emplace_back(0, rtp_frame(1));                                  // RTP
    auto rtcp = rtpscope::build_udp_frame(FrameSpec(), {0x80, 200, 0, 1, 0, 0, 0, 1});
    f.emplace_back(1, rtcp);                                          // RTCP
    f.emplace_back(2, rtpscope::build_udp_frame(FrameSpec(), {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}));  // other UDP
    auto arp = rtp_frame(1);
    arp[12] = 0x08;
    arp[13] = 0x06;
    f.emplace_back(3, arp);                                           // not IPv4
    f.emplace_back(4, std::vector<uint8_t>(5, 0));                    // malformed
    const auto a = analyze(f);
    const auto& c = a.counters();
    CHECK_EQ(c.frames, 5u);
    CHECK_EQ(c.rtp, 1u);
    CHECK_EQ(c.rtcp, 1u);
    CHECK_EQ(c.non_rtp_udp, 1u);
    CHECK_EQ(c.non_ipv4, 1u);
    CHECK_EQ(c.malformed(), 1u);
    CHECK_EQ(c.rtp + c.rtcp + c.non_rtp_udp + c.non_ipv4 + c.non_udp + c.fragments + c.malformed(), c.frames);
}

TEST(vlan_tagged_and_sll_frames_feed_the_same_stream_logic) {
    FrameSpec vlan;
    vlan.vlan = true;
    Frames f = {{0, rtp_frame(1, 0, 7, vlan)}, {20 * kMs, rtp_frame(2, 160, 7, vlan)}, {40 * kMs, rtp_frame(4, 480, 7, vlan)}};
    const auto a = analyze(f);
    CHECK_EQ(a.streams().size(), 1u);
    CHECK_EQ(a.streams()[0]->lost(), 1u);
}

TEST_MAIN()
