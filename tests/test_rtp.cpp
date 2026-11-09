// test_rtp.cpp -- RTP header parsing and the RTP/RTCP/non-RTP classifier.
#include "classify.hpp"
#include "pcap_writer.hpp"
#include "rtp_header.hpp"
#include "test_harness.hpp"

using namespace rtpscope;

namespace {
RtpPacketSpec base_spec() {
    RtpPacketSpec s;
    s.payload_type = 96;
    s.sequence = 0xabcd;
    s.timestamp = 0x01020304;
    s.ssrc = 0xdeadbeef;
    s.marker = true;
    s.payload_bytes = 20;
    return s;
}
}  // namespace

TEST(parses_all_fixed_fields) {
    const auto p = build_rtp_packet(base_spec());
    RtpHeader h;
    CHECK(parse_rtp(p.data(), p.size(), h) == RtpParse::Ok);
    CHECK_EQ(h.version, 2);
    CHECK(h.marker);
    CHECK_EQ(h.payload_type, 96);
    CHECK_EQ(h.sequence, 0xabcd);
    CHECK_EQ(h.timestamp, 0x01020304u);
    CHECK_EQ(h.ssrc, 0xdeadbeefu);
    CHECK_EQ(h.header_length, 12u);
    CHECK_EQ(h.payload_length, 20u);
}

TEST(csrc_extension_and_padding_adjust_payload_length) {
    RtpPacketSpec s = base_spec();
    s.csrcs = {1, 2, 3};
    s.extension = true;
    s.extension_words = 2;
    s.padding_bytes = 4;
    const auto p = build_rtp_packet(s);
    RtpHeader h;
    CHECK(parse_rtp(p.data(), p.size(), h) == RtpParse::Ok);
    CHECK_EQ(h.csrc_count, 3);
    CHECK(h.extension);
    CHECK(h.padding);
    CHECK_EQ(h.header_length, 12u + 12u + 4u + 8u);
    CHECK_EQ(h.padding_length, 4u);
    CHECK_EQ(h.payload_length, 20u);
}

TEST(bad_version_is_rejected) {
    for (uint8_t v : {0, 1, 3}) {
        RtpPacketSpec s = base_spec();
        s.version = v;
        const auto p = build_rtp_packet(s);
        RtpHeader h;
        CHECK(parse_rtp(p.data(), p.size(), h) == RtpParse::BadVersion);
        CHECK(classify_payload(p.data(), p.size(), h) == PacketClass::NotRtp);
    }
}

TEST(truncated_packets_never_overrun) {
    RtpPacketSpec s = base_spec();
    s.csrcs = {1, 2};
    s.extension = true;
    s.extension_words = 3;
    s.padding_bytes = 3;
    const auto p = build_rtp_packet(s);
    RtpHeader h;
    // Every proper prefix is either too short or malformed; none may be Ok
    // before the header+extension are complete. (A prefix that includes the
    // whole header but cuts payload/padding can still be Ok or Malformed.)
    for (size_t len = 0; len < 12 + 8 + 4 + 12; ++len) {
        CHECK(parse_rtp(p.data(), len, h) != RtpParse::Ok);
    }
    CHECK(parse_rtp(p.data(), p.size(), h) == RtpParse::Ok);
    CHECK(parse_rtp(nullptr, 0, h) == RtpParse::TooShort);
}

TEST(lying_padding_count_is_malformed) {
    auto p = build_rtp_packet(base_spec());
    p[0] = static_cast<uint8_t>(p[0] | 0x20);  // set P bit
    p.back() = 0;                              // pad count 0 is invalid
    RtpHeader h;
    CHECK(parse_rtp(p.data(), p.size(), h) == RtpParse::Malformed);
    p.back() = 200;  // more padding than packet
    CHECK(parse_rtp(p.data(), p.size(), h) == RtpParse::Malformed);
}

TEST(csrc_count_larger_than_packet_is_malformed) {
    std::vector<uint8_t> p = build_rtp_packet(base_spec());
    p.resize(14);        // just past the fixed header
    p[0] = 0x80 | 0x0f;  // claims 15 CSRCs
    RtpHeader h;
    CHECK(parse_rtp(p.data(), p.size(), h) == RtpParse::Malformed);
    CHECK(classify_payload(p.data(), p.size(), h) == PacketClass::Malformed);
}

TEST(classifier_separates_rtp_rtcp_and_other_udp) {
    RtpHeader h;
    const auto rtp = build_rtp_packet(base_spec());
    CHECK(classify_payload(rtp.data(), rtp.size(), h) == PacketClass::Rtp);

    // RTCP sender report: V=2, PT=200, minimal 8 bytes.
    const std::vector<uint8_t> sr = {0x80, 200, 0, 1, 0, 0, 0, 1};
    CHECK(classify_payload(sr.data(), sr.size(), h) == PacketClass::Rtcp);
    for (uint8_t t = 200; t <= 204; ++t) {
        const std::vector<uint8_t> r = {0x80, t, 0, 1, 0, 0, 0, 1};
        CHECK(classify_payload(r.data(), r.size(), h) == PacketClass::Rtcp);
    }

    const std::vector<uint8_t> dns = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    CHECK(classify_payload(dns.data(), dns.size(), h) == PacketClass::NotRtp);
    const std::vector<uint8_t> tiny = {0x80, 0x00, 0x00};
    CHECK(classify_payload(tiny.data(), tiny.size(), h) == PacketClass::NotRtp);
}

TEST_MAIN()
