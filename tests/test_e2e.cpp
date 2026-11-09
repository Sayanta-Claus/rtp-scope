// test_e2e.cpp -- generator -> pcap -> analyzer, compared with the ground truth.
//
// This is the key correctness test: rtp_gen counts exactly what it did to the
// traffic, and the analyzer (which shares no logic with the generator beyond
// the file format) must report the same numbers.
#include <sstream>

#include "analyzer.hpp"
#include "test_harness.hpp"
#include "trace_gen.hpp"

using namespace rtpscope;

namespace {

void check_against_truth(const GenConfig& c) {
    std::vector<GeneratedPacket> arr;
    GroundTruth t;
    generate_trace(c, arr, t);
    std::ostringstream os(std::ios::binary);
    write_trace_pcap(c, arr, os);

    std::istringstream in(os.str(), std::ios::binary);
    Analyzer a;
    std::string err;
    CHECK(a.analyze(in, err));
    CHECK_EQ(a.counters().malformed(), 0u);

    // A stream is only reported once two consecutive sequence numbers have
    // arrived back to back (RFC 3550 A.1 probation). Without such a pair the
    // packets are counted as non-RTP, not as a stream.
    bool confirmed = false;
    for (size_t i = 1; i < arr.size(); ++i) {
        if (arr[i].sequence == static_cast<uint16_t>(arr[i - 1].sequence + 1)) confirmed = true;
    }
    if (!confirmed) {
        CHECK_EQ(a.streams().size(), 0u);
        CHECK_EQ(a.counters().rtp, 0u);
        CHECK_EQ(a.counters().non_rtp_udp, t.received);
        return;
    }
    CHECK_EQ(a.counters().rtp, t.received);
    CHECK_EQ(a.streams().size(), 1u);
    const StreamStats& s = *a.streams()[0];
    CHECK_EQ(s.packets(), t.received);
    CHECK_EQ(s.unique_received(), t.unique_received);
    CHECK_EQ(s.expected(), t.expected);
    CHECK_EQ(s.lost(), t.lost);
    CHECK_EQ(s.duplicates(), t.duplicated);
    CHECK_EQ(s.out_of_order(), t.reordered);
    CHECK_EQ(s.extended_highest(), t.ext_highest_seq);
}

}  // namespace

TEST(known_loss_matches_ground_truth_exactly) {
    GenConfig c;
    c.seed = 5;
    c.packets = 5000;
    c.loss = 0.07;
    check_against_truth(c);
}

TEST(everything_at_once_with_wraparound) {
    GenConfig c;
    c.seed = 11;
    c.packets = 4000;
    c.start_seq = 65000;  // wraps after 536 packets
    c.loss = 0.1;
    c.reorder = 0.08;
    c.duplicate = 0.05;
    c.jitter_ms = 12;
    c.jitter_distribution = JitterDistribution::Normal;
    check_against_truth(c);
}

TEST(all_pcap_flavours_agree) {
    for (int flavour = 0; flavour < 8; ++flavour) {
        GenConfig c;
        c.seed = 21 + static_cast<uint64_t>(flavour);
        c.packets = 800;
        c.loss = 0.05;
        c.reorder = 0.05;
        c.duplicate = 0.05;
        c.start_seq = 65400;
        c.big_endian = flavour & 1;
        c.nanosecond = flavour & 2;
        c.vlan = (flavour & 4) != 0;
        check_against_truth(c);
    }
    GenConfig sll;
    sll.packets = 300;
    sll.loss = 0.1;
    sll.sll = true;
    check_against_truth(sll);
}

TEST(talkspurts_and_odd_parameters) {
    GenConfig c;
    c.seed = 3;
    c.packets = 1500;
    c.talk_on_ms = 400;
    c.talk_off_ms = 600;
    c.loss = 0.2;
    c.reorder = 0.2;
    c.duplicate = 0.2;
    c.payload_type = 111;
    c.start_timestamp = 0xfffff000u;  // RTP timestamp wraps too
    check_against_truth(c);
}

TEST(extreme_cases_do_not_confuse_the_analyzer) {
    GenConfig all_lost;
    all_lost.packets = 50;
    all_lost.loss = 1.0;
    check_against_truth(all_lost);

    GenConfig one;
    one.packets = 1;
    check_against_truth(one);

    GenConfig heavy;
    heavy.seed = 8;
    heavy.packets = 3000;
    heavy.loss = 0.5;
    heavy.reorder = 0.5;
    heavy.duplicate = 0.5;
    check_against_truth(heavy);
}

TEST(sweep_of_seeds) {
    for (uint64_t seed = 100; seed < 140; ++seed) {
        GenConfig c;
        c.seed = seed;
        c.packets = 600;
        c.start_seq = static_cast<uint16_t>(seed * 977);  // arbitrary start, often near a wrap
        c.loss = 0.02 * static_cast<double>(seed % 10);
        c.reorder = 0.03 * static_cast<double>(seed % 7);
        c.duplicate = 0.04 * static_cast<double>(seed % 5);
        c.jitter_ms = static_cast<double>(seed % 13);
        check_against_truth(c);
    }
}

TEST_MAIN()
