// test_traffic.cpp -- RNG determinism and generator model properties.
#include <cmath>
#include <sstream>

#include "test_harness.hpp"
#include "trace_gen.hpp"
#include "traffic_model.hpp"

using namespace rtpscope;

TEST(rng_is_deterministic_per_seed_and_stream) {
    Rng a(42), b(42), c(43), d(42, 1);
    bool differs_seed = false, differs_stream = false;
    for (int i = 0; i < 100; ++i) {
        const uint64_t x = a.next_u64();
        CHECK_EQ(x, b.next_u64());
        differs_seed |= x != c.next_u64();
        differs_stream |= x != d.next_u64();
    }
    CHECK(differs_seed);
    CHECK(differs_stream);
}

TEST(uniform_and_normal_have_the_right_moments) {
    Rng r(7);
    double sum = 0, sum_sq = 0;
    const int n = 200000;
    for (int i = 0; i < n; ++i) {
        const double u = r.uniform();
        CHECK(u >= 0.0 && u < 1.0);
        sum += u;
    }
    CHECK(std::fabs(sum / n - 0.5) < 0.005);

    sum = 0;
    for (int i = 0; i < n; ++i) {
        const double z = r.normal();
        sum += z;
        sum_sq += z * z;
    }
    const double mean = sum / n, var = sum_sq / n - mean * mean;
    CHECK(std::fabs(mean) < 0.02);
    CHECK(std::fabs(var - 1.0) < 0.03);
}

TEST(same_config_gives_byte_identical_pcap_and_truth) {
    GenConfig c;
    c.seed = 99;
    c.packets = 500;
    c.loss = 0.1;
    c.reorder = 0.1;
    c.duplicate = 0.1;
    c.jitter_ms = 8;
    std::string pcap[2], truth[2];
    for (int k = 0; k < 2; ++k) {
        std::vector<GeneratedPacket> arr;
        GroundTruth t;
        generate_trace(c, arr, t);
        std::ostringstream os(std::ios::binary);
        write_trace_pcap(c, arr, os);
        pcap[k] = os.str();
        truth[k] = truth_to_text(c, t);
    }
    CHECK(pcap[0] == pcap[1]);
    CHECK(truth[0] == truth[1]);
    c.seed = 100;
    std::vector<GeneratedPacket> arr;
    GroundTruth t;
    generate_trace(c, arr, t);
    CHECK(truth_to_text(c, t) != truth[0]);
}

TEST(clean_network_delivers_everything_in_order) {
    GenConfig c;
    c.packets = 1000;
    c.jitter_ms = 10;  // jitter alone must not reorder (FIFO path)
    std::vector<GeneratedPacket> arr;
    GroundTruth t;
    generate_trace(c, arr, t);
    CHECK_EQ(t.sent, 1000u);
    CHECK_EQ(t.dropped, 0u);
    CHECK_EQ(t.reordered, 0u);
    CHECK_EQ(t.duplicated, 0u);
    CHECK_EQ(arr.size(), 1000u);
    for (size_t i = 1; i < arr.size(); ++i) {
        CHECK(arr[i].index == arr[i - 1].index + 1);
        CHECK(arr[i].arrival_ns >= arr[i - 1].arrival_ns);
    }
}

TEST(duration_sets_packet_count_and_timestamps_follow_the_clock) {
    GenConfig c;
    c.duration_s = 2.0;
    c.interval_ms = 20;
    std::vector<GeneratedPacket> arr;
    GroundTruth t;
    generate_trace(c, arr, t);
    CHECK_EQ(t.sent, 100u);
    CHECK_EQ(arr[1].timestamp - arr[0].timestamp, 160u);  // 20 ms at 8 kHz
    c.payload_type = 111;                                  // dynamic => 48 kHz
    generate_trace(c, arr, t);
    CHECK_EQ(arr[1].timestamp - arr[0].timestamp, 960u);
}

TEST(talkspurts_leave_gaps_and_set_markers) {
    GenConfig c;
    c.packets = 100;
    c.talk_on_ms = 200;   // 10 packets of 20 ms
    c.talk_off_ms = 300;  // 15 slots of silence
    std::vector<GeneratedPacket> arr;
    GroundTruth t;
    generate_trace(c, arr, t);
    int markers = 0;
    for (const auto& p : arr) markers += p.marker;
    CHECK_EQ(markers, 10);  // 100 packets / 10 per spurt
    CHECK(arr[10].marker);
    CHECK_EQ(arr[10].timestamp - arr[9].timestamp, 160u * 16);  // 1 packet step + 15 silent slots
    CHECK_EQ(static_cast<uint16_t>(arr[10].sequence - arr[9].sequence), 1);  // sequence is continuous
}

TEST(wrap_option_really_wraps) {
    GenConfig c;
    c.packets = 100;
    c.start_seq = 65500;
    std::vector<GeneratedPacket> arr;
    GroundTruth t;
    generate_trace(c, arr, t);
    CHECK_EQ(arr.back().sequence, static_cast<uint16_t>(65500 + 99));
    CHECK(arr.back().sequence < arr.front().sequence);
    CHECK_EQ(t.ext_highest_seq, 65500 + 99);
}

TEST_MAIN()
