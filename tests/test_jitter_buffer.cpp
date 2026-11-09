// test_jitter_buffer.cpp -- playout simulation on hand-computable traces.
#include <cmath>
#include <sstream>

#include "jitter_buffer.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"

using namespace rtpscope;

namespace {

bool near(double a, double b) { return std::fabs(a - b) < 1e-9; }

// Packets 20 ms apart in media time whose network transit (ms) is given.
PlayoutTrace trace_from_transits(const std::vector<double>& transit_ms, uint64_t expected = 0) {
    PlayoutTrace t;
    for (size_t i = 0; i < transit_ms.size(); ++i) {
        PlayoutPacket p;
        p.media_s = static_cast<double>(i) * 0.020;
        p.arrival_s = p.media_s + transit_ms[i] / 1000.0;
        t.packets.push_back(p);
    }
    t.expected = expected ? expected : transit_ms.size();
    return t;
}

}  // namespace

TEST(fixed_delay_counts_late_packets_and_latency_by_hand) {
    // transits 0,10,100,20,0 ms with D = 60 ms: only the 100 ms packet is late.
    // buffered time = D - transit = 60, 50, (late), 40, 60 -> avg 52.5, max 60.
    const auto r = simulate_fixed(trace_from_transits({0, 10, 100, 20, 0}), 60);
    CHECK_EQ(r.played, 4u);
    CHECK_EQ(r.late, 1u);
    CHECK_EQ(r.lost, 0u);
    CHECK(near(r.late_or_lost_percent, 20.0));
    CHECK(near(r.avg_latency_ms, 52.5));
    CHECK(near(r.max_latency_ms, 60.0));
}

TEST(larger_delay_removes_lateness_but_adds_latency) {
    const auto trace = trace_from_transits({0, 10, 100, 20, 0});
    const auto small = simulate_fixed(trace, 30);
    const auto large = simulate_fixed(trace, 120);
    CHECK(large.late < small.late);
    CHECK_EQ(large.late, 0u);
    CHECK(large.avg_latency_ms > small.avg_latency_ms);
}

TEST(a_packet_on_the_deadline_is_on_time) {
    const auto r = simulate_fixed(trace_from_transits({0, 60}), 60);
    CHECK_EQ(r.late, 0u);
}

TEST(network_loss_is_counted_separately_from_late) {
    // 5 packets arrived (one late at D=60) out of 8 expected.
    const auto r = simulate_fixed(trace_from_transits({0, 10, 100, 20, 0}, 8), 60);
    CHECK_EQ(r.expected, 8u);
    CHECK_EQ(r.lost, 3u);
    CHECK_EQ(r.late, 1u);
    CHECK(near(r.late_or_lost_percent, 100.0 * 4.0 / 8.0));
}

TEST(adaptive_shrinks_delay_on_a_calm_network) {
    // Transit alternates 4 and 6 ms (deviation 1 ms): little to absorb, so the
    // delay should settle near mean + 4 * deviation = 9 ms instead of 60 ms.
    // (A perfectly constant transit would put the target exactly on the
    // deadline, where floating-point noise decides lateness: unrealistic.)
    std::vector<double> transits;
    for (int i = 0; i < 2000; ++i) transits.push_back(i % 2 ? 6.0 : 4.0);
    const auto trace = trace_from_transits(transits);
    AdaptiveParams p;
    const auto fixed = simulate_fixed(trace, 60);
    const auto adaptive = simulate_adaptive(trace, p);
    CHECK_EQ(adaptive.late, 0u);
    CHECK(adaptive.avg_latency_ms < 0.2 * fixed.avg_latency_ms);
}

TEST(adaptive_grows_delay_when_jitter_is_large) {
    // Transit alternates 0 and 80 ms. A 20 ms fixed buffer is late on half the
    // packets; the adaptive one learns the deviation and stops being late.
    std::vector<double> transits;
    for (int i = 0; i < 4000; ++i) transits.push_back(i % 2 ? 80.0 : 0.0);
    const auto trace = trace_from_transits(transits);
    AdaptiveParams p;
    p.initial_delay_ms = 20;
    const auto fixed = simulate_fixed(trace, 20);
    const auto adaptive = simulate_adaptive(trace, p);
    CHECK(fixed.late_or_lost_percent > 40.0);
    CHECK(adaptive.late_or_lost_percent < 5.0);
}

TEST(talkspurt_boundaries_let_the_delay_jump_instead_of_creep) {
    // Calm network; with markers the delay snaps to the target at each boundary,
    // without them it only creeps down at slew_ms per packet.
    std::vector<double> transits;
    for (int i = 0; i < 1000; ++i) transits.push_back(i % 2 ? 6.0 : 4.0);
    auto no_markers = trace_from_transits(transits);
    auto with_markers = no_markers;
    for (size_t i = 100; i < with_markers.packets.size(); i += 100) with_markers.packets[i].marker = true;
    AdaptiveParams p;
    CHECK(simulate_adaptive(with_markers, p).avg_latency_ms < simulate_adaptive(no_markers, p).avg_latency_ms);
}

TEST(sweep_csv_has_header_fixed_rows_and_adaptive_rows) {
    const auto trace = trace_from_transits(std::vector<double>(300, 3.0));
    AdaptiveParams p;
    const std::string csv = sweep_csv(trace, p);
    CHECK(csv.rfind("strategy,avg_latency_ms,late_or_lost_pct\n", 0) == 0);
    CHECK(csv.find("fixed-0ms,") != std::string::npos);
    CHECK(csv.find("fixed-200ms,") != std::string::npos);
    CHECK(csv.find("adaptive-k4,") != std::string::npos);
    int lines = 0;
    for (char c : csv) lines += c == '\n';
    CHECK_EQ(lines, 1 + 9 + 4);  // header + fixed delays + adaptive k in {1,2,4,8}
}

TEST(make_trace_dedupes_unwraps_timestamps_and_keeps_arrival_order) {
    // RTP timestamp crosses 2^32; one duplicate; one reordered packet.
    const uint32_t t0 = 0xffffff00u;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> frames = {
        {0, support::rtp_frame(1, t0)},
        {20000000, support::rtp_frame(2, t0 + 160)},
        {20000000, support::rtp_frame(2, t0 + 160)},  // duplicate
        {60000000, support::rtp_frame(4, t0 + 480)},
        {70000000, support::rtp_frame(3, t0 + 320)},  // late, out of order
    };
    std::istringstream in(support::make_pcap(frames), std::ios::binary);
    Analyzer a(ClockRates(), /*keep_arrivals=*/true);
    std::string err;
    CHECK(a.analyze(in, err));
    const PlayoutTrace trace = make_trace(*a.streams()[0]);
    CHECK_EQ(trace.packets.size(), 4u);
    CHECK_EQ(trace.expected, 4u);
    CHECK(near(trace.packets[0].media_s, 0.0));
    CHECK(near(trace.packets[1].media_s, 0.020));
    CHECK(near(trace.packets[2].media_s, 0.060));
    CHECK(near(trace.packets[3].media_s, 0.040));  // arrived last, but earlier in media time
    CHECK(near(trace.packets[3].arrival_s, 0.070));
}

TEST_MAIN()
