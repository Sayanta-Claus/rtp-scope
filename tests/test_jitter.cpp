// test_jitter.cpp -- RFC 3550 6.4.1 jitter on hand-computed examples.
#include <cmath>

#include "jitter.hpp"
#include "test_harness.hpp"

using rtpscope::JitterEstimator;

namespace {
bool near(double a, double b) { return std::fabs(a - b) < 1e-9; }
constexpr uint64_t kMs = 1000000;  // nanoseconds per millisecond
}  // namespace

// 8 kHz audio, 20 ms packets => RTP timestamp step of 160.
// Arrival times (ms): 0, 20, 45, 60   RTP timestamps: 0, 160, 320, 480
//   packet 2: arrival delta 160 units, ts delta 160 -> D = 0     -> J = 0
//   packet 3: arrival delta 25 ms = 200 units      -> D = +40   -> J = 0 + (40 - 0)/16 = 2.5
//   packet 4: arrival delta 15 ms = 120 units      -> D = -40   -> J = 2.5 + (40 - 2.5)/16 = 4.84375
TEST(hand_computed_example) {
    JitterEstimator j;
    j.update(0 * kMs, 0, 8000);
    CHECK(near(j.jitter_units(), 0.0));
    j.update(20 * kMs, 160, 8000);
    CHECK(near(j.jitter_units(), 0.0));
    j.update(45 * kMs, 320, 8000);
    CHECK(near(j.jitter_units(), 2.5));
    j.update(60 * kMs, 480, 8000);
    CHECK(near(j.jitter_units(), 4.84375));
    CHECK(near(j.jitter_ms(8000), 4.84375 / 8.0));  // 8 units per ms
}

TEST(constant_delay_gives_zero_jitter) {
    JitterEstimator j;
    for (uint32_t i = 0; i < 100; ++i) j.update(1000 * kMs + i * 20 * kMs, 5000 + i * 160, 8000);
    CHECK(near(j.jitter_units(), 0.0));
}

TEST(timestamp_wrap_does_not_create_a_spike) {
    JitterEstimator j;
    uint32_t ts = 0xffffff00u;
    for (uint32_t i = 0; i < 10; ++i, ts += 160) j.update(i * 20 * kMs, ts, 8000);
    CHECK(near(j.jitter_units(), 0.0));  // ts crosses 2^32 between packets 1 and 2
}

TEST(alternating_delay_converges_towards_its_amplitude) {
    // Every second packet is 10 ms late => |D| = 80 units on every step.
    JitterEstimator j;
    for (uint32_t i = 0; i < 400; ++i) {
        const uint64_t extra = (i % 2) ? 10 * kMs : 0;
        j.update(i * 20 * kMs + extra, i * 160, 8000);
    }
    CHECK(std::fabs(j.jitter_units() - 80.0) < 1.0);
}

TEST_MAIN()
