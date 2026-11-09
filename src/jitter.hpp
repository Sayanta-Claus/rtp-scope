// jitter.hpp -- interarrival jitter estimator (RFC 3550 section 6.4.1).
//
// What it does:
//   Maintains the running jitter estimate J of one stream. For each packet i,
//   with arrival time R_i and RTP timestamp S_i (both in RTP timestamp units),
//       D(i-1, i) = (R_i - R_{i-1}) - (S_i - S_{i-1})
//       J += (|D| - J) / 16
//   D is how much longer (or shorter) consecutive packets took than they were
//   spaced at the sender: the *variation* of one-way delay. Constant network
//   delay cancels out, so no clock synchronisation between the hosts is needed.
//
// Where it sits in the data flow:
//   (arrival time, RtpHeader.timestamp) --> JitterEstimator --> StreamStats.
//
// Why 1/16: it is a first-order low-pass filter (an exponentially weighted
// moving average). A gain of 1/16 smooths out single spikes yet still tracks a
// real change within a few dozen packets. The RFC picked it as a good
// noise-reduction/responsiveness trade-off.
//
// Design decisions:
//   * The timestamp difference is computed as a *signed 32-bit* value so it is
//     correct across the 2^32 timestamp wrap.
//   * Arrival times are converted from nanoseconds to timestamp units with
//     one multiplication (ns * clock / 1e9) to keep floating-point error small.
#pragma once

#include <cstdint>

namespace rtpscope {

class JitterEstimator {
public:
    // Feed packets in arrival order.
    void update(uint64_t arrival_ns, uint32_t rtp_timestamp, uint32_t clock_rate);

    double jitter_units() const { return jitter_; }
    // Statistics of the running estimate over all updates (used to compare with
    // tools such as Wireshark that report mean/max jitter).
    double mean_units() const { return updates_ == 0 ? 0.0 : sum_ / static_cast<double>(updates_); }
    double max_units() const { return max_; }
    static double to_ms(double units, uint32_t clock_rate) { return clock_rate == 0 ? 0.0 : units * 1000.0 / clock_rate; }
    double jitter_ms(uint32_t clock_rate) const {
        return clock_rate == 0 ? 0.0 : jitter_ * 1000.0 / clock_rate;
    }

private:
    bool has_prev_ = false;
    uint64_t prev_arrival_ns_ = 0;
    uint32_t prev_timestamp_ = 0;
    double jitter_ = 0.0;
    double sum_ = 0.0;      // sum of J after every update
    double max_ = 0.0;
    uint64_t updates_ = 0;
};

}  // namespace rtpscope
