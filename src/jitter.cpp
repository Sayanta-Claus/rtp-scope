// jitter.cpp -- RFC 3550 6.4.1 interarrival jitter.
//
// What it does: one update per packet, see jitter.hpp for the formula.
// Data flow: (arrival_ns, rtp_timestamp, clock) --> jitter_ (double, RTP units).
#include "jitter.hpp"

#include <algorithm>
#include <cmath>

namespace rtpscope {

void JitterEstimator::update(uint64_t arrival_ns, uint32_t rtp_timestamp, uint32_t clock_rate) {
    if (has_prev_) {
        // Arrival spacing in RTP timestamp units. Signed, because a reordered
        // packet can arrive "before" the previous one.
        const double arrival_delta =
            static_cast<double>(static_cast<int64_t>(arrival_ns - prev_arrival_ns_)) *
            static_cast<double>(clock_rate) / 1e9;
        // Unsigned subtraction wraps correctly mod 2^32; reinterpreting as
        // int32 gives the signed distance (valid while packets are < 2^31 apart).
        const double timestamp_delta =
            static_cast<double>(static_cast<int32_t>(rtp_timestamp - prev_timestamp_));
        const double d = arrival_delta - timestamp_delta;
        jitter_ += (std::fabs(d) - jitter_) / 16.0;
        sum_ += jitter_;
        max_ = std::max(max_, jitter_);
        ++updates_;
    }
    has_prev_ = true;
    prev_arrival_ns_ = arrival_ns;
    prev_timestamp_ = rtp_timestamp;
}

}  // namespace rtpscope
