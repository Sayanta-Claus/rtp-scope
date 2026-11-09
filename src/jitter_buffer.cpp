// jitter_buffer.cpp -- fixed and adaptive playout simulation.
//
// What it does: walks the packets of a PlayoutTrace in arrival order and
// decides, for each, whether it makes its playout deadline p_i = m_i + D.
//
// Data flow: PlayoutTrace --> (D per packet) --> counts + latency statistics.
//
// Key quantities (all seconds internally, ms in the results):
//   transit  n_i = arrival_i - media_i
//   deadline arrival_i <= media_i + D        <=>  n_i <= D
//   buffered time of a played packet = (media_i + D) - arrival_i = D - n_i
#include "jitter_buffer.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <set>

namespace rtpscope {

namespace {

// Accumulates per-packet outcomes into a SimResult.
class Tally {
public:
    explicit Tally(const PlayoutTrace& trace) : unique_(trace.packets.size()), expected_(trace.expected) {}

    void on_time(double buffered_s) {
        ++played_;
        const double ms = buffered_s * 1000.0;
        sum_ms_ += ms;
        max_ms_ = std::max(max_ms_, ms);
    }
    void late() { ++late_; }

    SimResult finish(const std::string& name) const {
        SimResult r;
        r.strategy = name;
        r.expected = std::max<uint64_t>(expected_, unique_);
        r.played = played_;
        r.late = late_;
        r.lost = r.expected - unique_;
        r.late_or_lost_percent =
            r.expected == 0 ? 0.0 : 100.0 * static_cast<double>(r.late + r.lost) / static_cast<double>(r.expected);
        r.avg_latency_ms = played_ == 0 ? 0.0 : sum_ms_ / static_cast<double>(played_);
        r.max_latency_ms = max_ms_;
        return r;
    }

private:
    uint64_t unique_, expected_;
    uint64_t played_ = 0, late_ = 0;
    double sum_ms_ = 0.0, max_ms_ = 0.0;
};

std::string fixed_name(double delay_ms) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "fixed-%gms", delay_ms);
    return buf;
}

std::string adaptive_name(double k) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "adaptive-k%g", k);
    return buf;
}

}  // namespace

PlayoutTrace make_trace(const StreamStats& stream) {
    PlayoutTrace trace;
    trace.clock_rate = stream.clock_rate();
    trace.expected = stream.expected();

    bool first = true;
    uint64_t first_arrival_ns = 0;
    uint32_t prev_ts = 0;
    int64_t media_units = 0;  // unwrapped timestamp ticks since the first packet
    for (const Arrival& a : stream.arrivals()) {
        if (a.duplicate) continue;
        if (first) {
            first_arrival_ns = a.arrival_ns;
            first = false;
        } else {
            // Signed 32-bit difference handles both the 2^32 wrap and reordered
            // packets (negative steps).
            media_units += static_cast<int32_t>(a.rtp_timestamp - prev_ts);
        }
        prev_ts = a.rtp_timestamp;
        PlayoutPacket p;
        p.arrival_s = static_cast<double>(static_cast<int64_t>(a.arrival_ns - first_arrival_ns)) / 1e9;
        p.media_s = static_cast<double>(media_units) / static_cast<double>(trace.clock_rate);
        p.marker = a.marker;
        trace.packets.push_back(p);
    }
    return trace;
}

SimResult simulate_fixed(const PlayoutTrace& trace, double delay_ms) {
    Tally tally(trace);
    const double d = delay_ms / 1000.0;
    for (const PlayoutPacket& p : trace.packets) {
        const double transit = p.arrival_s - p.media_s;
        if (transit <= d) tally.on_time(d - transit);
        else tally.late();
    }
    return tally.finish(fixed_name(delay_ms));
}

SimResult simulate_adaptive(const PlayoutTrace& trace, const AdaptiveParams& prm) {
    Tally tally(trace);
    const double slew = prm.slew_ms / 1000.0;
    const double gap = prm.talkspurt_gap_ms / 1000.0;

    double delay = prm.initial_delay_ms / 1000.0;  // current playout delay D
    double mean = 0.0, dev = 0.0;                  // d_hat and v_hat
    uint64_t samples = 0;
    double max_media = 0.0;
    bool have_media = false;

    for (const PlayoutPacket& p : trace.packets) {
        const double transit = p.arrival_s - p.media_s;
        const double target = std::max(0.0, mean + prm.k * dev);
        const bool warm = samples >= prm.warmup_packets;

        // Talkspurt boundary: explicit marker, or a long silence in media time.
        const bool boundary = p.marker || (have_media && p.media_s - max_media > gap);
        if (boundary && warm) delay = target;

        if (transit <= delay) tally.on_time(delay - transit);
        else tally.late();

        // Update the estimators with this packet's transit (bias-corrected weight).
        ++samples;
        const double a = std::min(prm.alpha, 1.0 - 1.0 / static_cast<double>(samples));
        mean = a * mean + (1.0 - a) * transit;
        dev = a * dev + (1.0 - a) * std::fabs(mean - transit);

        // Between boundaries, creep towards the new target without a jump.
        if (warm && !boundary) {
            const double new_target = std::max(0.0, mean + prm.k * dev);
            delay += std::max(-slew, std::min(slew, new_target - delay));
        }
        max_media = have_media ? std::max(max_media, p.media_s) : p.media_s;
        have_media = true;
    }
    return tally.finish(adaptive_name(prm.k));
}

std::string sweep_csv(const PlayoutTrace& trace, const AdaptiveParams& base) {
    std::string out = "strategy,avg_latency_ms,late_or_lost_pct\n";
    auto row = [&out](const SimResult& r) {
        char buf[160];
        std::snprintf(buf, sizeof buf, "%s,%.3f,%.4f\n", r.strategy.c_str(), r.avg_latency_ms, r.late_or_lost_percent);
        out += buf;
    };
    for (double ms : {0.0, 10.0, 20.0, 40.0, 60.0, 80.0, 100.0, 150.0, 200.0}) row(simulate_fixed(trace, ms));

    std::set<double> ks = {1.0, 2.0, 4.0, 8.0, base.k};
    for (double k : ks) {
        AdaptiveParams p = base;
        p.k = k;
        row(simulate_adaptive(trace, p));
    }
    return out;
}

}  // namespace rtpscope
