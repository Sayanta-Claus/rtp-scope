// jitter_buffer.hpp -- playout (de-jitter) buffer simulation.
//
// What it does:
//   Replays the arrival times of one RTP stream through a receiver-side
//   playout buffer and reports, per strategy, how many packets would have
//   been played on time, arrived too late (discarded) or were lost, and how
//   much latency the buffer added.
//
// Where it sits in the data flow:
//   StreamStats (arrivals) --> make_trace() --> PlayoutTrace
//   --> simulate_fixed() / simulate_adaptive() --> SimResult --> tables / CSV.
//
// The model:
//   Packet i has a *media time* m_i (when the sender produced it, from the RTP
//   timestamp) and an *arrival time* a_i. Its network transit is n_i = a_i - m_i
//   (up to an unknown constant offset between the two clocks; times are taken
//   relative to the first packet that arrived, so n_1 = 0). A buffer plays
//   packet i at   p_i = m_i + D   where D is the playout delay.
//       on time : a_i <= p_i  (i.e. n_i <= D)  -> played, buffered for p_i - a_i = D - n_i
//       late    : a_i >  p_i                   -> discarded (audible gap)
//   Increasing D trades latency for fewer late packets; that is the whole
//   jitter-buffer trade-off.
//
// Strategies:
//   * Fixed: D is constant.
//   * Adaptive (Ramjee, Kurose, Towsley, Schulzrinne, "Adaptive playout
//     mechanisms for packetized audio applications", INFOCOM 1994, algorithm 1):
//         d = a*d + (1-a)*n_i,   v = a*v + (1-a)*|d - n_i|,   target = d + k*v
//     i.e. track the mean transit and its deviation, and play k deviations
//     later than the mean. D follows the target:
//       - jumps to it at a talkspurt boundary (marker bit, or a long gap in
//         media time), when changing the delay is inaudible because silence
//         is just made longer or shorter;
//       - otherwise slews towards it by at most `slew_ms` per packet so the
//         audio is never cut abruptly.
//     Until `warmup_packets` samples are seen D stays at `initial_delay_ms`.
//
// Design decisions:
//   * "Added latency" is the time a played packet waits in the buffer.
//   * The estimator uses a bias-corrected weight min(alpha, 1 - 1/count), so
//     the first samples form a plain running average instead of crawling away
//     from an arbitrary initial value (alpha = 0.998 would take ~500 packets).
//   * Lateness is judged with the delay chosen *before* the packet's own
//     transit enters the estimate, so the simulation stays causal.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "stream_stats.hpp"

namespace rtpscope {

struct PlayoutPacket {
    double arrival_s = 0.0;  // seconds since the first packet arrived
    double media_s = 0.0;    // seconds of media since the first packet (unwrapped RTP timestamp)
    bool marker = false;
};

struct PlayoutTrace {
    std::vector<PlayoutPacket> packets;  // unique packets in arrival order
    uint64_t expected = 0;               // packets the sender is believed to have sent
    uint32_t clock_rate = 8000;
};

struct AdaptiveParams {
    double k = 4.0;
    double alpha = 0.998;
    double initial_delay_ms = 60.0;
    double slew_ms = 0.5;
    double talkspurt_gap_ms = 100.0;
    uint32_t warmup_packets = 20;
};

struct SimResult {
    std::string strategy;
    uint64_t expected = 0;
    uint64_t played = 0;
    uint64_t late = 0;
    uint64_t lost = 0;
    double late_or_lost_percent = 0.0;
    double avg_latency_ms = 0.0;
    double max_latency_ms = 0.0;
};

// Needs a stream analysed with keep_arrivals = true. Duplicates are dropped.
PlayoutTrace make_trace(const StreamStats& stream);

SimResult simulate_fixed(const PlayoutTrace& trace, double delay_ms);
SimResult simulate_adaptive(const PlayoutTrace& trace, const AdaptiveParams& params);

// Fixed-delay sweep plus adaptive runs for several k, as CSV text with the
// header "strategy,avg_latency_ms,late_or_lost_pct".
std::string sweep_csv(const PlayoutTrace& trace, const AdaptiveParams& base);

}  // namespace rtpscope
