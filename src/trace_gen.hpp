// trace_gen.hpp -- synthetic RTP traffic with a known ground truth.
//
// What it does:
//   Simulates one RTP sender and a lossy network, producing the packets a
//   receiver would capture, and *counts exactly* what it did to them: packets
//   sent, dropped, duplicated and reordered. The analyzer's output can then be
//   checked against these numbers.
//
// Where it sits in the data flow:
//   GenConfig --> generate_trace() --> arrivals + GroundTruth
//   --> write_trace_pcap() --> .pcap     and   truth_to_text() --> .truth file.
//
// The network model (in this order):
//   1. Sender: packet n leaves at t = n * interval (talkspurts optionally
//      leave gaps), with sequence start_seq + n (mod 2^16) and a timestamp
//      advancing at the codec clock rate.
//   2. Loss: each packet is dropped independently with probability `loss`.
//   3. Delay: base delay + jitter (uniform in [0,J], or |N(0,J)|), but the path
//      is FIFO (arrival = max(previous arrival, send + delay)). Jitter alone
//      therefore never reorders; reordering is explicit (next step).
//   4. Reordering: with probability `reorder` a delivered packet swaps places
//      with the next delivered one (each swap = exactly 1 reordered packet).
//   5. Duplication: with probability `duplicate` a delivered packet is
//      followed immediately by an identical copy.
//
// Design decision:
//   Each effect is deliberately unambiguous so that "reordered" has one
//   defensible meaning: a packet that arrives after a packet with a higher
//   sequence number, which is exactly what an RTP receiver can observe.
#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "pcap_writer.hpp"

namespace rtpscope {

enum class JitterDistribution { Uniform, Normal };

struct GenConfig {
    uint64_t seed = 1;
    double duration_s = 10.0;       // used when `packets` is 0
    uint64_t packets = 0;           // exact number of packets to send (overrides duration)
    double interval_ms = 20.0;
    uint8_t payload_type = 0;
    uint32_t clock_rate = 0;        // 0 = default for the payload type
    uint32_t ssrc = 0x11223344;
    uint16_t start_seq = 100;
    uint32_t start_timestamp = 1000000;
    size_t payload_bytes = 160;
    double loss = 0.0;
    double reorder = 0.0;
    double duplicate = 0.0;
    double jitter_ms = 0.0;
    JitterDistribution jitter_distribution = JitterDistribution::Uniform;
    double base_delay_ms = 20.0;
    double talk_on_ms = 0.0;        // 0 = continuous; otherwise on/off cycle with silence gaps
    double talk_off_ms = 0.0;
    uint64_t start_time_s = 1700000000;
    // Output format.
    bool nanosecond = false;
    bool big_endian = false;
    bool vlan = false;
    bool sll = false;
};

struct GeneratedPacket {
    uint64_t arrival_ns = 0;
    uint16_t sequence = 0;
    uint32_t timestamp = 0;
    bool marker = false;
    uint64_t index = 0;  // n-th packet sent (0-based): unwrapped seq = start_seq + index
};

struct GroundTruth {
    uint64_t sent = 0;
    uint64_t dropped = 0;
    uint64_t duplicated = 0;
    uint64_t reordered = 0;
    uint64_t received = 0;         // packets in the capture, duplicates included
    uint64_t unique_received = 0;  // distinct packets delivered
    uint64_t expected = 0;         // what a receiver can know: highest - lowest delivered + 1
    uint64_t lost = 0;             // expected - unique_received (drops at the very start/end are invisible)
    int64_t ext_highest_seq = 0;   // as RFC 3550 A.1 would number it (cycle 0 = first arrival's cycle)
};

// Fills `arrivals` (capture order, duplicates included) and `truth`.
void generate_trace(const GenConfig& config, std::vector<GeneratedPacket>& arrivals, GroundTruth& truth);

// Resolves the clock rate actually used (config value or the PT default).
uint32_t effective_clock_rate(const GenConfig& config);

void write_trace_pcap(const GenConfig& config, const std::vector<GeneratedPacket>& arrivals, std::ostream& out);

// key=value text for the sidecar file (see docs/README).
std::string truth_to_text(const GenConfig& config, const GroundTruth& truth);

}  // namespace rtpscope
