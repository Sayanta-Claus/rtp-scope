// trace_gen.cpp -- implementation of the synthetic traffic model.
//
// What it does: runs the five steps described in trace_gen.hpp and tallies the
// ground truth as it goes.
//
// Data flow: GenConfig --> sent packets --> delivered (loss, FIFO delay)
//            --> reorder swaps --> duplicates --> arrivals + GroundTruth.
//
// Determinism notes:
//   * All times are integer nanoseconds rounded to whole microseconds, so a
//     microsecond-resolution pcap stores them exactly and the analyzer sees
//     what the generator computed.
//   * Loss, delay, reorder and duplicate decisions use independent Rng streams.
//   * The sender timestamp is start_timestamp + floor(t_ns * clock / 1e9) in
//     64-bit integer math (t up to ~1.5e13 ns * 48000 < 2^63), truncated to 32
//     bits, so it wraps naturally like a real RTP timestamp.
#include "trace_gen.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>

#include "clock_rate.hpp"
#include "pcap_reader.hpp"
#include "traffic_model.hpp"

namespace rtpscope {

namespace {

uint64_t round_to_us(double ns) {
    return static_cast<uint64_t>(std::llround(ns / 1000.0)) * 1000ull;
}

struct Sent {
    uint64_t index;
    uint64_t send_ns;
    uint16_t seq;
    uint32_t ts;
    bool marker;
};

// Step 1: the sender. Returns packets in send order.
std::vector<Sent> make_sender(const GenConfig& c, uint32_t clock) {
    std::vector<Sent> out;
    const uint64_t interval_ns = round_to_us(c.interval_ms * 1e6);
    const uint64_t on_ns = round_to_us(c.talk_on_ms * 1e6);
    const uint64_t off_ns = round_to_us(c.talk_off_ms * 1e6);
    if (interval_ns == 0) return out;  // nothing sensible to send
    const bool talkspurts = on_ns > 0 && off_ns > 0;
    const uint64_t cycle_ns = on_ns + off_ns;
    const uint64_t duration_ns = static_cast<uint64_t>(c.duration_s * 1e9);

    bool prev_slot_sent = false;
    for (uint64_t slot = 0;; ++slot) {
        const uint64_t t = slot * interval_ns;
        if (c.packets > 0 ? out.size() >= c.packets : t >= duration_ns) break;
        if (talkspurts && (t % cycle_ns) >= on_ns) {  // silence: nothing is sent
            prev_slot_sent = false;
            continue;
        }
        Sent s;
        s.index = out.size();
        s.send_ns = t;
        s.seq = static_cast<uint16_t>(c.start_seq + s.index);
        s.ts = c.start_timestamp + static_cast<uint32_t>(t * clock / 1000000000ull);
        s.marker = !prev_slot_sent && talkspurts;  // first packet of a talkspurt
        prev_slot_sent = true;
        out.push_back(s);
    }
    return out;
}

}  // namespace

uint32_t effective_clock_rate(const GenConfig& config) {
    return config.clock_rate != 0 ? config.clock_rate : ClockRates().rate_for(config.payload_type);
}

void generate_trace(const GenConfig& c, std::vector<GeneratedPacket>& arrivals, GroundTruth& truth) {
    arrivals.clear();
    truth = GroundTruth();

    Rng rng_loss(c.seed, 1), rng_delay(c.seed, 2), rng_reorder(c.seed, 3), rng_dup(c.seed, 4);
    const uint32_t clock = effective_clock_rate(c);
    const std::vector<Sent> sent = make_sender(c, clock);
    truth.sent = sent.size();

    // Steps 2 and 3: loss and FIFO delay.
    std::vector<GeneratedPacket> delivered;
    delivered.reserve(sent.size());
    uint64_t last_arrival = 0;
    const uint64_t start_ns = c.start_time_s * 1000000000ull;
    for (const Sent& s : sent) {
        // Draw both values for every packet so the sequences do not depend on the loss outcome.
        const double u_loss = rng_loss.uniform();
        const double u_delay = c.jitter_distribution == JitterDistribution::Uniform
                                   ? rng_delay.uniform()
                                   : std::fabs(rng_delay.normal());
        if (u_loss < c.loss) {
            ++truth.dropped;
            continue;
        }
        const double delay_ns = (c.base_delay_ms + u_delay * c.jitter_ms) * 1e6;
        uint64_t arrival = start_ns + s.send_ns + round_to_us(delay_ns);
        arrival = std::max(arrival, last_arrival);  // FIFO path: no overtaking from jitter alone
        last_arrival = arrival;
        GeneratedPacket p;
        p.arrival_ns = arrival;
        p.sequence = s.seq;
        p.timestamp = s.ts;
        p.marker = s.marker;
        p.index = s.index;
        delivered.push_back(p);
    }
    truth.unique_received = delivered.size();

    // Step 4: reordering = swap neighbouring delivered packets, keeping the
    // arrival *times* in their original slots so the capture stays time-ordered.
    for (size_t i = 0; i + 1 < delivered.size();) {
        if (rng_reorder.uniform() < c.reorder) {
            std::swap(delivered[i], delivered[i + 1]);
            std::swap(delivered[i].arrival_ns, delivered[i + 1].arrival_ns);
            ++truth.reordered;
            i += 2;
        } else {
            ++i;
        }
    }

    // Step 5: duplication, right after the original.
    arrivals.reserve(delivered.size());
    for (const GeneratedPacket& p : delivered) {
        arrivals.push_back(p);
        if (rng_dup.uniform() < c.duplicate) {
            arrivals.push_back(p);
            ++truth.duplicated;
        }
    }
    truth.received = arrivals.size();

    if (!delivered.empty()) {
        uint64_t lo = delivered[0].index, hi = delivered[0].index;
        for (const GeneratedPacket& p : delivered) {
            lo = std::min(lo, p.index);
            hi = std::max(hi, p.index);
        }
        truth.expected = hi - lo + 1;
        truth.lost = truth.expected - truth.unique_received;
        // The analyzer numbers packets relative to the cycle of the first
        // packet that *arrives* (cycle 0), see seq_tracker.hpp.
        const uint64_t first_unwrapped = c.start_seq + delivered[0].index;
        const uint64_t cycle_offset = (first_unwrapped >> 16) << 16;
        truth.ext_highest_seq = static_cast<int64_t>(c.start_seq + hi) - static_cast<int64_t>(cycle_offset);
    }
}

void write_trace_pcap(const GenConfig& c, const std::vector<GeneratedPacket>& arrivals, std::ostream& out) {
    PcapWriteOptions opt;
    opt.big_endian = c.big_endian;
    opt.nanosecond = c.nanosecond;
    opt.link_type = c.sll ? kLinkLinuxSll : kLinkEthernet;
    PcapWriter writer(out, opt);
    writer.write_header();

    FrameSpec frame;
    frame.vlan = c.vlan;
    frame.sll = c.sll;
    RtpPacketSpec rtp;
    rtp.payload_type = c.payload_type;
    rtp.ssrc = c.ssrc;
    rtp.payload_bytes = c.payload_bytes;
    for (const GeneratedPacket& p : arrivals) {
        rtp.sequence = p.sequence;
        rtp.timestamp = p.timestamp;
        rtp.marker = p.marker;
        writer.write_record(p.arrival_ns, build_udp_frame(frame, build_rtp_packet(rtp)));
    }
}

std::string truth_to_text(const GenConfig& c, const GroundTruth& t) {
    char buf[1024];
    std::snprintf(buf, sizeof buf,
                  "seed=%llu\n"
                  "ssrc=%u\n"
                  "payload_type=%u\n"
                  "clock_rate=%u\n"
                  "start_seq=%u\n"
                  "packets_sent=%llu\n"
                  "packets_dropped=%llu\n"
                  "packets_duplicated=%llu\n"
                  "packets_reordered=%llu\n"
                  "packets_received=%llu\n"
                  "packets_unique_received=%llu\n"
                  "packets_expected=%llu\n"
                  "packets_lost=%llu\n"
                  "ext_highest_seq=%lld\n",
                  static_cast<unsigned long long>(c.seed), c.ssrc, c.payload_type, effective_clock_rate(c),
                  c.start_seq, static_cast<unsigned long long>(t.sent),
                  static_cast<unsigned long long>(t.dropped), static_cast<unsigned long long>(t.duplicated),
                  static_cast<unsigned long long>(t.reordered), static_cast<unsigned long long>(t.received),
                  static_cast<unsigned long long>(t.unique_received), static_cast<unsigned long long>(t.expected),
                  static_cast<unsigned long long>(t.lost), static_cast<long long>(t.ext_highest_seq));
    return buf;
}

}  // namespace rtpscope
