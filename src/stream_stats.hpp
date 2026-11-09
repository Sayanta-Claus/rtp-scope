// stream_stats.hpp -- statistics of one RTP stream (one SSRC on one 5-tuple).
//
// What it does:
//   Accumulates, per stream: packet and byte counts, first/last arrival time,
//   sequence-number tracking (loss, duplicates, reordering) and interarrival
//   jitter. Optionally also keeps the arrival list for the jitter-buffer
//   simulator.
//
// Where it sits in the data flow:
//   Analyzer --(RtpHeader, arrival time)--> StreamStats --> report / simulator.
//
// Key definitions (RFC 3550 6.4.1 and A.3):
//   expected      = extended highest seq - base seq + 1
//   lost          = expected - unique packets received   (clamped at 0 here)
//   The RFC computes lost = expected - received where "received" counts every
//   arriving packet, so duplicates can drive it negative; the RFC allows a
//   negative cumulative loss. We keep duplicates in a separate counter, report
//   loss clamped at 0, and expose the signed RFC-style value in JSON.
//
// Design decisions:
//   * A stream is keyed by (src ip, src port, dst ip, dst port, SSRC), so two
//     SSRCs on one port pair, or one SSRC seen from two sources, stay apart.
//   * Jitter ignores duplicates and rejected packets: a duplicate has the same
//     RTP timestamp as the original, so it would look like a huge D.
//   * The clock rate is fixed from the first packet's payload type; a change of
//     payload type mid-stream (e.g. DTMF events) is flagged, not split.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "jitter.hpp"
#include "rtp_header.hpp"
#include "seq_tracker.hpp"

namespace rtpscope {

struct StreamKey {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t ssrc = 0;

    bool operator==(const StreamKey& o) const {
        return src_ip == o.src_ip && dst_ip == o.dst_ip && src_port == o.src_port &&
               dst_port == o.dst_port && ssrc == o.ssrc;
    }
    bool operator<(const StreamKey& o) const;
};

// One received packet, kept (optionally) for the jitter-buffer simulation.
struct Arrival {
    uint64_t arrival_ns = 0;
    uint32_t rtp_timestamp = 0;
    int64_t ext_seq = 0;
    bool marker = false;
    bool duplicate = false;
};

class StreamStats {
public:
    StreamStats(const StreamKey& key, uint8_t payload_type, uint32_t clock_rate, bool keep_arrivals)
        : key_(key), payload_type_(payload_type), clock_rate_(clock_rate), keep_arrivals_(keep_arrivals) {}

    // rtp_bytes = length of the whole RTP packet (header + payload + padding).
    void add_packet(uint64_t arrival_ns, const RtpHeader& header, size_t rtp_bytes);

    const StreamKey& key() const { return key_; }
    uint8_t payload_type() const { return payload_type_; }
    bool payload_type_changed() const { return payload_type_changed_; }
    uint32_t clock_rate() const { return clock_rate_; }

    uint64_t packets() const { return packets_; }  // everything attributed to this stream
    uint64_t bytes() const { return bytes_; }
    double duration_s() const;
    double bitrate_kbps() const;

    int64_t extended_highest() const { return seq_.extended_highest(); }
    uint64_t expected() const { return seq_.expected(); }
    uint64_t unique_received() const { return seq_.unique_received(); }
    uint64_t lost() const;                 // clamped at 0
    int64_t lost_signed() const;           // RFC 3550 style: may be negative
    double loss_percent() const;
    uint64_t duplicates() const { return seq_.duplicates(); }
    uint64_t out_of_order() const { return seq_.out_of_order(); }
    uint64_t seq_rejected() const { return seq_.rejected(); }
    uint64_t seq_resyncs() const { return seq_.resyncs(); }

    double jitter_units() const { return jitter_.jitter_units(); }
    double jitter_ms() const { return jitter_.jitter_ms(clock_rate_); }

    uint64_t first_arrival_ns() const { return first_ns_; }
    const std::vector<Arrival>& arrivals() const { return arrivals_; }

private:
    StreamKey key_;
    uint8_t payload_type_;
    bool payload_type_changed_ = false;
    uint32_t clock_rate_;
    bool keep_arrivals_;

    uint64_t packets_ = 0;
    uint64_t bytes_ = 0;
    uint64_t first_ns_ = 0;
    uint64_t last_ns_ = 0;
    SeqTracker seq_;
    JitterEstimator jitter_;
    std::vector<Arrival> arrivals_;
};

}  // namespace rtpscope
