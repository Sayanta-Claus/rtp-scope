// stream_stats.cpp -- per-stream accumulation and derived statistics.
//
// What it does: feeds each packet into the sequence tracker and jitter
// estimator and keeps byte/time totals; derived values are computed on demand.
//
// Data flow: (arrival_ns, RtpHeader) --> counters + SeqTracker + JitterEstimator.
//
// Notes:
//   * duration = latest arrival time seen minus the first packet's arrival
//     time, so reordering cannot make it negative.
//   * bitrate counts RTP bytes (header + payload) over that duration; it
//     excludes UDP/IP/Ethernet overhead. One packet => duration 0 => bitrate 0.
#include "stream_stats.hpp"

#include <tuple>

namespace rtpscope {

bool StreamKey::operator<(const StreamKey& o) const {
    return std::tie(src_ip, src_port, dst_ip, dst_port, ssrc) <
           std::tie(o.src_ip, o.src_port, o.dst_ip, o.dst_port, o.ssrc);
}

void StreamStats::add_packet(uint64_t arrival_ns, const RtpHeader& h, size_t rtp_bytes) {
    if (packets_ == 0) first_ns_ = arrival_ns;
    if (arrival_ns > last_ns_) last_ns_ = arrival_ns;
    ++packets_;
    bytes_ += rtp_bytes;
    if (h.payload_type != payload_type_) payload_type_changed_ = true;

    if (has_last_seq_ && h.sequence == static_cast<uint16_t>(last_seq_ + 1)) ++sequential_pairs_;
    has_last_seq_ = true;
    last_seq_ = h.sequence;

    const SeqResult r = seq_.update(h.sequence);
    const bool counted = r.kind != SeqKind::Duplicate && r.kind != SeqKind::Rejected;
    if (counted) jitter_.update(arrival_ns, h.timestamp, clock_rate_);

    if (keep_arrivals_) {
        Arrival a;
        a.arrival_ns = arrival_ns;
        a.rtp_timestamp = h.timestamp;
        a.ext_seq = r.ext_seq;
        a.marker = h.marker;
        a.duplicate = r.kind == SeqKind::Duplicate || r.kind == SeqKind::Rejected;
        arrivals_.push_back(a);
    }
}

double StreamStats::duration_s() const {
    return packets_ < 2 ? 0.0 : static_cast<double>(last_ns_ - first_ns_) / 1e9;
}

double StreamStats::bitrate_kbps() const {
    const double d = duration_s();
    return d > 0.0 ? static_cast<double>(bytes_) * 8.0 / d / 1000.0 : 0.0;
}

int64_t StreamStats::lost_signed() const {
    // RFC 3550 A.3: lost = expected - received, where received counts every
    // arriving packet including duplicates.
    return static_cast<int64_t>(seq_.expected()) -
           static_cast<int64_t>(seq_.unique_received() + seq_.duplicates());
}

uint64_t StreamStats::lost() const {
    const int64_t unique_lost =
        static_cast<int64_t>(seq_.expected()) - static_cast<int64_t>(seq_.unique_received());
    return unique_lost > 0 ? static_cast<uint64_t>(unique_lost) : 0;
}

double StreamStats::loss_percent() const {
    const uint64_t e = seq_.expected();
    return e == 0 ? 0.0 : 100.0 * static_cast<double>(lost()) / static_cast<double>(e);
}

}  // namespace rtpscope
