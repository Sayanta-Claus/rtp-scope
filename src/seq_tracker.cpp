// seq_tracker.cpp -- implementation of RFC 3550 A.1 sequence tracking.
//
// What it does:
//   One call to update() per received packet; see seq_tracker.hpp for the
//   concepts. The branches below follow the structure of update_seq() in the RFC.
//
// Data flow: seq16 --> (max_seq, cycles, seen ring) --> SeqResult.
//
// The wraparound arithmetic, spelled out:
//   udelta = (uint16_t)(seq - max_seq) uses unsigned 16-bit subtraction, which
//   wraps modulo 65536. Example: max_seq = 65535, seq = 1 => udelta = 2, a
//   forward step of two even though 1 < 65535. We detect that the counter
//   wrapped by "seq < max_seq" in that forward branch and add one cycle.
//   A late packet is the opposite: seq = 65534 with max_seq = 2 gives
//   udelta = 65532 > 65436, i.e. 4 packets behind. Its extended number is
//   simply extended_highest - 4, which is automatically the previous cycle.
#include "seq_tracker.hpp"

namespace rtpscope {

void SeqTracker::start_epoch(uint16_t seq) {
    if (started_) {
        acc_expected_ += static_cast<uint64_t>(extended_highest() - base_ + 1);
        acc_received_ += epoch_received_;
    }
    started_ = true;
    max_seq_ = seq;
    cycles_ = 0;
    base_ = seq;
    bad_seq_ = -1;
    epoch_received_ = 1;
    seen_.assign(kSeqMod, false);
    seen_[seq] = true;
}

uint64_t SeqTracker::expected() const {
    if (!started_) return 0;
    return acc_expected_ + static_cast<uint64_t>(extended_highest() - base_ + 1);
}

SeqResult SeqTracker::update(uint16_t seq) {
    if (!started_) {
        start_epoch(seq);
        return {SeqKind::First, extended_highest()};
    }

    const uint16_t udelta = static_cast<uint16_t>(seq - max_seq_);

    if (udelta == 0) {  // same number as the highest: a duplicate
        ++duplicates_;
        return {SeqKind::Duplicate, extended_highest()};
    }

    if (udelta < kMaxDropout) {
        // In order, possibly with a gap. A numerically smaller seq means the
        // 16-bit counter wrapped.
        if (seq < max_seq_) ++cycles_;
        // Forget stale "seen" bits for the numbers we are skipping over, so a
        // number reused after a wrap is not mistaken for a duplicate.
        for (uint32_t k = 1; k < udelta; ++k) {
            seen_[static_cast<uint16_t>(max_seq_ + k)] = false;
        }
        seen_[seq] = true;
        max_seq_ = seq;
        ++epoch_received_;
        bad_seq_ = -1;
        return {SeqKind::InOrder, extended_highest()};
    }

    if (udelta <= kSeqMod - kMaxMisorder) {
        // A very large jump forward or backward. Accept only if the previous
        // suspicious packet announced this exact number (source restarted).
        if (bad_seq_ == static_cast<int32_t>(seq)) {
            ++resyncs_;
            start_epoch(seq);
            return {SeqKind::Resync, extended_highest()};
        }
        bad_seq_ = static_cast<int32_t>((seq + 1u) & (kSeqMod - 1));
        ++rejected_;
        return {SeqKind::Rejected, extended_highest()};
    }

    // Slightly behind the highest number: a late or duplicated packet.
    const int64_t behind = static_cast<int64_t>(kSeqMod) - udelta;  // 1..kMaxMisorder
    const int64_t ext = extended_highest() - behind;
    if (seen_[seq]) {
        ++duplicates_;
        return {SeqKind::Duplicate, ext};
    }
    seen_[seq] = true;
    ++epoch_received_;
    ++out_of_order_;
    if (ext < base_) base_ = ext;  // arrived before anything we had seen
    return {SeqKind::OutOfOrder, ext};
}

}  // namespace rtpscope
