// seq_tracker.hpp -- RTP sequence-number tracking per RFC 3550 Appendix A.1.
//
// What it does:
//   Turns the 16-bit sequence numbers of one stream into an *extended* 64-bit
//   counter (cycles * 65536 + seq), and classifies every arriving packet as
//   in-order, duplicate, out-of-order or a discontinuity. From this it derives
//   how many packets were expected versus received.
//
// Where it sits in the data flow:
//   RtpHeader.sequence --> SeqTracker::update() --> SeqResult --> StreamStats.
//
// Key concepts (RFC 3550 A.1, update_seq()):
//   * Sequence numbers wrap every 65536 packets (~22 min at 50 pps), so a plain
//     16-bit value cannot count a long call. We count wraps in `cycles`.
//   * udelta = (uint16)(seq - max_seq) is the forward distance modulo 2^16.
//       udelta < MAX_DROPOUT (3000)      : forward jump (gap = lost packets)
//       udelta > 65536 - MAX_MISORDER    : a few packets *behind* max (late or
//                                          duplicate), within 100
//       anything in between              : implausible jump, probably a
//                                          restarted/bogus source
//   * For an implausible jump, A.1 only accepts it if the *next* packet is
//     sequential to it (two in a row => the source really restarted); the
//     first such packet is rejected.
//
// Design decisions that differ from / extend the RFC:
//   * Duplicates are detected with a 256-bit "seen" ring indexed by seq16 mod 256
//     (A.1 itself cannot tell a duplicate from a reordered packet). A packet is
//     at most MAX_MISORDER (100) behind the highest number, so 256 slots are
//     enough, and a stream costs 32 bytes instead of 8 KB. Bits ahead
//     of max_seq are cleared as it advances, so stale entries never survive a
//     wrap.
//   * A restart (resync) starts a new "epoch". Totals from the old epoch are
//     folded into acc_expected_/acc_received_, so loss stays cumulative.
//   * A.1's "probation" (MIN_SEQUENTIAL) is not done here: the tracker counts
//     every packet from the first. Whether a stream is real is decided at the
//     end by StreamStats::confirmed() (two consecutive sequence numbers seen),
//     so no early packets are lost from the totals.
#pragma once

#include <cstdint>
#include <bitset>

namespace rtpscope {

enum class SeqKind {
    First,       // first packet of the stream (or of a new epoch after a restart)
    InOrder,     // advanced the highest sequence number
    Duplicate,   // already seen
    OutOfOrder,  // new, but older than the highest sequence number
    Rejected,    // implausible jump, ignored (see above)
    Resync,      // second sequential packet after a jump: source restarted
};

struct SeqResult {
    SeqKind kind = SeqKind::First;
    int64_t ext_seq = 0;  // extended sequence number (can be < base for a very late packet)
};

class SeqTracker {
public:
    static constexpr uint32_t kMaxDropout = 3000;
    static constexpr uint32_t kMaxMisorder = 100;
    static constexpr uint32_t kSeqMod = 1u << 16;

    SeqTracker() = default;

    SeqResult update(uint16_t seq);

    // Highest extended sequence number of the current epoch.
    int64_t extended_highest() const { return static_cast<int64_t>(cycles_) * kSeqMod + max_seq_; }
    // Packets expected / unique packets received, cumulative over epochs.
    uint64_t expected() const;
    uint64_t unique_received() const { return acc_received_ + epoch_received_; }

    uint64_t duplicates() const { return duplicates_; }
    uint64_t out_of_order() const { return out_of_order_; }
    uint64_t rejected() const { return rejected_; }
    uint64_t resyncs() const { return resyncs_; }
    bool started() const { return started_; }

private:
    void start_epoch(uint16_t seq);

    // Which of the most recent kRing sequence numbers have been seen, indexed by seq & (kRing - 1).
    static constexpr uint32_t kRing = 256;  // must exceed kMaxMisorder
    std::bitset<kRing> seen_;
    bool started_ = false;
    uint16_t max_seq_ = 0;
    int64_t cycles_ = 0;
    int64_t base_ = 0;             // lowest extended seq seen in this epoch
    int32_t bad_seq_ = -1;         // expected "next" seq of a suspicious jump, or -1
    uint64_t epoch_received_ = 0;
    uint64_t acc_expected_ = 0;
    uint64_t acc_received_ = 0;
    uint64_t duplicates_ = 0;
    uint64_t out_of_order_ = 0;
    uint64_t rejected_ = 0;
    uint64_t resyncs_ = 0;
};

}  // namespace rtpscope
