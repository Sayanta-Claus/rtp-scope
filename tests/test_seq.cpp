// test_seq.cpp -- RFC 3550 A.1 sequence tracking: wraparound, loss, duplicates,
// reordering, restarts.
#include "seq_tracker.hpp"
#include "test_harness.hpp"

using namespace rtpscope;

namespace {
void feed(SeqTracker& t, std::initializer_list<uint16_t> seqs) {
    for (uint16_t s : seqs) t.update(s);
}
}  // namespace

TEST(wraparound_extends_to_32_bits_and_loses_nothing) {
    SeqTracker t;
    feed(t, {65534, 65535, 0, 1});
    CHECK_EQ(t.extended_highest(), 65537);
    CHECK_EQ(t.expected(), 4u);
    CHECK_EQ(t.unique_received(), 4u);
    CHECK_EQ(t.duplicates(), 0u);
    CHECK_EQ(t.out_of_order(), 0u);
}

TEST(wraparound_with_a_lost_packet) {
    SeqTracker t;
    feed(t, {65533, 65535, 1});  // 65534 and 0 are missing
    CHECK_EQ(t.extended_highest(), 65537);
    CHECK_EQ(t.expected(), 5u);
    CHECK_EQ(t.unique_received(), 3u);
}

TEST(sequence_numbers_can_be_reused_after_a_full_cycle_without_false_duplicates) {
    SeqTracker t;
    for (uint32_t i = 0; i < 70000; ++i) t.update(static_cast<uint16_t>(i));
    CHECK_EQ(t.duplicates(), 0u);
    CHECK_EQ(t.expected(), 70000u);
    CHECK_EQ(t.extended_highest(), 69999);
}

TEST(gap_counts_as_loss) {
    SeqTracker t;
    feed(t, {1, 2, 5});
    CHECK_EQ(t.expected(), 5u);
    CHECK_EQ(t.unique_received(), 3u);
}

TEST(immediate_and_late_duplicates) {
    SeqTracker t;
    feed(t, {10, 11, 11, 12, 13, 11});  // 11 repeated right away and again later
    CHECK_EQ(t.duplicates(), 2u);
    CHECK_EQ(t.unique_received(), 4u);
    CHECK_EQ(t.expected(), 4u);
    CHECK_EQ(t.out_of_order(), 0u);
}

TEST(reordering_is_not_loss_and_is_not_duplicate) {
    SeqTracker t;
    feed(t, {1, 2, 4, 3, 5});
    CHECK_EQ(t.out_of_order(), 1u);
    CHECK_EQ(t.duplicates(), 0u);
    CHECK_EQ(t.expected(), 5u);
    CHECK_EQ(t.unique_received(), 5u);
}

TEST(late_packet_from_before_the_wrap_gets_previous_cycle_number) {
    SeqTracker t;
    t.update(65534);
    t.update(0);  // 65535 skipped, wrap happened
    const SeqResult late = t.update(65535);
    CHECK(late.kind == SeqKind::OutOfOrder);
    CHECK_EQ(late.ext_seq, 65535);
    CHECK_EQ(t.extended_highest(), 65536);
    CHECK_EQ(t.expected(), 3u);
    CHECK_EQ(t.unique_received(), 3u);
}

TEST(packet_older_than_the_first_one_extends_the_range_downwards) {
    SeqTracker t;
    feed(t, {10, 8});
    CHECK_EQ(t.out_of_order(), 1u);
    CHECK_EQ(t.expected(), 3u);  // 8, 9, 10
    CHECK_EQ(t.unique_received(), 2u);
}

TEST(single_wild_packet_is_rejected_and_stream_continues) {
    SeqTracker t;
    feed(t, {100, 101});
    CHECK(t.update(50000).kind == SeqKind::Rejected);
    CHECK(t.update(102).kind == SeqKind::InOrder);
    CHECK_EQ(t.rejected(), 1u);
    CHECK_EQ(t.expected(), 3u);
    CHECK_EQ(t.unique_received(), 3u);
}

TEST(two_sequential_wild_packets_are_a_restart_and_totals_accumulate) {
    SeqTracker t;
    feed(t, {10, 11});
    CHECK(t.update(40000).kind == SeqKind::Rejected);
    CHECK(t.update(40001).kind == SeqKind::Resync);
    CHECK_EQ(t.resyncs(), 1u);
    CHECK_EQ(t.expected(), 3u);  // 2 from the old epoch + 1 from the new
    CHECK_EQ(t.unique_received(), 3u);
}

TEST_MAIN()
