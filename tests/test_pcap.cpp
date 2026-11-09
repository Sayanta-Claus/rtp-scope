// test_pcap.cpp -- pcap global/record header parsing: byte orders, timestamp
// resolutions, link types, and damaged files.
#include <sstream>

#include "pcap_reader.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"

using namespace support;

namespace {

// Runs the analyzer over pcap bytes; returns success and the error text.
bool run(const std::string& bytes, rtpscope::Analyzer& a, std::string& err) {
    std::istringstream in(bytes, std::ios::binary);
    return a.analyze(in, err);
}

}  // namespace

TEST(all_four_magics_parse) {
    for (int big = 0; big < 2; ++big) {
        for (int nano = 0; nano < 2; ++nano) {
            PcapWriteOptions opt;
            opt.big_endian = big != 0;
            opt.nanosecond = nano != 0;
            const std::string pcap = make_pcap({{1500000000ull * 1000000000ull + 123456000ull, rtp_frame(1)}}, opt);

            std::istringstream in(pcap, std::ios::binary);
            rtpscope::PcapReader reader(in);
            std::string err;
            CHECK(reader.read_header(err));
            CHECK_EQ(reader.big_endian(), big != 0);
            CHECK_EQ(reader.nanosecond(), nano != 0);

            rtpscope::PcapRecord rec;
            CHECK(reader.next(rec) == rtpscope::PcapReader::Next::Record);
            // 123456000 ns is exactly representable in microseconds too.
            CHECK_EQ(rec.timestamp_ns, 1500000000ull * 1000000000ull + 123456000ull);
            CHECK(reader.next(rec) == rtpscope::PcapReader::Next::End);

            rtpscope::Analyzer a;
            CHECK(run(pcap, a, err));
            CHECK_EQ(a.counters().rtp, 1u);
        }
    }
}

TEST(microsecond_files_truncate_sub_microsecond_precision) {
    PcapWriteOptions opt;  // microsecond
    const std::string pcap = make_pcap({{5ull * 1000000000ull + 1999ull, rtp_frame(1)}}, opt);
    std::istringstream in(pcap, std::ios::binary);
    rtpscope::PcapReader reader(in);
    std::string err;
    CHECK(reader.read_header(err));
    rtpscope::PcapRecord rec;
    CHECK(reader.next(rec) == rtpscope::PcapReader::Next::Record);
    CHECK_EQ(rec.timestamp_ns, 5ull * 1000000000ull + 1000ull);
}

TEST(linux_sll_link_type) {
    FrameSpec fs;
    fs.sll = true;
    PcapWriteOptions opt;
    opt.link_type = 113;
    rtpscope::Analyzer a;
    std::string err;
    CHECK(run(make_pcap({{0, rtp_frame(7, 0, 1, fs)}}, opt), a, err));
    CHECK_EQ(a.counters().rtp, 1u);
}

TEST(unsupported_link_type_is_rejected_with_clear_error) {
    PcapWriteOptions opt;
    opt.link_type = 101;  // raw IP
    rtpscope::Analyzer a;
    std::string err;
    CHECK(!run(make_pcap({}, opt), a, err));
    CHECK(err.find("unsupported link type 101") != std::string::npos);
}

TEST(bad_magic_and_short_files_are_rejected) {
    rtpscope::Analyzer a;
    std::string err;
    CHECK(!run(std::string("not a pcap file at all, just text"), a, err));
    CHECK(err.find("magic") != std::string::npos);
    CHECK(!run(std::string("abc"), a, err));
    CHECK(!run(std::string(), a, err));
    // pcapng starts with 0a0d0d0a
    CHECK(!run(std::string("\x0a\x0d\x0d\x0a" "0000000000000000000000000000", 28), a, err));
}

TEST(truncated_last_record_keeps_earlier_packets) {
    std::string pcap = make_pcap({{0, rtp_frame(1)}, {1000, rtp_frame(2)}});
    pcap.resize(pcap.size() - 10);  // cut into the second record's data
    rtpscope::Analyzer a;
    std::string err;
    CHECK(run(pcap, a, err));
    CHECK_EQ(a.counters().rtp, 1u);
    CHECK(a.counters().capture_truncated);
}

TEST(truncated_record_header_is_flagged) {
    std::string pcap = make_pcap({{0, rtp_frame(1)}});
    pcap.append("\x01\x02\x03", 3);  // stray bytes: not a full 16-byte record header
    rtpscope::Analyzer a;
    std::string err;
    CHECK(run(pcap, a, err));
    CHECK_EQ(a.counters().rtp, 1u);
    CHECK(a.counters().capture_truncated);
}

TEST(absurd_record_length_stops_without_huge_allocation) {
    std::string pcap = make_pcap({{0, rtp_frame(1)}});
    // Append a record header claiming ~4 GiB of captured data.
    const unsigned char hdr[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    pcap.append(reinterpret_cast<const char*>(hdr), sizeof hdr);
    rtpscope::Analyzer a;
    std::string err;
    CHECK(run(pcap, a, err));
    CHECK_EQ(a.counters().rtp, 1u);
    CHECK(a.counters().capture_corrupt);
}

TEST_MAIN()
