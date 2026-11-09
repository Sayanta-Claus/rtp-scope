// test_report.cpp -- JSON escaping and report structure.
#include <sstream>

#include "report.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"

using namespace support;

TEST(json_escape_handles_quotes_backslashes_and_control_chars) {
    CHECK_EQ(rtpscope::json_escape("plain"), std::string("plain"));
    CHECK_EQ(rtpscope::json_escape("a\"b"), std::string("a\\\"b"));
    CHECK_EQ(rtpscope::json_escape("C:\\dir\\f.pcap"), std::string("C:\\\\dir\\\\f.pcap"));
    CHECK_EQ(rtpscope::json_escape("line1\nline2\ttab\r"), std::string("line1\\nline2\\ttab\\r"));
    CHECK_EQ(rtpscope::json_escape(std::string("nul\0x", 5)), std::string("nul\\u0000x"));
    CHECK_EQ(rtpscope::json_escape("\x01\x1f"), std::string("\\u0001\\u001f"));
}

TEST(format_ipv4_is_dotted_quad) {
    CHECK_EQ(rtpscope::format_ipv4(0x0a000001u), std::string("10.0.0.1"));
    CHECK_EQ(rtpscope::format_ipv4(0xc0a80164u), std::string("192.168.1.100"));
    CHECK_EQ(rtpscope::format_ipv4(0xffffffffu), std::string("255.255.255.255"));
}

namespace {
rtpscope::Analyzer small_capture() {
    std::istringstream in(make_pcap({{0, rtp_frame(1, 0)}, {20000000, rtp_frame(2, 160)}, {60000000, rtp_frame(4, 480)}}),
                          std::ios::binary);
    rtpscope::Analyzer a;
    std::string err;
    a.analyze(in, err);
    return a;
}
}  // namespace

TEST(json_output_contains_expected_fields_and_escapes_the_file_name) {
    const auto a = small_capture();
    std::ostringstream os;
    rtpscope::print_json(os, "we\"ird\\name.pcap", a);
    const std::string j = os.str();
    CHECK(j.find("\"file\": \"we\\\"ird\\\\name.pcap\"") != std::string::npos);
    CHECK(j.find("\"source\": \"10.0.0.1:5004\"") != std::string::npos);
    CHECK(j.find("\"expected\": 4,") != std::string::npos);
    CHECK(j.find("\"lost\": 1,") != std::string::npos);
    CHECK(j.find("\"clock_rate\": 8000,") != std::string::npos);
    int depth = 0;
    for (char c : j) depth += (c == '{' || c == '[') - (c == '}' || c == ']');
    CHECK_EQ(depth, 0);
}

TEST(json_with_no_streams_is_still_valid) {
    std::istringstream in(make_pcap({}), std::ios::binary);
    rtpscope::Analyzer a;
    std::string err;
    CHECK(a.analyze(in, err));
    std::ostringstream os;
    rtpscope::print_json(os, "empty.pcap", a);
    CHECK(os.str().find("\"streams\": []") != std::string::npos);
}

TEST(text_report_mentions_streams_and_loss) {
    const auto a = small_capture();
    std::ostringstream os;
    rtpscope::print_text(os, "x.pcap", a);
    const std::string t = os.str();
    CHECK(t.find("streams: 1") != std::string::npos);
    CHECK(t.find("10.0.0.1:5004") != std::string::npos);
    CHECK(t.find("0 PCMU") != std::string::npos);
    CHECK(t.find("25.00") != std::string::npos);  // 1 of 4 lost
}

TEST_MAIN()
