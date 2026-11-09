// test_support.hpp -- helpers shared by the unit tests.
//
// What it does:
//   Builds small in-memory pcap files with PcapWriter and runs the Analyzer
//   over them, so each test states its scenario in a few lines.
#pragma once

#include <sstream>
#include <string>
#include <vector>

#include "analyzer.hpp"
#include "pcap_writer.hpp"

namespace support {

using rtpscope::FrameSpec;
using rtpscope::PcapWriteOptions;
using rtpscope::PcapWriter;
using rtpscope::RtpPacketSpec;

inline std::vector<uint8_t> rtp_frame(uint16_t seq, uint32_t ts = 0, uint32_t ssrc = 0x1234,
                                      const FrameSpec& fs = FrameSpec()) {
    RtpPacketSpec rs;
    rs.sequence = seq;
    rs.timestamp = ts;
    rs.ssrc = ssrc;
    return rtpscope::build_udp_frame(fs, rtpscope::build_rtp_packet(rs));
}

// Serialises (timestamp_ns, frame) pairs into pcap bytes.
inline std::string make_pcap(const std::vector<std::pair<uint64_t, std::vector<uint8_t>>>& frames,
                             const PcapWriteOptions& opt = PcapWriteOptions()) {
    std::ostringstream os(std::ios::binary);
    PcapWriter w(os, opt);
    w.write_header();
    for (const auto& f : frames) w.write_record(f.first, f.second);
    return os.str();
}

}  // namespace support
