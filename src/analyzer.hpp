// analyzer.hpp -- drives a whole capture through the decode pipeline.
//
// What it does:
//   Reads every record of a pcap, decodes link/IP/UDP, classifies the UDP
//   payload and keeps counters for each outcome so nothing is silently lost:
//   RTP, RTCP, non-RTP UDP, non-IPv4, non-UDP, skipped fragments, malformed.
//
// Where it sits in the data flow:
//   istream --> PcapReader --> decode_frame --> classify_payload
//            --> counters (+ per-stream statistics, added in milestone 2).
//
// Design decision:
//   Every frame ends in exactly one bucket, so the counters always add up to
//   the number of records read. That invariant is easy to test and makes the
//   report trustworthy ("where did my packets go?").
#pragma once

#include <cstdint>
#include <istream>
#include <string>

#include "pcap_reader.hpp"

namespace rtpscope {

struct Counters {
    uint64_t frames = 0;         // pcap records read
    uint64_t rtp = 0;            // classified as RTP
    uint64_t rtcp = 0;           // RTCP (types 200-204), counted only
    uint64_t non_rtp_udp = 0;    // UDP that does not look like RTP
    uint64_t non_ipv4 = 0;       // ARP, IPv6, ...
    uint64_t non_udp = 0;        // IPv4 but TCP/ICMP/...
    uint64_t fragments = 0;      // IPv4 fragments skipped
    uint64_t malformed_net = 0;  // truncated/inconsistent Ethernet/IP/UDP headers
    uint64_t malformed_rtp = 0;  // looked like RTP but CSRC/ext/padding do not fit
    bool capture_truncated = false;  // file ended in the middle of a record
    bool capture_corrupt = false;    // implausible record length, stopped early

    uint64_t malformed() const { return malformed_net + malformed_rtp; }
};

class Analyzer {
public:
    // Reads a whole capture. Returns false (with `error` set) only for fatal
    // problems such as a bad header or unsupported link type; damaged records
    // are counted, not fatal.
    bool analyze(std::istream& in, std::string& error);

    const Counters& counters() const { return counters_; }
    uint32_t link_type() const { return link_type_; }
    bool nanosecond() const { return nano_; }

private:
    void handle_record(const PcapRecord& record);

    Counters counters_;
    uint32_t link_type_ = 0;
    bool nano_ = false;
};

}  // namespace rtpscope
