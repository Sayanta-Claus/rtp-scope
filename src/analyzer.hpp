// analyzer.hpp -- drives a whole capture through the decode pipeline.
//
// What it does:
//   Reads every record of a pcap, decodes link/IP/UDP, classifies the UDP
//   payload and keeps counters for each outcome so nothing is silently lost:
//   RTP, RTCP, non-RTP UDP, non-IPv4, non-UDP, skipped fragments, malformed.
//
// Where it sits in the data flow:
//   istream --> PcapReader --> decode_frame --> classify_payload
//            --> counters + per-stream statistics (StreamStats).
//
// Design decision:
//   Every frame ends in exactly one bucket, so the counters always add up to
//   the number of records read. That invariant is easy to test and makes the
//   report trustworthy ("where did my packets go?").
#pragma once

#include <cstdint>
#include <istream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "classify.hpp"
#include "clock_rate.hpp"
#include "net_decode.hpp"
#include "pcap_reader.hpp"
#include "stream_stats.hpp"

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
    // keep_arrivals: store every packet's arrival for the jitter-buffer
    // simulator (costs ~32 bytes per packet, so it is opt-in).
    explicit Analyzer(const ClockRates& rates = ClockRates(), bool keep_arrivals = false)
        : rates_(rates), keep_arrivals_(keep_arrivals) {}

    // Reads a whole capture. Returns false (with `error` set) only for fatal
    // problems such as a bad header or unsupported link type; damaged records
    // are counted, not fatal.
    bool analyze(std::istream& in, std::string& error);

    const Counters& counters() const { return counters_; }
    uint32_t link_type() const { return link_type_; }
    bool nanosecond() const { return nano_; }

    // Streams in order of first appearance.
    const std::vector<std::unique_ptr<StreamStats>>& streams() const { return streams_; }

private:
    void handle_record(const PcapRecord& record);
    void handle_rtp(uint64_t timestamp_ns, const UdpDatagram& udp, const RtpHeader& header);

    ClockRates rates_;
    bool keep_arrivals_;
    std::vector<std::unique_ptr<StreamStats>> streams_;
    std::map<StreamKey, StreamStats*> index_;
    StreamStats* last_stream_ = nullptr;  // cache: consecutive packets usually share a stream
    Counters counters_;
    uint32_t link_type_ = 0;
    bool nano_ = false;
};

}  // namespace rtpscope
