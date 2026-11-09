// analyzer.cpp -- the capture-level processing loop.
//
// What it does:
//   For each pcap record: decode_frame -> classify_payload -> bump exactly one
//   counter. Truncated or corrupt files stop the loop but keep the results.
//
// Data flow: istream --> PcapReader --> Counters.
//
// Design decision:
//   A truncated final record is the *normal* result of killing tcpdump, so it
//   is a warning flag in Counters, not an error that discards the data.
#include "analyzer.hpp"

#include "classify.hpp"
#include "net_decode.hpp"

namespace rtpscope {

bool Analyzer::analyze(std::istream& in, std::string& error) {
    PcapReader reader(in);
    if (!reader.read_header(error)) return false;
    link_type_ = reader.link_type();
    nano_ = reader.nanosecond();

    PcapRecord record;
    for (;;) {
        const PcapReader::Next status = reader.next(record);
        if (status == PcapReader::Next::End) break;
        if (status == PcapReader::Next::Truncated) {
            counters_.capture_truncated = true;
            break;
        }
        if (status == PcapReader::Next::Corrupt) {
            counters_.capture_corrupt = true;
            break;
        }
        handle_record(record);
    }
    return true;
}

void Analyzer::handle_record(const PcapRecord& record) {
    ++counters_.frames;

    UdpDatagram udp;
    switch (decode_frame(link_type_, record.data, record.captured_length, udp)) {
        case DecodeStatus::NotIpv4: ++counters_.non_ipv4; return;
        case DecodeStatus::NotUdp: ++counters_.non_udp; return;
        case DecodeStatus::Fragment: ++counters_.fragments; return;
        case DecodeStatus::Malformed: ++counters_.malformed_net; return;
        case DecodeStatus::Udp: break;
    }

    RtpHeader header;
    switch (classify_payload(udp.payload, udp.payload_length, header)) {
        case PacketClass::Rtp: ++counters_.rtp; break;
        case PacketClass::Rtcp: ++counters_.rtcp; break;
        case PacketClass::NotRtp: ++counters_.non_rtp_udp; break;
        case PacketClass::Malformed: ++counters_.malformed_rtp; break;
    }
}

}  // namespace rtpscope
