// analyzer.cpp -- the capture-level processing loop.
//
// What it does:
//   For each pcap record: decode_frame -> classify_payload -> bump exactly one
//   counter; RTP packets are additionally routed to their StreamStats.
//   Truncated or corrupt files stop the loop but keep the results.
//
// Data flow: istream --> PcapReader --> Counters + StreamStats per stream.
//
// Design decision:
//   A truncated final record is the *normal* result of killing tcpdump, so it
//   is a warning flag in Counters, not an error that discards the data.
#include "analyzer.hpp"

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
        case PacketClass::Rtp:
            ++counters_.rtp;
            handle_rtp(record.timestamp_ns, udp, header);
            break;
        case PacketClass::Rtcp: ++counters_.rtcp; break;
        case PacketClass::NotRtp: ++counters_.non_rtp_udp; break;
        case PacketClass::Malformed: ++counters_.malformed_rtp; break;
    }
}

void Analyzer::handle_rtp(uint64_t timestamp_ns, const UdpDatagram& udp, const RtpHeader& h) {
    StreamKey key;
    key.src_ip = udp.src_ip;
    key.dst_ip = udp.dst_ip;
    key.src_port = udp.src_port;
    key.dst_port = udp.dst_port;
    key.ssrc = h.ssrc;

    if (last_stream_ == nullptr || !(last_stream_->key() == key)) {
        auto it = index_.find(key);
        if (it == index_.end()) {
            streams_.push_back(std::make_unique<StreamStats>(
                key, h.payload_type, rates_.rate_for(h.payload_type), keep_arrivals_));
            it = index_.emplace(key, streams_.back().get()).first;
        }
        last_stream_ = it->second;
    }
    last_stream_->add_packet(timestamp_ns, h, udp.payload_length);
}

}  // namespace rtpscope
