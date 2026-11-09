// analyzer.cpp -- the capture-level processing loop.
//
// What it does:
//   For each pcap record: decode_frame -> classify_payload -> bump exactly one
//   counter; RTP-looking packets are additionally routed to their StreamStats.
//   After the last record, streams that never showed consecutive sequence
//   numbers are dropped and their packets are re-counted as non-RTP.
//   Truncated or corrupt files stop the loop but keep the results.
//
// Data flow: istream --> PcapReader --> Counters + StreamStats per stream.
//
// Design decisions:
//   * A truncated final record is the *normal* result of killing tcpdump, so it
//     is a warning flag in Counters, not an error that discards the data.
//   * Real captures are full of UDP that merely resembles RTP (DNS and NetBIOS
//     queries have a random first byte, so 1 in 4 has "version 2"). Two cheap
//     defences, both visible in the counters: (1) ports reserved for other
//     well-known protocols are never treated as RTP, the same priority
//     Wireshark gives a port-assigned dissector; (2) a stream is only reported
//     if it shows two consecutive sequence numbers (RFC 3550 A.1 "probation",
//     MIN_SEQUENTIAL = 2). Confirmation is judged at the end so that no early
//     packet of a real stream is lost from its totals.
//   * The number of distinct streams is capped so a flood of random-looking UDP
//     (each with a different "SSRC") cannot use unbounded memory.
#include "analyzer.hpp"

namespace rtpscope {

namespace {

constexpr size_t kMaxStreams = 100000;

// UDP ports of other well-known protocols whose payloads can look like RTP by
// accident. RTP on one of these ports would be missed (documented limitation).
bool is_other_protocol_port(uint16_t port) {
    switch (port) {
        case 53:    // DNS
        case 67:    // DHCP/BOOTP
        case 68:
        case 123:   // NTP
        case 137:   // NetBIOS name service
        case 138:   // NetBIOS datagram
        case 161:   // SNMP
        case 162:
        case 514:   // syslog
        case 1900:  // SSDP
        case 5353:  // mDNS
        case 5355:  // LLMNR
            return true;
        default:
            return false;
    }
}

}  // namespace

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
    drop_unconfirmed_streams();
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
    if (is_other_protocol_port(udp.src_port) || is_other_protocol_port(udp.dst_port)) {
        ++counters_.non_rtp_udp;
        return;
    }

    RtpHeader header;
    switch (classify_payload(udp.payload, udp.payload_length, header)) {
        case PacketClass::Rtp:
            if (handle_rtp(record.timestamp_ns, udp, header)) {
                ++counters_.rtp;
            } else {
                ++counters_.non_rtp_udp;
                counters_.streams_capped = true;
            }
            break;
        case PacketClass::Rtcp: ++counters_.rtcp; break;
        case PacketClass::NotRtp: ++counters_.non_rtp_udp; break;
        case PacketClass::Malformed: ++counters_.malformed_rtp; break;
    }
}

bool Analyzer::handle_rtp(uint64_t timestamp_ns, const UdpDatagram& udp, const RtpHeader& h) {
    StreamKey key;
    key.src_ip = udp.src_ip;
    key.dst_ip = udp.dst_ip;
    key.src_port = udp.src_port;
    key.dst_port = udp.dst_port;
    key.ssrc = h.ssrc;

    if (last_stream_ == nullptr || !(last_stream_->key() == key)) {
        auto it = index_.find(key);
        if (it == index_.end()) {
            if (streams_.size() >= kMaxStreams) return false;
            streams_.push_back(std::make_unique<StreamStats>(
                key, h.payload_type, rates_.rate_for(h.payload_type), keep_arrivals_));
            it = index_.emplace(key, streams_.back().get()).first;
        }
        last_stream_ = it->second;
    }
    last_stream_->add_packet(timestamp_ns, h, udp.payload_length);
    return true;
}

void Analyzer::drop_unconfirmed_streams() {
    std::vector<std::unique_ptr<StreamStats>> kept;
    for (auto& s : streams_) {
        if (s->confirmed()) {
            kept.push_back(std::move(s));
        } else {
            counters_.rtp -= s->packets();
            counters_.non_rtp_udp += s->packets();
            counters_.rtp_unconfirmed += s->packets();
            index_.erase(s->key());
        }
    }
    streams_ = std::move(kept);
    last_stream_ = nullptr;
}

}  // namespace rtpscope
