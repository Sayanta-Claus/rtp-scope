// report.cpp -- text table and hand-written JSON output.
//
// What it does: formats Analyzer results; no analysis happens here.
// Data flow: Analyzer --> std::ostream.
//
// JSON string escaping (RFC 8259 section 7): a string may not contain a raw
// quote, backslash or control character; they become \" \\ \n \t ... or \u00XX.
#include "report.hpp"

#include <cstdarg>
#include <cstdio>

namespace rtpscope {

namespace {

// printf into a std::string.
std::string fmt(const char* format, ...) __attribute__((format(printf, 1, 2)));
std::string fmt(const char* format, ...) {
    char buf[256];
    va_list args;
    va_start(args, format);
    std::vsnprintf(buf, sizeof buf, format, args);
    va_end(args);
    return buf;
}

std::string endpoint(uint32_t ip, uint16_t port) { return format_ipv4(ip) + ":" + std::to_string(port); }

const char* resolution(const Analyzer& a) { return a.nanosecond() ? "nanosecond" : "microsecond"; }

unsigned long long u(uint64_t v) { return static_cast<unsigned long long>(v); }

}  // namespace

std::string format_ipv4(uint32_t ip) {
    return fmt("%u.%u.%u.%u", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
}

std::string json_escape(const std::string& text) {
    std::string out;
    for (const char ch : text) {
        const unsigned char c = static_cast<unsigned char>(ch);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) out += fmt("\\u%04x", c);
                else out += ch;
        }
    }
    return out;
}

void print_text(std::ostream& out, const std::string& file, const Analyzer& a) {
    const Counters& c = a.counters();
    out << "rtp-scope: " << file << "\n";
    out << fmt("  link type          : %s (%u), %s timestamps\n", link_type_name(a.link_type()),
               a.link_type(), resolution(a));
    out << fmt("  frames in capture  : %llu\n", u(c.frames));
    out << fmt("  RTP / RTCP         : %llu / %llu\n", u(c.rtp), u(c.rtcp));
    out << fmt("  non-RTP UDP        : %llu\n", u(c.non_rtp_udp));
    out << fmt("  non-IPv4 / non-UDP : %llu / %llu\n", u(c.non_ipv4), u(c.non_udp));
    out << fmt("  IPv4 fragments     : %llu (skipped)\n", u(c.fragments));
    out << fmt("  malformed          : %llu (network %llu, rtp %llu)\n", u(c.malformed()),
               u(c.malformed_net), u(c.malformed_rtp));
    if (c.capture_truncated) out << "  warning: capture ends in the middle of a record (truncated file)\n";
    if (c.capture_corrupt) out << "  warning: implausible record length; stopped reading early\n";

    const auto& streams = a.streams();
    out << "\nstreams: " << streams.size() << "\n";
    if (streams.empty()) return;

    out << "\n" << fmt(" %-2s %-21s %-21s %-10s %-9s %8s %9s %9s\n", "#", "source", "destination", "SSRC",
                       "PT", "packets", "dur(s)", "kbps");
    int index = 0;
    for (const auto& sp : streams) {
        const StreamStats& s = *sp;
        const std::string pt = fmt("%u %s%s", s.payload_type(), payload_type_name(s.payload_type()),
                                   s.payload_type_changed() ? "*" : "");
        out << fmt(" %-2d %-21s %-21s 0x%08x %-9s %8llu %9.3f %9.2f\n", index++,
                   endpoint(s.key().src_ip, s.key().src_port).c_str(),
                   endpoint(s.key().dst_ip, s.key().dst_port).c_str(), s.key().ssrc, pt.c_str(),
                   u(s.packets()), s.duration_s(), s.bitrate_kbps());
    }

    out << "\n" << fmt(" %-2s %11s %9s %6s %7s %5s %5s %10s %10s\n", "#", "ext.highest", "expected", "lost",
                       "loss%", "dup", "ooo", "jitter(ts)", "jitter(ms)");
    index = 0;
    for (const auto& sp : streams) {
        const StreamStats& s = *sp;
        out << fmt(" %-2d %11lld %9llu %6llu %7.2f %5llu %5llu %10.2f %10.3f\n", index++,
                   static_cast<long long>(s.extended_highest()), u(s.expected()), u(s.lost()),
                   s.loss_percent(), u(s.duplicates()), u(s.out_of_order()), s.jitter_units(), s.jitter_ms());
    }
    out << "\n  dup = duplicate packets, ooo = out-of-order packets, jitter per RFC 3550 6.4.1\n";
    for (const auto& sp : streams) {
        if (sp->payload_type_changed()) {
            out << "  * payload type changed mid-stream; clock rate taken from the first packet\n";
            break;
        }
    }
    for (const auto& sp : streams) {
        if (sp->seq_rejected() > 0 || sp->seq_resyncs() > 0) {
            out << "  note: sequence discontinuities seen (see --json: seq_rejected / seq_resyncs)\n";
            break;
        }
    }
}

void print_simulation(std::ostream& out, size_t index, const StreamStats& s, const std::vector<SimResult>& results) {
    out << fmt("\njitter-buffer simulation, stream #%zu (%s -> %s, SSRC 0x%08x, %u Hz)\n", index,
               endpoint(s.key().src_ip, s.key().src_port).c_str(),
               endpoint(s.key().dst_ip, s.key().dst_port).c_str(), s.key().ssrc, s.clock_rate());
    if (results.empty()) return;
    out << fmt("  expected %llu packets; %llu never arrived (lost in the network)\n\n", u(results[0].expected),
               u(results[0].lost));
    out << fmt(" %-16s %8s %6s %6s %12s %13s %13s\n", "strategy", "played", "late", "lost", "late+lost %",
               "avg lat (ms)", "max lat (ms)");
    for (const SimResult& r : results) {
        out << fmt(" %-16s %8llu %6llu %6llu %12.2f %13.2f %13.2f\n", r.strategy.c_str(), u(r.played), u(r.late),
                   u(r.lost), r.late_or_lost_percent, r.avg_latency_ms, r.max_latency_ms);
    }
    out << "\n  late = arrived after its playout time (discarded); latency = time a played packet\n"
           "  waits in the buffer. Playout is scheduled relative to the first packet that arrived.\n";
}

void print_json(std::ostream& out, const std::string& file, const Analyzer& a) {
    const Counters& c = a.counters();
    out << "{\n";
    out << "  \"file\": \"" << json_escape(file) << "\",\n";
    out << fmt("  \"link_type\": %u,\n", a.link_type());
    out << "  \"timestamp_resolution\": \"" << resolution(a) << "\",\n";
    out << "  \"counters\": {\n";
    out << fmt("    \"frames\": %llu,\n", u(c.frames));
    out << fmt("    \"rtp\": %llu,\n", u(c.rtp));
    out << fmt("    \"rtcp\": %llu,\n", u(c.rtcp));
    out << fmt("    \"non_rtp_udp\": %llu,\n", u(c.non_rtp_udp));
    out << fmt("    \"non_ipv4\": %llu,\n", u(c.non_ipv4));
    out << fmt("    \"non_udp\": %llu,\n", u(c.non_udp));
    out << fmt("    \"ipv4_fragments_skipped\": %llu,\n", u(c.fragments));
    out << fmt("    \"malformed_network\": %llu,\n", u(c.malformed_net));
    out << fmt("    \"malformed_rtp\": %llu,\n", u(c.malformed_rtp));
    out << fmt("    \"capture_truncated\": %s,\n", c.capture_truncated ? "true" : "false");
    out << fmt("    \"capture_corrupt\": %s\n", c.capture_corrupt ? "true" : "false");
    out << "  },\n";
    out << "  \"streams\": [";
    bool first = true;
    for (const auto& sp : a.streams()) {
        const StreamStats& s = *sp;
        out << (first ? "\n" : ",\n");
        first = false;
        out << "    {\n";
        out << "      \"source\": \"" << json_escape(endpoint(s.key().src_ip, s.key().src_port)) << "\",\n";
        out << "      \"destination\": \"" << json_escape(endpoint(s.key().dst_ip, s.key().dst_port)) << "\",\n";
        out << fmt("      \"ssrc\": %u,\n", s.key().ssrc);
        out << fmt("      \"payload_type\": %u,\n", s.payload_type());
        out << "      \"payload_type_name\": \"" << json_escape(payload_type_name(s.payload_type())) << "\",\n";
        out << fmt("      \"payload_type_changed\": %s,\n", s.payload_type_changed() ? "true" : "false");
        out << fmt("      \"clock_rate\": %u,\n", s.clock_rate());
        out << fmt("      \"packets_received\": %llu,\n", u(s.packets()));
        out << fmt("      \"bytes\": %llu,\n", u(s.bytes()));
        out << fmt("      \"duration_s\": %.6f,\n", s.duration_s());
        out << fmt("      \"bitrate_kbps\": %.3f,\n", s.bitrate_kbps());
        out << fmt("      \"extended_highest_seq\": %lld,\n", static_cast<long long>(s.extended_highest()));
        out << fmt("      \"expected\": %llu,\n", u(s.expected()));
        out << fmt("      \"unique_received\": %llu,\n", u(s.unique_received()));
        out << fmt("      \"lost\": %llu,\n", u(s.lost()));
        out << fmt("      \"lost_rfc_signed\": %lld,\n", static_cast<long long>(s.lost_signed()));
        out << fmt("      \"loss_percent\": %.4f,\n", s.loss_percent());
        out << fmt("      \"duplicates\": %llu,\n", u(s.duplicates()));
        out << fmt("      \"out_of_order\": %llu,\n", u(s.out_of_order()));
        out << fmt("      \"seq_rejected\": %llu,\n", u(s.seq_rejected()));
        out << fmt("      \"seq_resyncs\": %llu,\n", u(s.seq_resyncs()));
        out << fmt("      \"jitter_rtp_units\": %.4f,\n", s.jitter_units());
        out << fmt("      \"jitter_ms\": %.4f\n", s.jitter_ms());
        out << "    }";
    }
    out << (first ? "]\n" : "\n  ]\n");
    out << "}\n";
}

}  // namespace rtpscope
