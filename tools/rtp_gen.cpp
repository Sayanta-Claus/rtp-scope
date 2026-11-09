// rtp_gen.cpp -- command-line synthetic RTP traffic generator.
//
// What it does:
//   Builds a GenConfig from the command line, runs generate_trace() and writes
//   a .pcap (Ethernet or Linux-SLL / IPv4 / UDP / RTP) plus a plain-text
//   ground-truth sidecar (key=value lines) describing exactly what happened.
//
// Data flow: argv --> GenConfig --> trace_gen --> out.pcap + out.pcap.truth.
//
// The same seed and options always produce byte-identical files, which is what
// makes the generated traces usable as test oracles.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#include "cli_args.hpp"
#include "trace_gen.hpp"

using rtpscope::GenConfig;

namespace {

void print_usage(std::FILE* to) {
    std::fputs(
        "usage: rtp_gen --out FILE.pcap [options]\n"
        "\n"
        "  --out FILE            output pcap (required)\n"
        "  --truth FILE          ground-truth file (default: FILE.truth)\n"
        "  --duration S          seconds of audio to generate (default 10)\n"
        "  --packets N           send exactly N packets (overrides --duration)\n"
        "  --interval-ms MS      packet interval (default 20)\n"
        "  --pt N                payload type 0-127 (default 0 = PCMU)\n"
        "  --clock-rate HZ       RTP clock rate (default: from payload type)\n"
        "  --ssrc N              SSRC, decimal or 0x hex (default 0x11223344)\n"
        "  --seed N              random seed (default 1)\n"
        "  --loss P              packet loss probability 0..1\n"
        "  --jitter-ms MS        network jitter amount (default 0)\n"
        "  --jitter-dist D       uniform (U[0,J]) or normal (|N(0,J)|) (default uniform)\n"
        "  --base-delay-ms MS    fixed one-way delay (default 20)\n"
        "  --reorder P           probability a packet swaps with its successor\n"
        "  --duplicate P         probability a packet is duplicated\n"
        "  --start-seq N         first sequence number (default 100)\n"
        "  --wrap                start near 65535 so the sequence number wraps (= --start-seq 65500)\n"
        "  --start-ts N          first RTP timestamp (default 1000000)\n"
        "  --payload-bytes N     RTP payload size (default 160)\n"
        "  --talk-on-ms MS --talk-off-ms MS   talkspurt/silence cycle (marker bit set at spurt start)\n"
        "  --nano                write a nanosecond-resolution pcap\n"
        "  --big-endian          write a big-endian pcap\n"
        "  --vlan                add an 802.1Q tag\n"
        "  --sll                 use Linux cooked (SLL) framing\n",
        to);
}

bool fail(const std::string& msg) {
    std::fprintf(stderr, "rtp_gen: %s\n", msg.c_str());
    return false;
}

// Parses argv into config; returns false after printing a message on error.
bool parse_args(int argc, char** argv, GenConfig& c, std::string& out_path, std::string& truth_path) {
    for (int i = 1; i < argc; ++i) {
        const std::string opt = argv[i];
        auto value = [&](std::string& v) {
            if (i + 1 >= argc) return fail("missing value for " + opt);
            v = argv[++i];
            return true;
        };
        auto number = [&](double& d, double lo, double hi) {
            std::string v;
            if (!value(v)) return false;
            if (!rtpscope::parse_double(v, d) || d < lo || d > hi) return fail("bad value for " + opt + ": '" + v + "'");
            return true;
        };
        auto integer = [&](uint64_t& n, uint64_t hi) {
            std::string v;
            if (!value(v)) return false;
            if (!rtpscope::parse_uint(v, n) || n > hi) return fail("bad value for " + opt + ": '" + v + "'");
            return true;
        };

        std::string s;
        uint64_t n = 0;
        if (opt == "--out") { if (!value(out_path)) return false; }
        else if (opt == "--truth") { if (!value(truth_path)) return false; }
        else if (opt == "--duration") { if (!number(c.duration_s, 0.001, 1e6)) return false; }
        else if (opt == "--packets") { if (!integer(c.packets, 100000000ull)) return false; }
        else if (opt == "--interval-ms") { if (!number(c.interval_ms, 0.001, 1e5)) return false; }
        else if (opt == "--pt") { if (!integer(n, 127)) return false; c.payload_type = static_cast<uint8_t>(n); }
        else if (opt == "--clock-rate") { if (!integer(n, 1000000)) return false; c.clock_rate = static_cast<uint32_t>(n); }
        else if (opt == "--ssrc") { if (!integer(n, 0xffffffffull)) return false; c.ssrc = static_cast<uint32_t>(n); }
        else if (opt == "--seed") { if (!integer(c.seed, ~0ull)) return false; }
        else if (opt == "--loss") { if (!number(c.loss, 0, 1)) return false; }
        else if (opt == "--jitter-ms") { if (!number(c.jitter_ms, 0, 1e5)) return false; }
        else if (opt == "--jitter-dist") {
            if (!value(s)) return false;
            if (s == "uniform") c.jitter_distribution = rtpscope::JitterDistribution::Uniform;
            else if (s == "normal") c.jitter_distribution = rtpscope::JitterDistribution::Normal;
            else return fail("--jitter-dist must be 'uniform' or 'normal'");
        }
        else if (opt == "--base-delay-ms") { if (!number(c.base_delay_ms, 0, 1e5)) return false; }
        else if (opt == "--reorder") { if (!number(c.reorder, 0, 1)) return false; }
        else if (opt == "--duplicate") { if (!number(c.duplicate, 0, 1)) return false; }
        else if (opt == "--start-seq") { if (!integer(n, 65535)) return false; c.start_seq = static_cast<uint16_t>(n); }
        else if (opt == "--wrap") { c.start_seq = 65500; }
        else if (opt == "--start-ts") { if (!integer(n, 0xffffffffull)) return false; c.start_timestamp = static_cast<uint32_t>(n); }
        else if (opt == "--payload-bytes") { if (!integer(n, 1400)) return false; c.payload_bytes = static_cast<size_t>(n); }
        else if (opt == "--talk-on-ms") { if (!number(c.talk_on_ms, 0, 1e7)) return false; }
        else if (opt == "--talk-off-ms") { if (!number(c.talk_off_ms, 0, 1e7)) return false; }
        else if (opt == "--nano") { c.nanosecond = true; }
        else if (opt == "--big-endian") { c.big_endian = true; }
        else if (opt == "--vlan") { c.vlan = true; }
        else if (opt == "--sll") { c.sll = true; }
        else if (opt == "-h" || opt == "--help") { print_usage(stdout); std::exit(0); }
        else { return fail("unknown option '" + opt + "'"); }
    }
    if (out_path.empty()) return fail("--out is required");
    if (c.sll && c.vlan) return fail("--sll and --vlan cannot be combined");
    if (truth_path.empty()) truth_path = out_path + ".truth";
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    GenConfig config;
    std::string out_path, truth_path;
    if (!parse_args(argc, argv, config, out_path, truth_path)) {
        print_usage(stderr);
        return 2;
    }

    std::vector<rtpscope::GeneratedPacket> arrivals;
    rtpscope::GroundTruth truth;
    rtpscope::generate_trace(config, arrivals, truth);

    std::ofstream pcap(out_path, std::ios::binary);
    if (!pcap) {
        std::fprintf(stderr, "rtp_gen: cannot write '%s'\n", out_path.c_str());
        return 1;
    }
    rtpscope::write_trace_pcap(config, arrivals, pcap);
    pcap.close();
    if (!pcap) {
        std::fprintf(stderr, "rtp_gen: error while writing '%s'\n", out_path.c_str());
        return 1;
    }

    std::ofstream sidecar(truth_path);
    sidecar << rtpscope::truth_to_text(config, truth);
    sidecar.close();
    if (!sidecar) {
        std::fprintf(stderr, "rtp_gen: cannot write '%s'\n", truth_path.c_str());
        return 1;
    }

    std::printf("wrote %s (%llu packets in capture) and %s\n", out_path.c_str(),
                static_cast<unsigned long long>(truth.received), truth_path.c_str());
    return 0;
}
