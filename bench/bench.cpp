// bench.cpp -- throughput and memory benchmark of the parsing/analysis pipeline.
//
// What it does:
//   Given an existing pcap (scripts/bench.sh makes a 1M-packet one with
//   rtp_gen), it times two passes over the file and prints key=value lines:
//     parse    : pcap record reading + Ethernet/IPv4/UDP decode + RTP
//                classification and header parsing (no statistics)
//     analyze  : the full Analyzer (parse + sequence tracking + jitter + stats)
//   then the process's peak resident memory. scripts/bench.sh runs it five
//   times in fresh processes and reports the median.
//
// Where it sits: standalone tool, compiled with -O2 (see CMakeLists.txt) so the
// numbers do not depend on the build type chosen for the rest of the project.
//
// Design decisions:
//   * The capture is read from disk each pass but sits in the OS page cache
//     after bench.sh writes it, so the numbers measure the CPU-bound pipeline,
//     not the disk. A 1 MiB stream buffer keeps read syscalls out of the profile.
//   * Memory is the peak RSS (VmHWM from /proc/self/status, plus getrusage as a
//     cross-check). The pcap reader streams records, so it should stay small
//     and independent of the file size; that is what this verifies.
#include <sys/resource.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "analyzer.hpp"
#include "classify.hpp"
#include "net_decode.hpp"
#include "pcap_reader.hpp"

#ifndef BENCH_FLAGS
#define BENCH_FLAGS "unknown"
#endif

namespace {

using Clock = std::chrono::steady_clock;

double seconds_since(Clock::time_point t0) { return std::chrono::duration<double>(Clock::now() - t0).count(); }

// Peak resident set size in kB from /proc/self/status (Linux), or -1.
long vm_hwm_kb() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmHWM:", 0) == 0) return std::stol(line.substr(6));
    }
    return -1;
}

bool open_with_big_buffer(std::ifstream& f, std::vector<char>& buffer, const std::string& path) {
    buffer.resize(1 << 20);
    f.rdbuf()->pubsetbuf(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    f.open(path, std::ios::binary);
    return static_cast<bool>(f);
}

// Pass 1: decode only.
bool parse_pass(const std::string& path, uint64_t& frames, uint64_t& rtp, double& secs) {
    std::ifstream f;
    std::vector<char> buf;
    if (!open_with_big_buffer(f, buf, path)) return false;
    rtpscope::PcapReader reader(f);
    std::string err;
    if (!reader.read_header(err)) return false;
    const auto t0 = Clock::now();
    rtpscope::PcapRecord rec;
    while (reader.next(rec) == rtpscope::PcapReader::Next::Record) {
        ++frames;
        rtpscope::UdpDatagram udp;
        if (rtpscope::decode_frame(reader.link_type(), rec.data, rec.captured_length, udp) !=
            rtpscope::DecodeStatus::Udp) {
            continue;
        }
        rtpscope::RtpHeader h;
        if (rtpscope::classify_payload(udp.payload, udp.payload_length, h) == rtpscope::PacketClass::Rtp) ++rtp;
    }
    secs = seconds_since(t0);
    return true;
}

// Pass 2: the whole analyzer.
bool analyze_pass(const std::string& path, uint64_t& rtp, double& secs) {
    std::ifstream f;
    std::vector<char> buf;
    if (!open_with_big_buffer(f, buf, path)) return false;
    rtpscope::Analyzer analyzer;
    std::string err;
    const auto t0 = Clock::now();
    if (!analyzer.analyze(f, err)) return false;
    secs = seconds_since(t0);
    rtp = analyzer.counters().rtp;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fputs("usage: rtp_bench capture.pcap\n", stderr);
        return 2;
    }
    const std::string path = argv[1];
    std::ifstream size_probe(path, std::ios::binary | std::ios::ate);
    if (!size_probe) {
        std::fprintf(stderr, "rtp_bench: cannot open %s\n", path.c_str());
        return 1;
    }
    const double mbytes = static_cast<double>(size_probe.tellg()) / 1e6;

    uint64_t frames = 0, rtp_parse = 0, rtp_full = 0;
    double parse_s = 0, analyze_s = 0;
    if (!parse_pass(path, frames, rtp_parse, parse_s) || !analyze_pass(path, rtp_full, analyze_s)) {
        std::fputs("rtp_bench: pass failed\n", stderr);
        return 1;
    }
    if (rtp_parse != rtp_full) {
        std::fprintf(stderr, "rtp_bench: passes disagree (%llu vs %llu RTP packets)\n",
                     static_cast<unsigned long long>(rtp_parse), static_cast<unsigned long long>(rtp_full));
        return 1;
    }

    struct rusage ru {};
    getrusage(RUSAGE_SELF, &ru);
    std::printf("packets=%llu\n", static_cast<unsigned long long>(frames));
    std::printf("file_mb=%.3f\n", mbytes);
    std::printf("parse_seconds=%.4f\n", parse_s);
    std::printf("parse_pps=%.0f\n", static_cast<double>(frames) / parse_s);
    std::printf("parse_mbps=%.1f\n", mbytes / parse_s);
    std::printf("analyze_seconds=%.4f\n", analyze_s);
    std::printf("analyze_pps=%.0f\n", static_cast<double>(frames) / analyze_s);
    std::printf("analyze_mbps=%.1f\n", mbytes / analyze_s);
    std::printf("peak_rss_kb_proc=%ld\n", vm_hwm_kb());
    std::printf("peak_rss_kb_rusage=%ld\n", ru.ru_maxrss);
    std::printf("compiler=%s\n",
#if defined(__clang__)
                "clang " __clang_version__
#else
                "gcc " __VERSION__
#endif
    );
    std::printf("flags=%s\n", BENCH_FLAGS);
    return 0;
}
