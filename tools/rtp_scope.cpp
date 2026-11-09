// rtp_scope.cpp -- command-line front end for the RTP analyzer.
//
// What it does:
//   Parses arguments, opens the pcap, runs the Analyzer and prints either a
//   text report (default) or JSON (--json). With --simulate it also replays
//   one stream through fixed and adaptive jitter buffers; --sweep prints a CSV
//   of latency versus late-or-lost for many buffer settings instead.
//
// Data flow: argv --> Analyzer(file) --> report [--> jitter_buffer] on stdout.
//
// Exit codes: 0 success, 1 runtime error (unreadable file, unsupported link
// type, bad pcap, no stream to simulate), 2 usage error. Diagnostics go to
// stderr so stdout stays clean for piping the report, JSON or CSV.
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "analyzer.hpp"
#include "cli_args.hpp"
#include "clock_rate.hpp"
#include "jitter_buffer.hpp"
#include "report.hpp"

namespace {

void print_usage(std::FILE* to) {
    std::fputs(
        "usage: rtp_scope [options] capture.pcap\n"
        "\n"
        "  --json                 machine-readable JSON instead of the text report\n"
        "  --clock-rate PT=HZ     override the RTP clock rate of a payload type (repeatable)\n"
        "                         e.g. --clock-rate 96=90000 for H.264 video\n"
        "  --simulate             also replay a stream through fixed and adaptive jitter buffers\n"
        "  --sweep                print a CSV (strategy,avg_latency_ms,late_or_lost_pct) over many\n"
        "                         fixed delays and adaptive settings, instead of the report\n"
        "  --stream N             stream index for --simulate/--sweep (default: the largest)\n"
        "  --fixed-delay MS       fixed playout delay for --simulate (default 60)\n"
        "  --k K                  adaptive buffer safety factor: delay = mean + K * deviation (default 4)\n"
        "  -h, --help             show this help\n",
        to);
}

int usage_error(const std::string& message) {
    std::fprintf(stderr, "rtp_scope: %s\n", message.c_str());
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string path;
    bool json = false, simulate = false, sweep = false;
    bool stream_given = false;
    uint64_t stream_index = 0;
    double fixed_delay_ms = 60.0, k = 4.0;
    rtpscope::ClockRates rates;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&](std::string& v) {
            if (i + 1 >= argc) return false;
            v = argv[++i];
            return true;
        };
        std::string v;
        if (arg == "-h" || arg == "--help") {
            print_usage(stdout);
            return 0;
        } else if (arg == "--json") {
            json = true;
        } else if (arg == "--simulate") {
            simulate = true;
        } else if (arg == "--sweep") {
            sweep = true;
        } else if (arg == "--clock-rate") {
            std::string error;
            if (!next(v) || !rates.add_override(v, error)) {
                return usage_error(error.empty() ? "--clock-rate needs PT=HZ" : error);
            }
        } else if (arg == "--stream") {
            if (!next(v) || !rtpscope::parse_uint(v, stream_index)) return usage_error("--stream needs a number");
            stream_given = true;
        } else if (arg == "--fixed-delay") {
            if (!next(v) || !rtpscope::parse_double(v, fixed_delay_ms) || fixed_delay_ms < 0 || fixed_delay_ms > 10000) {
                return usage_error("--fixed-delay needs a number of milliseconds (0-10000)");
            }
        } else if (arg == "--k") {
            if (!next(v) || !rtpscope::parse_double(v, k) || k < 0 || k > 100) {
                return usage_error("--k needs a number between 0 and 100");
            }
        } else if (!arg.empty() && arg[0] == '-') {
            print_usage(stderr);
            return usage_error("unknown option '" + arg + "'");
        } else if (path.empty()) {
            path = arg;
        } else {
            return usage_error("more than one input file given");
        }
    }
    if (path.empty()) {
        print_usage(stderr);
        return 2;
    }
    if (json && (simulate || sweep)) return usage_error("--json cannot be combined with --simulate/--sweep");
    if (simulate && sweep) return usage_error("use either --simulate or --sweep, not both");

    // A 1 MiB stream buffer (set before open) keeps read() syscalls off the hot path.
    std::vector<char> io_buffer(1 << 20);
    std::ifstream file;
    file.rdbuf()->pubsetbuf(io_buffer.data(), static_cast<std::streamsize>(io_buffer.size()));
    file.open(path, std::ios::binary);
    if (!file) {
        std::fprintf(stderr, "rtp_scope: cannot open '%s'\n", path.c_str());
        return 1;
    }

    rtpscope::Analyzer analyzer(rates, /*keep_arrivals=*/simulate || sweep);
    std::string error;
    if (!analyzer.analyze(file, error)) {
        std::fprintf(stderr, "rtp_scope: %s: %s\n", path.c_str(), error.c_str());
        return 1;
    }

    if (!simulate && !sweep) {
        if (json) rtpscope::print_json(std::cout, path, analyzer);
        else rtpscope::print_text(std::cout, path, analyzer);
        return 0;
    }

    // ---- jitter-buffer modes: pick the stream ----
    const auto& streams = analyzer.streams();
    if (streams.empty()) {
        std::fprintf(stderr, "rtp_scope: no RTP stream found in '%s'\n", path.c_str());
        return 1;
    }
    size_t index = 0;
    if (stream_given) {
        if (stream_index >= streams.size()) return usage_error("--stream index out of range");
        index = static_cast<size_t>(stream_index);
    } else {
        for (size_t i = 1; i < streams.size(); ++i) {
            if (streams[i]->packets() > streams[index]->packets()) index = i;
        }
    }
    const rtpscope::StreamStats& stream = *streams[index];
    const rtpscope::PlayoutTrace trace = rtpscope::make_trace(stream);
    rtpscope::AdaptiveParams adaptive;
    adaptive.k = k;
    adaptive.initial_delay_ms = fixed_delay_ms;

    if (sweep) {
        std::cout << rtpscope::sweep_csv(trace, adaptive);
        return 0;
    }
    rtpscope::print_text(std::cout, path, analyzer);
    std::vector<rtpscope::SimResult> results;
    results.push_back(rtpscope::simulate_fixed(trace, fixed_delay_ms));
    results.push_back(rtpscope::simulate_adaptive(trace, adaptive));
    rtpscope::print_simulation(std::cout, index, stream, results);
    return 0;
}
