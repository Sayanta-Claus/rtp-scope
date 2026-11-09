// rtp_scope.cpp -- command-line front end for the RTP analyzer.
//
// What it does:
//   Parses arguments, opens the pcap, runs the Analyzer and prints either a
//   text report (default) or JSON (--json).
//
// Data flow: argv --> Analyzer(file) --> report on stdout.
//
// Exit codes: 0 success, 1 runtime error (unreadable file, unsupported link
// type, bad pcap), 2 usage error. Diagnostics go to stderr so stdout stays
// clean for piping the report or JSON into other tools.
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "analyzer.hpp"
#include "clock_rate.hpp"
#include "report.hpp"

namespace {

void print_usage(std::FILE* to) {
    std::fputs(
        "usage: rtp_scope [options] capture.pcap\n"
        "\n"
        "  --json                 machine-readable JSON instead of the text report\n"
        "  --clock-rate PT=HZ     override the RTP clock rate of a payload type (repeatable)\n"
        "                         e.g. --clock-rate 96=90000 for H.264 video\n"
        "  -h, --help             show this help\n",
        to);
}

}  // namespace

int main(int argc, char** argv) {
    std::string path;
    bool json = false;
    rtpscope::ClockRates rates;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(stdout);
            return 0;
        } else if (arg == "--json") {
            json = true;
        } else if (arg == "--clock-rate") {
            std::string error;
            if (i + 1 >= argc || !rates.add_override(argv[++i], error)) {
                std::fprintf(stderr, "rtp_scope: %s\n", error.empty() ? "--clock-rate needs PT=HZ" : error.c_str());
                return 2;
            }
        } else if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "rtp_scope: unknown option '%s'\n", arg.c_str());
            print_usage(stderr);
            return 2;
        } else if (path.empty()) {
            path = arg;
        } else {
            std::fprintf(stderr, "rtp_scope: more than one input file given\n");
            return 2;
        }
    }
    if (path.empty()) {
        print_usage(stderr);
        return 2;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::fprintf(stderr, "rtp_scope: cannot open '%s'\n", path.c_str());
        return 1;
    }

    rtpscope::Analyzer analyzer(rates);
    std::string error;
    if (!analyzer.analyze(file, error)) {
        std::fprintf(stderr, "rtp_scope: %s: %s\n", path.c_str(), error.c_str());
        return 1;
    }

    if (json) rtpscope::print_json(std::cout, path, analyzer);
    else rtpscope::print_text(std::cout, path, analyzer);
    return 0;
}
