// rtp_scope.cpp -- command-line front end for the RTP analyzer.
//
// What it does:
//   Parses arguments, opens the pcap, runs the Analyzer and prints a report.
//
// Data flow: argv --> Analyzer(file) --> text report on stdout.
//
// Exit codes: 0 success, 1 runtime error (unreadable file, unsupported link
// type, bad pcap), 2 usage error. Errors go to stderr so stdout stays clean
// for piping the report or JSON.
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

#include "analyzer.hpp"

namespace {

void print_usage() {
    std::fputs("usage: rtp_scope [options] capture.pcap\n", stderr);
}

}  // namespace

int main(int argc, char** argv) {
    std::string path;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage();
            return 0;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "rtp_scope: unknown option '%s'\n", arg.c_str());
            return 2;
        }
        path = arg;
    }
    if (path.empty()) {
        print_usage();
        return 2;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::fprintf(stderr, "rtp_scope: cannot open '%s'\n", path.c_str());
        return 1;
    }

    rtpscope::Analyzer analyzer;
    std::string error;
    if (!analyzer.analyze(file, error)) {
        std::fprintf(stderr, "rtp_scope: %s: %s\n", path.c_str(), error.c_str());
        return 1;
    }

    const rtpscope::Counters& c = analyzer.counters();
    std::printf("file          : %s\n", path.c_str());
    std::printf("link type     : %s (%u)\n", rtpscope::link_type_name(analyzer.link_type()), analyzer.link_type());
    std::printf("frames        : %llu\n", static_cast<unsigned long long>(c.frames));
    std::printf("RTP           : %llu\n", static_cast<unsigned long long>(c.rtp));
    std::printf("RTCP          : %llu\n", static_cast<unsigned long long>(c.rtcp));
    std::printf("non-RTP UDP   : %llu\n", static_cast<unsigned long long>(c.non_rtp_udp));
    std::printf("malformed     : %llu\n", static_cast<unsigned long long>(c.malformed()));
    return 0;
}
