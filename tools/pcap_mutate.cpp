// pcap_mutate.cpp -- write a deterministically corrupted copy of a file.
//
// What it does: pcap_mutate IN OUT SEED applies the same mutation engine the
// unit test uses (tests/mutator.hpp) and saves the result, so scripts/fuzz.sh
// can feed damaged captures to the real rtp_scope executable.
// Data flow: IN file --> mutate(bytes, SEED) --> OUT file.
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "cli_args.hpp"
#include "mutator.hpp"

int main(int argc, char** argv) {
    uint64_t seed = 0;
    if (argc != 4 || !rtpscope::parse_uint(argv[3], seed)) {
        std::fputs("usage: pcap_mutate IN OUT SEED\n", stderr);
        return 2;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "pcap_mutate: cannot open '%s'\n", argv[1]);
        return 1;
    }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const std::vector<uint8_t> out = fuzz::mutate(bytes, seed);
    std::ofstream file(argv[2], std::ios::binary);
    file.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return file ? 0 : 1;
}
