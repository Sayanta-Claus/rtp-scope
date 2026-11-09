// mutator.hpp -- deterministic byte-level corruption of a pcap file.
//
// What it does:
//   mutate(bytes, seed) returns a damaged copy of a valid capture. The same
//   (bytes, seed) always gives the same result, so any failure found is
//   reproducible from its seed number alone.
//
// Where it sits: used by tests/test_mutation.cpp (in-process, under the
// sanitizers in ctest) and tools/pcap_mutate.cpp (writes the damaged file so
// scripts/fuzz.sh can feed the real rtp_scope executable).
//
// Mutation kinds (chosen from the seed):
//   bit flips, random byte overwrites, truncation at an arbitrary offset,
//   deleting a chunk, inserting random bytes, setting a 16/32-bit field to an
//   extreme value (0, 0xffff..., 0x7fff...), and combinations of these.
//   Half of all edit positions fall in the first 256 bytes, where the pcap
//   header, the first record header and the first Ethernet/IP/UDP/RTP headers
//   live, since damage there exercises the parsers hardest.
#pragma once

#include <cstdint>
#include <vector>

#include "traffic_model.hpp"

namespace fuzz {

inline size_t pick_offset(rtpscope::Rng& rng, size_t size) {
    if (size == 0) return 0;
    const size_t span = (rng.uniform() < 0.5 && size > 256) ? 256 : size;
    return static_cast<size_t>(rng.next_u64() % span);
}

inline void apply_one(std::vector<uint8_t>& b, rtpscope::Rng& rng, unsigned kind) {
    if (b.empty()) return;
    switch (kind) {
        case 0: {  // bit flips
            const unsigned n = 1 + static_cast<unsigned>(rng.next_u64() % 16);
            for (unsigned i = 0; i < n; ++i) b[pick_offset(rng, b.size())] ^= static_cast<uint8_t>(1u << (rng.next_u64() % 8));
            break;
        }
        case 1: {  // random byte overwrites
            const unsigned n = 1 + static_cast<unsigned>(rng.next_u64() % 32);
            for (unsigned i = 0; i < n; ++i) b[pick_offset(rng, b.size())] = static_cast<uint8_t>(rng.next_u64());
            break;
        }
        case 2:  // truncate anywhere, including inside headers
            b.resize(static_cast<size_t>(rng.next_u64() % (b.size() + 1)));
            break;
        case 3: {  // delete a chunk
            const size_t at = pick_offset(rng, b.size());
            const size_t len = 1 + static_cast<size_t>(rng.next_u64() % 64);
            const size_t end = at + len > b.size() ? b.size() : at + len;
            b.erase(b.begin() + static_cast<long>(at), b.begin() + static_cast<long>(end));
            break;
        }
        case 4: {  // insert random bytes
            const size_t at = pick_offset(rng, b.size());
            const size_t len = 1 + static_cast<size_t>(rng.next_u64() % 64);
            std::vector<uint8_t> junk(len);
            for (auto& x : junk) x = static_cast<uint8_t>(rng.next_u64());
            b.insert(b.begin() + static_cast<long>(at), junk.begin(), junk.end());
            break;
        }
        default: {  // extreme 16/32-bit values
            static const uint32_t extremes[] = {0u, 0xffffffffu, 0x7fffffffu, 0x80000000u, 0xffffu, 1u};
            const uint32_t v = extremes[rng.next_u64() % 6];
            const size_t at = pick_offset(rng, b.size());
            const unsigned width = (rng.next_u64() & 1) ? 4 : 2;
            for (unsigned i = 0; i < width && at + i < b.size(); ++i) b[at + i] = static_cast<uint8_t>(v >> (8 * i));
            break;
        }
    }
}

inline std::vector<uint8_t> mutate(std::vector<uint8_t> bytes, uint64_t seed) {
    rtpscope::Rng rng(seed, 0x6d7574);
    const unsigned rounds = rng.uniform() < 0.3 ? 2 + static_cast<unsigned>(rng.next_u64() % 2) : 1;
    for (unsigned r = 0; r < rounds; ++r) apply_one(bytes, rng, static_cast<unsigned>(rng.next_u64() % 6));
    return bytes;
}

}  // namespace fuzz
