// traffic_model.hpp -- deterministic random numbers for the traffic generator.
//
// What it does:
//   A small PRNG (xoshiro256**, seeded through splitmix64) plus uniform and
//   normal samplers written by hand.
//
// Where it sits in the data flow:
//   seed --> Rng --> trace_gen (loss / jitter / reorder / duplicate decisions).
//
// Why not <random>?
//   The C++ standard fixes the *engines* (mt19937 etc.) but not the
//   *distributions*: std::normal_distribution and friends may give different
//   numbers on libstdc++, libc++ and MSVC for the same seed. The ground-truth
//   tests and published results must be reproducible everywhere, so the
//   sampling code is ours and only uses integer arithmetic plus std::log /
//   std::sqrt / std::cos.
//
// Design decision:
//   Several independent Rng instances (derived from one seed) are used for
//   loss, delay, reordering and duplication, so changing e.g. the loss
//   probability does not change the jitter values drawn for the same seed.
#pragma once

#include <cstdint>

namespace rtpscope {

class Rng {
public:
    // `stream` selects an independent sequence for the same seed.
    explicit Rng(uint64_t seed, uint64_t stream = 0);

    uint64_t next_u64();
    double uniform();  // in [0, 1), 53 bits of precision
    double normal();   // mean 0, standard deviation 1 (Box-Muller)

private:
    uint64_t s_[4];
    bool has_spare_ = false;
    double spare_ = 0.0;
};

}  // namespace rtpscope
