// traffic_model.cpp -- xoshiro256** generator and samplers.
//
// What it does:
//   splitmix64 expands the 64-bit seed into the 256-bit xoshiro state (the
//   seeding method recommended by the xoshiro authors); xoshiro256** then
//   produces 64-bit outputs; the top 53 bits become a double in [0,1).
//
// Data flow: (seed, stream) --> next_u64() --> uniform() / normal().
//
// Box-Muller: if U1, U2 are uniform in (0,1] then
//   Z0 = sqrt(-2 ln U1) cos(2 pi U2),  Z1 = sqrt(-2 ln U1) sin(2 pi U2)
// are two independent standard-normal values; the second is cached.
#include "traffic_model.hpp"

#include <cmath>

namespace rtpscope {

namespace {

uint64_t splitmix64(uint64_t& x) {
    uint64_t z = (x += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

}  // namespace

Rng::Rng(uint64_t seed, uint64_t stream) {
    uint64_t x = seed ^ (stream * 0xd1342543de82ef95ull);
    for (uint64_t& word : s_) word = splitmix64(x);
}

uint64_t Rng::next_u64() {
    const uint64_t result = rotl(s_[1] * 5, 7) * 9;
    const uint64_t t = s_[1] << 17;
    s_[2] ^= s_[0];
    s_[3] ^= s_[1];
    s_[1] ^= s_[2];
    s_[0] ^= s_[3];
    s_[2] ^= t;
    s_[3] = rotl(s_[3], 45);
    return result;
}

double Rng::uniform() { return static_cast<double>(next_u64() >> 11) * (1.0 / 9007199254740992.0); }

double Rng::normal() {
    if (has_spare_) {
        has_spare_ = false;
        return spare_;
    }
    const double u1 = 1.0 - uniform();  // (0, 1] so that log(u1) is finite
    const double u2 = uniform();
    const double radius = std::sqrt(-2.0 * std::log(u1));
    const double angle = 2.0 * 3.14159265358979323846 * u2;
    spare_ = radius * std::sin(angle);
    has_spare_ = true;
    return radius * std::cos(angle);
}

}  // namespace rtpscope
