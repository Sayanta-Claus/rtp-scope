// cli_args.cpp -- strict string -> number conversions.
//
// What it does: wraps strtoull/strtod and checks errno, the end pointer and
// the first character (strtoull would happily accept a leading '-', wrapping
// it to a huge unsigned value).
// Data flow: command-line text --> uint64_t / double.
#include "cli_args.hpp"

#include <cerrno>
#include <cmath>
#include <cstdlib>

namespace rtpscope {

bool parse_uint(const std::string& text, uint64_t& out) {
    if (text.empty() || text[0] == '-' || text[0] == '+' || text[0] == ' ') return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long v = std::strtoull(text.c_str(), &end, 0);  // base 0: decimal or 0x hex
    if (errno != 0 || end == text.c_str() || *end != '\0') return false;
    out = v;
    return true;
}

bool parse_double(const std::string& text, double& out) {
    if (text.empty() || text[0] == ' ') return false;
    errno = 0;
    char* end = nullptr;
    const double v = std::strtod(text.c_str(), &end);
    if (errno != 0 || end == text.c_str() || *end != '\0' || !std::isfinite(v)) return false;
    out = v;
    return true;
}

}  // namespace rtpscope
