// cli_args.hpp -- strict number parsing shared by the command-line tools.
//
// What it does:
//   parse_uint / parse_double accept a string only if the *entire* string is a
//   valid number (no trailing junk, no empty string, no overflow). std::stoi
//   and atoi silently accept "12abc" or return 0 for garbage, which hides typos
//   in command lines.
//
// Where it sits: used by rtp_scope, rtp_gen and ClockRates::add_override.
// Accepts decimal and 0x-prefixed hexadecimal integers (handy for SSRCs).
#pragma once

#include <cstdint>
#include <string>

namespace rtpscope {

bool parse_uint(const std::string& text, uint64_t& out);
bool parse_double(const std::string& text, double& out);

}  // namespace rtpscope
