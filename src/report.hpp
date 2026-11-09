// report.hpp -- human-readable and JSON output of analysis results.
//
// What it does:
//   print_text() renders the capture counters plus two aligned tables (stream
//   identity, then stream quality). print_json() writes the same data as JSON
//   by hand: no library, so string escaping is done explicitly in json_escape().
//
// Where it sits in the data flow:
//   Analyzer (counters + StreamStats) --> report --> stdout.
//
// Design decisions:
//   * Text and JSON read from the same accessors, so they cannot disagree.
//   * JSON numbers are printed with fixed precision and never as nan/inf
//     (those are not valid JSON); integers stay integers (no 1e+06 surprises).
//   * json_escape handles the quote, the backslash and every control
//     character below 0x20 (as \u00XX), which is what RFC 8259 requires.
#pragma once

#include <ostream>
#include <string>

#include "analyzer.hpp"

namespace rtpscope {

// Dotted-quad text for a host-order IPv4 value.
std::string format_ipv4(uint32_t ip);

// JSON string-literal body escaping (does not add the surrounding quotes).
std::string json_escape(const std::string& text);

void print_text(std::ostream& out, const std::string& file, const Analyzer& analyzer);
void print_json(std::ostream& out, const std::string& file, const Analyzer& analyzer);

}  // namespace rtpscope
