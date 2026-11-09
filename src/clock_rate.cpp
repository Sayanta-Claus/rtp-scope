// clock_rate.cpp -- static payload type table and --clock-rate overrides.
//
// What it does: table lookup (RFC 3551 section 6) with user overrides on top.
// Data flow: payload type (7 bits) --> Hz.
#include "clock_rate.hpp"

#include "cli_args.hpp"

namespace rtpscope {

namespace {

struct PtInfo {
    uint8_t pt;
    const char* name;
    uint32_t rate;
};

// RFC 3551 table 4 (audio) and table 5 (video).
constexpr PtInfo kTable[] = {
    {0, "PCMU", 8000},  {3, "GSM", 8000},   {4, "G723", 8000},  {5, "DVI4", 8000},
    {6, "DVI4", 16000}, {7, "LPC", 8000},   {8, "PCMA", 8000},  {9, "G722", 8000},
    {10, "L16", 44100}, {11, "L16", 44100}, {12, "QCELP", 8000}, {13, "CN", 8000},
    {14, "MPA", 90000}, {15, "G728", 8000}, {16, "DVI4", 11025}, {17, "DVI4", 22050},
    {18, "G729", 8000}, {25, "CelB", 90000}, {26, "JPEG", 90000}, {28, "nv", 90000},
    {31, "H261", 90000}, {32, "MPV", 90000}, {33, "MP2T", 90000}, {34, "H263", 90000},
};

constexpr uint32_t kDefaultRate = 48000;

const PtInfo* find(uint8_t pt) {
    for (const PtInfo& e : kTable) {
        if (e.pt == pt) return &e;
    }
    return nullptr;
}

}  // namespace

bool ClockRates::add_override(const std::string& spec, std::string& error) {
    const size_t eq = spec.find('=');
    uint64_t pt = 0, hz = 0;
    if (eq == std::string::npos || !parse_uint(spec.substr(0, eq), pt) ||
        !parse_uint(spec.substr(eq + 1), hz) || pt > 127 || hz == 0 || hz > 1000000) {
        error = "bad --clock-rate '" + spec + "' (expected PT=HZ, PT 0-127, HZ 1-1000000)";
        return false;
    }
    overrides_[static_cast<uint8_t>(pt)] = static_cast<uint32_t>(hz);
    return true;
}

uint32_t ClockRates::rate_for(uint8_t payload_type) const {
    const auto it = overrides_.find(payload_type);
    if (it != overrides_.end()) return it->second;
    const PtInfo* e = find(payload_type);
    return e ? e->rate : kDefaultRate;
}

const char* payload_type_name(uint8_t payload_type) {
    const PtInfo* e = find(payload_type);
    if (e) return e->name;
    return payload_type >= 96 ? "dynamic" : "other";
}

}  // namespace rtpscope
