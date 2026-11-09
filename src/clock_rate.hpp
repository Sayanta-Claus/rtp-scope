// clock_rate.hpp -- payload type -> RTP timestamp clock rate (Hz).
//
// What it does:
//   Jitter and bitrate-per-second maths need to know how fast the RTP
//   timestamp ticks. That rate is a property of the payload format, not of the
//   packet, so we look it up from the payload type (RFC 3551 table 4/5) and
//   allow the user to override it with --clock-rate PT=HZ.
//
// Where it sits in the data flow:
//   RtpHeader.payload_type --> ClockRates::rate_for() --> StreamStats / jitter
//   buffer.
//
// Defaults worth remembering:
//   * PCMU(0), PCMA(8): 8000.  G722(9): the timestamp clock is 8000 even though
//     the audio is sampled at 16 kHz (a famous historical erratum in RFC 3551).
//   * L16 stereo/mono (10, 11): 44100.  Video static types (JPEG, H261, MPV...): 90000.
//   * Dynamic types (96-127), e.g. Opus: 48000 (Opus always uses 48 kHz).
//     Dynamic types are negotiated out of band (SDP), so a guess is unavoidable;
//     for video such as H.264 use --clock-rate 96=90000.
//   * Anything not in the table also defaults to 48000.
#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace rtpscope {

class ClockRates {
public:
    // Parses "PT=HZ" (e.g. "96=90000"). On failure returns false and sets error.
    bool add_override(const std::string& spec, std::string& error);

    uint32_t rate_for(uint8_t payload_type) const;

private:
    std::map<uint8_t, uint32_t> overrides_;
};

// Short name for display ("PCMU", "G722", ...); "dynamic" or "unassigned" otherwise.
const char* payload_type_name(uint8_t payload_type);

}  // namespace rtpscope
