// pcap_reader.hpp -- streaming reader for classic libpcap (.pcap) files.
//
// What it does:
//   Reads the 24-byte global header, works out byte order and timestamp
//   resolution from the magic number, then hands back one captured packet
//   record at a time.
//
// Where it sits in the data flow:
//   file (std::istream) --> PcapReader --> PcapRecord{timestamp, frame bytes}
//   --> net_decode (Ethernet/SLL, IPv4, UDP) --> RTP classification.
//
// Key concepts:
//   * The magic number doubles as a byte-order marker. A writer stores the
//     magic in *its own* byte order, so reading it as big-endian gives
//       a1b2c3d4 / a1b23c4d -> file is big-endian    (us / ns)
//       d4c3b2a1 / 4d3cb2a1 -> file is little-endian (us / ns)
//   * Only link types 0 (BSD loopback), 1 (Ethernet) and 113 (Linux cooked v1)
//     are accepted;
//     everything else is rejected with a clear message (we cannot find IP
//     without knowing the link layer).
//
// Design decision:
//   Records are *streamed* through one reusable buffer instead of loading the
//   file into memory, so memory use is O(max packet), not O(file size). That
//   matters for the 1M-packet benchmark and for large captures. A record's
//   data pointer is valid only until the next call to next().
#pragma once

#include <cstddef>
#include <cstdint>
#include <istream>
#include <string>
#include <vector>

namespace rtpscope {

constexpr uint32_t kLinkLoopback = 0;  // BSD loopback / "NULL": 4-byte address family, then IP
constexpr uint32_t kLinkEthernet = 1;
constexpr uint32_t kLinkLinuxSll = 113;

struct PcapRecord {
    uint64_t timestamp_ns = 0;      // capture time, nanoseconds since epoch
    uint32_t original_length = 0;   // length on the wire (may exceed captured)
    const uint8_t* data = nullptr;  // captured bytes
    size_t captured_length = 0;
};

class PcapReader {
public:
    enum class Next { Record, End, Truncated, Corrupt };

    explicit PcapReader(std::istream& in) : in_(in) {}

    // Reads and validates the global header. On failure returns false and
    // sets `error` to a human-readable reason.
    bool read_header(std::string& error);

    // Fetches the next record. Truncated = file ends mid-record (the records
    // read so far are still valid); Corrupt = implausible record length.
    Next next(PcapRecord& record);

    uint32_t link_type() const { return link_type_; }
    bool nanosecond() const { return nano_; }
    bool big_endian() const { return big_endian_; }

private:
    std::istream& in_;
    bool big_endian_ = false;
    bool nano_ = false;
    uint32_t link_type_ = 0;
    std::vector<uint8_t> buffer_;
};

const char* link_type_name(uint32_t link_type);

}  // namespace rtpscope
