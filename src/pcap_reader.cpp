// pcap_reader.cpp -- implementation of the classic pcap file reader.
//
// What it does:
//   Parses the global header (magic, version, snaplen, link type) and then
//   each per-packet record header (ts_sec, ts_frac, incl_len, orig_len).
//
// Data flow:
//   bytes in an istream --> ByteReader (explicit endianness) --> PcapRecord.
//
// Format reference (libpcap "pcap-savefile"):
//   global header, 24 bytes: magic(4) ver_major(2) ver_minor(2) thiszone(4)
//                            sigfigs(4) snaplen(4) network(4)
//   record header, 16 bytes: ts_sec(4) ts_frac(4) incl_len(4) orig_len(4)
//   ts_frac is microseconds for magic a1b2c3d4, nanoseconds for a1b23c4d.
//
// Design decisions:
//   * incl_len is attacker-controlled. We refuse anything above kMaxRecord
//     (16 MiB) before allocating, so a corrupt length cannot cause a huge
//     allocation or a long blocking read.
//   * Header read and record read use fixed small stack arrays plus
//     ByteReader, so there is no struct overlay anywhere.
#include "pcap_reader.hpp"

#include <algorithm>
#include <array>

#include "byte_reader.hpp"

namespace rtpscope {

namespace {

constexpr size_t kGlobalHeaderSize = 24;
constexpr size_t kRecordHeaderSize = 16;
constexpr uint32_t kMaxRecord = 16u * 1024u * 1024u;
constexpr size_t kReadChunk = 64u * 1024u;

// Reads exactly n bytes; false if the stream ends first.
bool read_exact(std::istream& in, uint8_t* dst, size_t n) {
    in.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n));
    return static_cast<size_t>(in.gcount()) == n;
}

}  // namespace

const char* link_type_name(uint32_t link_type) {
    switch (link_type) {
        case kLinkEthernet: return "Ethernet";
        case kLinkLinuxSll: return "Linux cooked (SLL)";
        default: return "unsupported";
    }
}

bool PcapReader::read_header(std::string& error) {
    std::array<uint8_t, kGlobalHeaderSize> raw{};
    if (!read_exact(in_, raw.data(), raw.size())) {
        error = "file is too short to be a pcap file (global header incomplete)";
        return false;
    }
    ByteReader r(raw.data(), raw.size());

    // Read the magic as big-endian; the four possible values tell us both the
    // file's byte order and its timestamp resolution.
    uint32_t magic = 0;
    r.read_u32(Endian::Big, magic);
    switch (magic) {
        case 0xa1b2c3d4u: big_endian_ = true;  nano_ = false; break;
        case 0xa1b23c4du: big_endian_ = true;  nano_ = true;  break;
        case 0xd4c3b2a1u: big_endian_ = false; nano_ = false; break;
        case 0x4d3cb2a1u: big_endian_ = false; nano_ = true;  break;
        default:
            error = "not a classic pcap file (bad magic number; pcapng is not supported)";
            return false;
    }
    const Endian e = big_endian_ ? Endian::Big : Endian::Little;

    uint16_t ver_major = 0, ver_minor = 0;
    uint32_t thiszone = 0, sigfigs = 0, snaplen = 0, network = 0;
    r.read_u16(e, ver_major);
    r.read_u16(e, ver_minor);
    r.read_u32(e, thiszone);
    r.read_u32(e, sigfigs);
    r.read_u32(e, snaplen);
    r.read_u32(e, network);
    if (ver_major != 2) {
        error = "unsupported pcap version " + std::to_string(ver_major) + "." +
                std::to_string(ver_minor);
        return false;
    }

    // The top bits of the field carry FCS/other flags in newer libpcap; the
    // link type itself is the low 28 bits.
    link_type_ = network & 0x0fffffffu;
    if (link_type_ != kLinkEthernet && link_type_ != kLinkLinuxSll) {
        error = "unsupported link type " + std::to_string(link_type_) +
                " (supported: 1 = Ethernet, 113 = Linux cooked SLL)";
        return false;
    }
    return true;
}

PcapReader::Next PcapReader::next(PcapRecord& record) {
    std::array<uint8_t, kRecordHeaderSize> raw{};
    in_.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    const size_t got = static_cast<size_t>(in_.gcount());
    if (got == 0) return Next::End;
    if (got < raw.size()) return Next::Truncated;

    const Endian e = big_endian_ ? Endian::Big : Endian::Little;
    ByteReader r(raw.data(), raw.size());
    uint32_t ts_sec = 0, ts_frac = 0, incl_len = 0, orig_len = 0;
    r.read_u32(e, ts_sec);
    r.read_u32(e, ts_frac);
    r.read_u32(e, incl_len);
    r.read_u32(e, orig_len);

    if (incl_len > kMaxRecord) return Next::Corrupt;
    // Grow the buffer chunk by chunk instead of trusting incl_len up front: a
    // damaged length of 10 MB on a 2 KB file then costs 64 KB, not 10 MB.
    buffer_.clear();
    while (buffer_.size() < incl_len) {
        const size_t chunk = std::min<size_t>(incl_len - buffer_.size(), kReadChunk);
        const size_t old_size = buffer_.size();
        buffer_.resize(old_size + chunk);
        if (!read_exact(in_, buffer_.data() + old_size, chunk)) return Next::Truncated;
    }

    // ts_sec is at most ~4.3e9, so ts_sec*1e9 fits in uint64 with room to spare.
    record.timestamp_ns = static_cast<uint64_t>(ts_sec) * 1000000000ull +
                          static_cast<uint64_t>(ts_frac) * (nano_ ? 1ull : 1000ull);
    record.original_length = orig_len;
    record.data = buffer_.data();
    record.captured_length = incl_len;
    return Next::Record;
}

}  // namespace rtpscope
