// byte_reader.hpp -- bounds-checked, endian-explicit reads from a byte buffer.
//
// What it does:
//   A tiny non-owning cursor over [data, data+size). Every read checks that
//   enough bytes remain and returns false (leaving the output untouched) if
//   not. Multi-byte values are assembled one byte at a time with shifts, so
//   the result never depends on the host's endianness and we never cast a
//   byte buffer to a struct (which would be UB: alignment, aliasing, padding).
//
// Where it sits in the data flow:
//   Every parser (pcap, Ethernet/IPv4/UDP, RTP) reads through this class.
//   Input: raw bytes from a file or a captured frame.  Output: integers.
//
// Key design decision:
//   Failure is a return value, not an exception or an assert. Malformed or
//   truncated network data is *normal* input for an analyzer, so the callers
//   check each read and classify the packet as "malformed" instead of crashing.
//   One central place for bounds checks means one place to audit.
#pragma once

#include <cstddef>
#include <cstdint>

namespace rtpscope {

enum class Endian { Big, Little };

class ByteReader {
public:
    ByteReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    size_t remaining() const { return size_ - pos_; }
    size_t position() const { return pos_; }
    // Pointer to the next unread byte (valid for remaining() bytes).
    const uint8_t* cursor() const { return data_ + pos_; }

    bool read_u8(uint8_t& out) {
        if (remaining() < 1) return false;
        out = data_[pos_++];
        return true;
    }

    bool read_u16(Endian e, uint16_t& out) {
        if (remaining() < 2) return false;
        const uint8_t* p = data_ + pos_;
        out = (e == Endian::Big)
                  ? static_cast<uint16_t>((p[0] << 8) | p[1])
                  : static_cast<uint16_t>((p[1] << 8) | p[0]);
        pos_ += 2;
        return true;
    }

    bool read_u32(Endian e, uint32_t& out) {
        if (remaining() < 4) return false;
        const uint8_t* p = data_ + pos_;
        const uint32_t b0 = p[0], b1 = p[1], b2 = p[2], b3 = p[3];
        out = (e == Endian::Big) ? (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
                                 : (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
        pos_ += 4;
        return true;
    }

    bool skip(size_t n) {
        if (remaining() < n) return false;
        pos_ += n;
        return true;
    }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_ = 0;
};

}  // namespace rtpscope
