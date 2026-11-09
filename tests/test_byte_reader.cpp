// test_byte_reader.cpp -- endianness and bounds behaviour of ByteReader.
#include "byte_reader.hpp"
#include "test_harness.hpp"

using rtpscope::ByteReader;
using rtpscope::Endian;

TEST(reads_big_and_little_endian) {
    const uint8_t buf[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
    ByteReader r(buf, sizeof buf);
    uint16_t a = 0;
    uint32_t b = 0;
    CHECK(r.read_u16(Endian::Big, a));
    CHECK_EQ(a, 0x1234);
    CHECK(r.read_u32(Endian::Little, b));
    CHECK_EQ(b, 0xbc9a7856u);  // bytes 56 78 9a bc read little-endian
    CHECK_EQ(r.remaining(), 0u);
}

TEST(read_past_end_fails_and_leaves_output_untouched) {
    const uint8_t buf[] = {0xff, 0xee, 0xdd};
    ByteReader r(buf, sizeof buf);
    uint32_t v = 0xdeadbeef;
    CHECK(!r.read_u32(Endian::Big, v));
    CHECK_EQ(v, 0xdeadbeefu);
    CHECK_EQ(r.position(), 0u);  // a failed read must not consume bytes
    uint16_t w = 0;
    CHECK(r.read_u16(Endian::Big, w));
    uint8_t x = 0;
    CHECK(r.read_u8(x));
    CHECK(!r.read_u8(x));
    CHECK(!r.skip(1));
}

TEST(empty_buffer_is_safe) {
    ByteReader r(nullptr, 0);
    uint8_t x = 0;
    CHECK(!r.read_u8(x));
    CHECK(r.skip(0));
}

TEST_MAIN()
