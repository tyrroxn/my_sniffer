/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_UdpParser
*/

#include <criterion/criterion.h>
#include <algorithm>
#include <cstdlib>
#include "parsers/UdpParser.hpp"

using sniffer::UdpParser;
using sniffer::UdpHeader;

// srcPort=12345 dstPort=53 length=16 (8 header + 8 payload) checksum=0xbeef
static const std::vector<std::uint8_t> UDP_HEADER = {
    0x30, 0x39, // source port
    0x00, 0x35, // destination port
    0x00, 0x10, // length
    0xbe, 0xef, // checksum
};

static std::vector<std::uint8_t> concat(std::initializer_list<std::vector<std::uint8_t>> parts)
{
    std::vector<std::uint8_t> out;

    for (const auto &part : parts)
        out.insert(out.end(), part.begin(), part.end());
    return out;
}

// ===== parse: valid segment =====

Test(UdpParser_parse, valid_fields)
{
    UdpParser parser;
    UdpHeader header;

    cr_assert(parser.parse(UDP_HEADER, header));
    cr_assert_eq(header.sourcePort, 12345);
    cr_assert_eq(header.destinationPort, 53);
    cr_assert_eq(header.length, 16);
    cr_assert_eq(header.checksum, 0xbeef);
}

Test(UdpParser_parse, no_payload_header_only)
{
    UdpParser parser;
    UdpHeader header;

    cr_assert(parser.parse(UDP_HEADER, header));
    cr_assert(header.payload.empty());
}

Test(UdpParser_parse, payload_extracted)
{
    std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::vector<std::uint8_t> segment = concat({UDP_HEADER, payload});
    UdpParser parser;
    UdpHeader header;

    cr_assert(parser.parse(segment, header));
    cr_assert_eq(header.payload.size(), payload.size());
    cr_assert(std::equal(header.payload.begin(), header.payload.end(), payload.begin()));
}

// ===== parse: truncated/corrupted (no crash, clean rejection) =====

Test(UdpParser_parse, buffer_too_short)
{
    std::vector<std::uint8_t> segment(7, 0x00);
    UdpParser parser;
    UdpHeader header;

    cr_assert_not(parser.parse(segment, header));
}

Test(UdpParser_parse, empty_buffer)
{
    std::vector<std::uint8_t> segment;
    UdpParser parser;
    UdpHeader header;

    cr_assert_not(parser.parse(segment, header));
}

Test(UdpParser_parse, fuzz_short_buffers_no_crash)
{
    std::srand(2468);

    for (std::size_t len = 0; len < 8; len++) {
        for (int trial = 0; trial < 5; trial++) {
            std::vector<std::uint8_t> segment(len);
            for (auto &byte : segment)
                byte = static_cast<std::uint8_t>(std::rand() % 256);

            UdpParser parser;
            UdpHeader header;
            cr_assert_not(parser.parse(segment, header),
                "length=%zu trial=%d must be cleanly rejected, not crash", len, trial);
        }
    }
}

Test(UdpParser_parse, fuzz_valid_length_random_content_no_crash)
{
    std::srand(1357);

    for (std::size_t len = 8; len < 40; len++) {
        for (int trial = 0; trial < 5; trial++) {
            std::vector<std::uint8_t> segment(len);
            for (auto &byte : segment)
                byte = static_cast<std::uint8_t>(std::rand() % 256);

            UdpParser parser;
            UdpHeader header;
            parser.parse(segment, header);
        }
    }
}
