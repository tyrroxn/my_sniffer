/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_Ipv4Parser
*/

#include <criterion/criterion.h>
#include <cstdlib>
#include "parsers/Ipv4Parser.hpp"

using sniffer::Ipv4Parser;
using sniffer::Ipv4Header;

// Known-good header (RFC-style textbook example): version=4, ihl=5,
// tos=0, totalLength=60, ttl=64, protocol=TCP, checksum valid,
// DF set, src=172.16.10.99, dst=172.16.10.12.
static const std::vector<std::uint8_t> VALID_HEADER = {
    0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
    0x40, 0x06, 0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63,
    0xac, 0x10, 0x0a, 0x0c
};

// ===== parse: valid header =====

Test(Ipv4Parser_parse, valid_header_fields)
{
    Ipv4Header header;

    cr_assert(Ipv4Parser::parse(VALID_HEADER, header));
    cr_assert_eq(header.version, 4);
    cr_assert_eq(header.ihl, 5);
    cr_assert_eq(header.typeOfService, 0);
    cr_assert_eq(header.totalLength, 60);
    cr_assert_eq(header.ttl, 64);
    cr_assert_eq(header.protocol, 6);
    cr_assert_eq(header.headerLength, 20);
    cr_assert_eq(header.sourceAddress, "172.16.10.99");
    cr_assert_eq(header.destinationAddress, "172.16.10.12");
}

Test(Ipv4Parser_parse, valid_header_checksum)
{
    Ipv4Header header;

    cr_assert(Ipv4Parser::parse(VALID_HEADER, header));
    cr_assert(header.checksumValid);
}

Test(Ipv4Parser_parse, corrupted_checksum_still_parses_but_invalid)
{
    std::vector<std::uint8_t> frame = VALID_HEADER;
    frame[8] = 0x41; // flip TTL: header still structurally valid, checksum no longer matches
    Ipv4Header header;

    cr_assert(Ipv4Parser::parse(frame, header));
    cr_assert_not(header.checksumValid);
}

Test(Ipv4Parser_parse, no_fragmentation_flags)
{
    Ipv4Header header;

    cr_assert(Ipv4Parser::parse(VALID_HEADER, header));
    cr_assert(header.DF_flag);
    cr_assert_not(header.MF_flag);
    cr_assert_eq(header.fragmentOffset, 0);
    cr_assert_not(header.isFragmented);
}

// ===== parse: fragmentation =====

Test(Ipv4Parser_parse, fragmented_more_fragments)
{
    std::vector<std::uint8_t> frame = VALID_HEADER;
    frame[6] = 0x20; // MF set, offset 0 (first fragment)
    frame[7] = 0x00;
    Ipv4Header header;

    cr_assert(Ipv4Parser::parse(frame, header));
    cr_assert(header.MF_flag);
    cr_assert_not(header.DF_flag);
    cr_assert_eq(header.fragmentOffset, 0);
    cr_assert(header.isFragmented);
}

Test(Ipv4Parser_parse, fragmented_last_fragment_nonzero_offset)
{
    std::vector<std::uint8_t> frame = VALID_HEADER;
    frame[6] = 0x00; // MF clear, offset 185 (last fragment of a fragmented datagram)
    frame[7] = 0xb9;
    Ipv4Header header;

    cr_assert(Ipv4Parser::parse(frame, header));
    cr_assert_not(header.MF_flag);
    cr_assert_eq(header.fragmentOffset, 185);
    cr_assert(header.isFragmented);
}

// ===== parse: truncated/corrupted (no crash, clean rejection) =====

Test(Ipv4Parser_parse, buffer_too_short)
{
    std::vector<std::uint8_t> frame(19, 0x00);
    Ipv4Header header;

    cr_assert_not(Ipv4Parser::parse(frame, header));
}

Test(Ipv4Parser_parse, empty_buffer)
{
    std::vector<std::uint8_t> frame;
    Ipv4Header header;

    cr_assert_not(Ipv4Parser::parse(frame, header));
}

Test(Ipv4Parser_parse, ihl_below_minimum)
{
    std::vector<std::uint8_t> frame = VALID_HEADER;
    frame[0] = 0x44; // version=4, ihl=4 (16 bytes: below the mandatory 20)
    Ipv4Header header;

    cr_assert_not(Ipv4Parser::parse(frame, header));
}

Test(Ipv4Parser_parse, ihl_claims_more_than_buffer)
{
    std::vector<std::uint8_t> frame = VALID_HEADER;
    frame[0] = 0x46; // ihl=6 (24 bytes) but buffer only holds 20
    Ipv4Header header;

    cr_assert_not(Ipv4Parser::parse(frame, header));
}

Test(Ipv4Parser_parse, fuzz_short_buffers_no_crash)
{
    std::srand(2024);

    for (std::size_t len = 0; len < 20; len++) {
        for (int trial = 0; trial < 5; trial++) {
            std::vector<std::uint8_t> frame(len);
            for (auto &byte : frame)
                byte = static_cast<std::uint8_t>(std::rand() % 256);

            Ipv4Header header;
            cr_assert_not(Ipv4Parser::parse(frame, header),
                "length=%zu trial=%d must be cleanly rejected, not crash", len, trial);
        }
    }
}

Test(Ipv4Parser_parse, fuzz_valid_length_random_content_no_crash)
{
    std::srand(99);

    for (std::size_t len = 20; len < 40; len++) {
        for (int trial = 0; trial < 5; trial++) {
            std::vector<std::uint8_t> frame(len);
            for (auto &byte : frame)
                byte = static_cast<std::uint8_t>(std::rand() % 256);

            Ipv4Header header;
            Ipv4Parser::parse(frame, header);
        }
    }
}

// ===== protocolName =====

Test(Ipv4Parser_protocolName, tcp)
{
    cr_assert_eq(std::string(Ipv4Parser::protocolName(6)), "TCP");
}

Test(Ipv4Parser_protocolName, udp)
{
    cr_assert_eq(std::string(Ipv4Parser::protocolName(17)), "UDP");
}

Test(Ipv4Parser_protocolName, unknown)
{
    cr_assert_eq(std::string(Ipv4Parser::protocolName(1)), "Unknown");
}
