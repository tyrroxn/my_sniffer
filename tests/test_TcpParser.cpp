/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_TcpParser
*/

#include <criterion/criterion.h>
#include <algorithm>
#include <cstdlib>
#include "TcpParser.hpp"

using sniffer::TcpParser;
using sniffer::TcpHeader;

// srcPort=12345 dstPort=80 seq=1 ack=0 dataOffset=5(20B) flags=SYN
// window=64240 checksum=0xdead urgent=0. No options, no payload.
static const std::vector<std::uint8_t> SYN_SEGMENT = {
    0x30, 0x39,             // source port
    0x00, 0x50,             // destination port
    0x00, 0x00, 0x00, 0x01, // sequence number
    0x00, 0x00, 0x00, 0x00, // acknowledgment number
    0x50, 0x02,             // dataOffset=5, flags=SYN
    0xfa, 0xf0,             // window size
    0xde, 0xad,             // checksum
    0x00, 0x00,             // urgent pointer
};

static std::vector<std::uint8_t> concat(std::initializer_list<std::vector<std::uint8_t>> parts)
{
    std::vector<std::uint8_t> out;

    for (const auto &part : parts)
        out.insert(out.end(), part.begin(), part.end());
    return out;
}

// ===== parse: valid segment =====

Test(TcpParser_parse, valid_syn_fields)
{
    TcpHeader header;

    cr_assert(TcpParser::parse(SYN_SEGMENT, header));
    cr_assert_eq(header.sourcePort, 12345);
    cr_assert_eq(header.destinationPort, 80);
    cr_assert_eq(header.sequenceNumber, 1);
    cr_assert_eq(header.acknowledgmentNumber, 0);
    cr_assert_eq(header.dataOffset, 5);
    cr_assert_eq(header.headerLength, 20);
    cr_assert_eq(header.windowSize, 0xfaf0);
    cr_assert_eq(header.checksum, 0xdead);
    cr_assert_eq(header.urgentPointer, 0);
}

Test(TcpParser_parse, valid_syn_flags)
{
    TcpHeader header;

    cr_assert(TcpParser::parse(SYN_SEGMENT, header));
    cr_assert(header.SYN_flag);
    cr_assert_not(header.ACK_flag);
    cr_assert_not(header.FIN_flag);
    cr_assert_not(header.RST_flag);
    cr_assert_not(header.PSH_flag);
    cr_assert_not(header.URG_flag);
    cr_assert_not(header.ECE_flag);
    cr_assert_not(header.CWR_flag);
    cr_assert_not(header.NS_flag);
}

Test(TcpParser_parse, no_payload_when_none_present)
{
    TcpHeader header;

    cr_assert(TcpParser::parse(SYN_SEGMENT, header));
    cr_assert(header.payload.empty());
}

Test(TcpParser_parse, ns_flag_bit)
{
    // dataOffset=5, NS set (LSB of the high byte), no other flags.
    std::vector<std::uint8_t> segment = SYN_SEGMENT;
    segment[12] = 0x51;
    segment[13] = 0x00;
    TcpHeader header;

    cr_assert(TcpParser::parse(segment, header));
    cr_assert(header.NS_flag);
    cr_assert_not(header.SYN_flag);
}

// ===== parse: payload extraction =====

Test(TcpParser_parse, payload_extracted_no_options)
{
    std::vector<std::uint8_t> payload = {'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> segment = concat({SYN_SEGMENT, payload});
    TcpHeader header;

    cr_assert(TcpParser::parse(segment, header));
    cr_assert_eq(header.headerLength, 20);
    cr_assert_eq(header.payload.size(), payload.size());
    cr_assert(std::equal(header.payload.begin(), header.payload.end(), payload.begin()));
}

Test(TcpParser_parse, payload_extracted_past_options)
{
    // dataOffset=6 (24 bytes: 20 fixed + 4 bytes of NOP options), then payload.
    std::vector<std::uint8_t> segment = SYN_SEGMENT;
    segment[12] = 0x60;
    std::vector<std::uint8_t> options = {0x01, 0x01, 0x01, 0x01};
    std::vector<std::uint8_t> payload = {'h', 'i'};
    segment = concat({segment, options, payload});
    TcpHeader header;

    cr_assert(TcpParser::parse(segment, header));
    cr_assert_eq(header.dataOffset, 6);
    cr_assert_eq(header.headerLength, 24);
    cr_assert_eq(header.payload.size(), payload.size());
    cr_assert(std::equal(header.payload.begin(), header.payload.end(), payload.begin()));
}

// ===== parse: truncated/corrupted (no crash, clean rejection) =====

Test(TcpParser_parse, buffer_too_short)
{
    std::vector<std::uint8_t> segment(19, 0x00);
    TcpHeader header;

    cr_assert_not(TcpParser::parse(segment, header));
}

Test(TcpParser_parse, empty_buffer)
{
    std::vector<std::uint8_t> segment;
    TcpHeader header;

    cr_assert_not(TcpParser::parse(segment, header));
}

Test(TcpParser_parse, data_offset_below_minimum)
{
    std::vector<std::uint8_t> segment = SYN_SEGMENT;
    segment[12] = 0x40; // dataOffset=4 (16 bytes): below the mandatory 20
    TcpHeader header;

    cr_assert_not(TcpParser::parse(segment, header));
}

Test(TcpParser_parse, data_offset_claims_more_than_buffer)
{
    std::vector<std::uint8_t> segment = SYN_SEGMENT;
    segment[12] = 0x90; // dataOffset=9 (36 bytes) but buffer only holds 20
    TcpHeader header;

    cr_assert_not(TcpParser::parse(segment, header));
}

Test(TcpParser_parse, fuzz_short_buffers_no_crash)
{
    std::srand(555);

    for (std::size_t len = 0; len < 20; len++) {
        for (int trial = 0; trial < 5; trial++) {
            std::vector<std::uint8_t> segment(len);
            for (auto &byte : segment)
                byte = static_cast<std::uint8_t>(std::rand() % 256);

            TcpHeader header;
            cr_assert_not(TcpParser::parse(segment, header),
                "length=%zu trial=%d must be cleanly rejected, not crash", len, trial);
        }
    }
}

Test(TcpParser_parse, fuzz_valid_length_random_content_no_crash)
{
    std::srand(321);

    for (std::size_t len = 20; len < 40; len++) {
        for (int trial = 0; trial < 5; trial++) {
            std::vector<std::uint8_t> segment(len);
            for (auto &byte : segment)
                byte = static_cast<std::uint8_t>(std::rand() % 256);

            TcpHeader header;
            TcpParser::parse(segment, header);
        }
    }
}

// ===== flagsLabel =====

Test(TcpParser_flagsLabel, syn_ack)
{
    TcpHeader header{};
    header.SYN_flag = true;
    header.ACK_flag = true;

    cr_assert_eq(TcpParser::flagsLabel(header), "[SYN, ACK]");
}

Test(TcpParser_flagsLabel, fin_ack)
{
    TcpHeader header{};
    header.FIN_flag = true;
    header.ACK_flag = true;

    cr_assert_eq(TcpParser::flagsLabel(header), "[FIN, ACK]");
}

Test(TcpParser_flagsLabel, no_flags)
{
    TcpHeader header{};

    cr_assert_eq(TcpParser::flagsLabel(header), "[]");
}
