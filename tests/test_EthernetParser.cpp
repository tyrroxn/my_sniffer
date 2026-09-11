/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_EthernetParser
*/

#include <criterion/criterion.h>
#include "EthernetParser.hpp"
#include <cstdlib>

using sniffer::EthernetParser;
using sniffer::EthernetHeader;
using sniffer::EthernetType;

static const std::vector<std::uint8_t> DST_MAC = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const std::vector<std::uint8_t> SRC_MAC = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

static std::vector<std::uint8_t> concat(std::initializer_list<std::vector<std::uint8_t>> parts)
{
    std::vector<std::uint8_t> out;

    for (const auto &part : parts)
        out.insert(out.end(), part.begin(), part.end());
    return out;
}

// ===== parse: untagged frames =====

Test(EthernetParser_parse, valid_untagged_ipv4)
{
    std::vector<std::uint8_t> frame = concat({DST_MAC, SRC_MAC, {0x08, 0x00}});
    EthernetHeader header;

    cr_assert(EthernetParser::parse(frame, header));
    cr_assert_eq(header.destinationMac, "aa:bb:cc:dd:ee:ff");
    cr_assert_eq(header.sourceMac, "11:22:33:44:55:66");
    cr_assert_eq(header.etherType, 0x0800);
    cr_assert_not(header.vlanTagged);
}

Test(EthernetParser_parse, untagged_frame_with_extra_payload)
{
    // Header (14 bytes) + a few payload bytes, no VLAN tag: must still parse.
    std::vector<std::uint8_t> frame =
        concat({DST_MAC, SRC_MAC, {0x08, 0x00}, {0xde, 0xad, 0xbe}});
    EthernetHeader header;

    cr_assert(EthernetParser::parse(frame, header));
    cr_assert_eq(header.etherType, 0x0800);
    cr_assert_not(header.vlanTagged);
}

Test(EthernetParser_parse, buffer_too_short)
{
    std::vector<std::uint8_t> frame = concat({DST_MAC, {0x11, 0x22}});
    EthernetHeader header;

    cr_assert_not(EthernetParser::parse(frame, header));
}

Test(EthernetParser_parse, empty_buffer)
{
    std::vector<std::uint8_t> frame;
    EthernetHeader header;

    cr_assert_not(EthernetParser::parse(frame, header));
}

// ===== parse: VLAN-tagged (802.1Q) frames =====

Test(EthernetParser_parse, valid_vlan_tagged_ipv4)
{
    std::vector<std::uint8_t> frame = concat({
        DST_MAC, SRC_MAC,
        {0x81, 0x00},  // TPID: 802.1Q tag
        {0x00, 0x64},  // TCI (VLAN id 100), value irrelevant to detection
        {0x08, 0x00},  // real EtherType behind the tag
    });
    EthernetHeader header;

    cr_assert(EthernetParser::parse(frame, header));
    cr_assert(header.vlanTagged);
    cr_assert_eq(header.etherType, 0x0800);
}

Test(EthernetParser_parse, vlan_tagged_truncated_before_real_ethertype)
{
    // TPID + TCI present, but the real EtherType is cut off: must not crash.
    std::vector<std::uint8_t> frame = concat({
        DST_MAC, SRC_MAC,
        {0x81, 0x00},
        {0x00, 0x64},
    });
    EthernetHeader header;

    cr_assert_not(EthernetParser::parse(frame, header));
}

// ===== parse: fuzzed short/corrupted buffers =====

Test(EthernetParser_parse, fuzz_short_buffers_no_crash)
{
    std::srand(1337);

    for (std::size_t len = 0; len < 14; len++) {
        for (int trial = 0; trial < 5; trial++) {
            std::vector<std::uint8_t> frame(len);
            for (auto &byte : frame)
                byte = static_cast<std::uint8_t>(std::rand() % 256);

            EthernetHeader header;
            cr_assert_not(EthernetParser::parse(frame, header),
                "length=%zu trial=%d must be cleanly rejected, not crash",
                len, trial);
        }
    }
}

Test(EthernetParser_parse, fuzz_valid_length_random_content_no_crash)
{
    std::srand(7);

    // Lengths spanning the untagged header, the VLAN-tagged header and some
    // extra payload: random content must never crash, whatever it decodes to.
    for (std::size_t len = 14; len < 32; len++) {
        for (int trial = 0; trial < 5; trial++) {
            std::vector<std::uint8_t> frame(len);
            for (auto &byte : frame)
                byte = static_cast<std::uint8_t>(std::rand() % 256);

            EthernetHeader header;
            EthernetParser::parse(frame, header);
        }
    }
}

// ===== protocolName =====

Test(EthernetParser_protocolName, ipv4)
{
    cr_assert_eq(std::string(EthernetParser::protocolName(
        static_cast<std::uint16_t>(EthernetType::IPv4))), "IPv4");
}

Test(EthernetParser_protocolName, arp)
{
    cr_assert_eq(std::string(EthernetParser::protocolName(
        static_cast<std::uint16_t>(EthernetType::ARP))), "ARP");
}

Test(EthernetParser_protocolName, ipv6)
{
    cr_assert_eq(std::string(EthernetParser::protocolName(
        static_cast<std::uint16_t>(EthernetType::IPv6))), "IPv6");
}

Test(EthernetParser_protocolName, unknown)
{
    cr_assert_eq(std::string(EthernetParser::protocolName(0x9999)), "Unknown");
}
