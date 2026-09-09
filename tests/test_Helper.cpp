/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_Helper
*/

#include <criterion/criterion.h>
#include "Helper.hpp"

using sniffer::Helper;

// ===== bynaryIPV4ToString =====

Test(bynaryIPV4ToString, valid)
{
    unsigned char ip[4] = {192, 168, 1, 1};
    std::string output;

    cr_assert(Helper::bynaryIPV4ToString(ip, output));
    cr_assert_eq(output, "192.168.1.1");
}

Test(bynaryIPV4ToString, null_input)
{
    std::string output;

    cr_assert_not(Helper::bynaryIPV4ToString(nullptr, output));
}

// ===== bynaryMACToString =====

Test(bynaryMACToString, valid)
{
    unsigned char mac[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
    std::string output;

    cr_assert(Helper::bynaryMACToString(mac, output));
    cr_assert_eq(output, "00:1a:2b:3c:4d:5e");
}

Test(bynaryMACToString, null_input)
{
    std::string output;

    cr_assert_not(Helper::bynaryMACToString(nullptr, output));
}

// ===== stringToBinaryIPV4 =====

Test(stringToBinaryIPV4, valid)
{
    unsigned char ip[4] = {0};

    cr_assert(Helper::stringToBinaryIPV4("192.168.1.1", ip));
    cr_assert_eq(ip[0], 192);
    cr_assert_eq(ip[1], 168);
    cr_assert_eq(ip[2], 1);
    cr_assert_eq(ip[3], 1);
}

Test(stringToBinaryIPV4, empty_string)
{
    unsigned char ip[4] = {0};

    cr_assert_not(Helper::stringToBinaryIPV4("", ip));
}

Test(stringToBinaryIPV4, malformed)
{
    unsigned char ip[4] = {0};

    cr_assert_not(Helper::stringToBinaryIPV4("not an ip", ip));
}

// ===== stringToBinaryMAC =====

Test(stringToBinaryMAC, valid)
{
    unsigned char mac[6] = {0};

    cr_assert(Helper::stringToBinaryMAC("00:1a:2b:3c:4d:5e", mac));
    cr_assert_eq(mac[0], 0x00);
    cr_assert_eq(mac[1], 0x1a);
    cr_assert_eq(mac[2], 0x2b);
    cr_assert_eq(mac[3], 0x3c);
    cr_assert_eq(mac[4], 0x4d);
    cr_assert_eq(mac[5], 0x5e);
}

Test(stringToBinaryMAC, empty_string)
{
    unsigned char mac[6] = {0};

    cr_assert_not(Helper::stringToBinaryMAC("", mac));
}

Test(stringToBinaryMAC, malformed)
{
    unsigned char mac[6] = {0};

    cr_assert_not(Helper::stringToBinaryMAC("not a mac", mac));
}

Test(stringToBinaryMAC, round_trip)
{
    unsigned char mac[6] = {0};
    std::string output;

    cr_assert(Helper::stringToBinaryMAC("de:ad:be:ef:00:ff", mac));
    cr_assert(Helper::bynaryMACToString(mac, output));
    cr_assert_eq(output, "de:ad:be:ef:00:ff");
}

// ===== hostToNetwork16 / networkToHost16 =====

Test(hostToNetwork16, roundtrip)
{
    std::uint16_t value = 0x1234;
    std::uint16_t net = Helper::hostToNetwork16(value);

    cr_assert_eq(Helper::networkToHost16(net), value);
}

Test(hostToNetwork16, byte_order)
{
    std::uint16_t net = Helper::hostToNetwork16(0x1234);

    cr_assert_eq(net, 0x3412);
}

// ===== hostToNetwork32 / networkToHost32 =====

Test(hostToNetwork32, roundtrip)
{
    std::uint32_t value = 0x12345678;
    std::uint32_t net = Helper::hostToNetwork32(value);

    cr_assert_eq(Helper::networkToHost32(net), value);
}

Test(hostToNetwork32, byte_order)
{
    std::uint32_t net = Helper::hostToNetwork32(0x12345678);

    cr_assert_eq(net, 0x78563412);
}

// ===== readUint16 =====

Test(readUint16, valid_network_order)
{
    unsigned char buffer[2] = {0x12, 0x34};
    std::uint16_t value = 0;

    cr_assert(Helper::readUint16(buffer, sizeof(buffer), 0, value));
    cr_assert_eq(value, 0x1234);
}

Test(readUint16, valid_host_order)
{
    unsigned char buffer[2] = {0x12, 0x34};
    std::uint16_t value = 0;

    cr_assert(Helper::readUint16(buffer, sizeof(buffer), 0, value, false));
    cr_assert_eq(value, 0x3412);
}

Test(readUint16, offset)
{
    unsigned char buffer[4] = {0x00, 0x00, 0x12, 0x34};
    std::uint16_t value = 0;

    cr_assert(Helper::readUint16(buffer, sizeof(buffer), 2, value));
    cr_assert_eq(value, 0x1234);
}

Test(readUint16, out_of_bounds)
{
    unsigned char buffer[2] = {0x12, 0x34};
    std::uint16_t value = 0;

    cr_assert_not(Helper::readUint16(buffer, sizeof(buffer), 1, value));
}

Test(readUint16, null_buffer)
{
    std::uint16_t value = 0;

    cr_assert_not(Helper::readUint16(nullptr, 2, 0, value));
}

// ===== readUint32 =====

Test(readUint32, valid_network_order)
{
    unsigned char buffer[4] = {0x12, 0x34, 0x56, 0x78};
    std::uint32_t value = 0;

    cr_assert(Helper::readUint32(buffer, sizeof(buffer), 0, value));
    cr_assert_eq(value, 0x12345678);
}

Test(readUint32, valid_host_order)
{
    unsigned char buffer[4] = {0x12, 0x34, 0x56, 0x78};
    std::uint32_t value = 0;

    cr_assert(Helper::readUint32(buffer, sizeof(buffer), 0, value, false));
    cr_assert_eq(value, 0x78563412);
}

Test(readUint32, out_of_bounds)
{
    unsigned char buffer[4] = {0x12, 0x34, 0x56, 0x78};
    std::uint32_t value = 0;

    cr_assert_not(Helper::readUint32(buffer, sizeof(buffer), 1, value));
}

Test(readUint32, null_buffer)
{
    std::uint32_t value = 0;

    cr_assert_not(Helper::readUint32(nullptr, 4, 0, value));
}

// ===== hexdump =====

Test(hexdump, valid)
{
    unsigned char buffer[3] = {0x00, 0xab, 0xff};

    cr_assert_eq(Helper::hexdump(buffer, 3), "00 ab ff");
}

Test(hexdump, empty)
{
    cr_assert_eq(Helper::hexdump(nullptr, 0), "");
}

// ===== rawBufferToString =====

Test(rawBufferToString, valid)
{
    unsigned char buffer[5] = {'h', 'e', 'l', 'l', 'o'};

    cr_assert_eq(Helper::rawBufferToString(buffer, 5), "hello");
}

Test(rawBufferToString, empty)
{
    cr_assert_eq(Helper::rawBufferToString(nullptr, 0), "");
}
