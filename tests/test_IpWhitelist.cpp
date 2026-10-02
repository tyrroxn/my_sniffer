/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_IpWhitelist
*/

#include <criterion/criterion.h>
#include "analysis/IpWhitelist.hpp"
#include <fstream>

using namespace analyser;

// Writes `content` to a whitelist file in /tmp and returns its path
static std::string writeWhitelist(const std::string &name, const std::string &content)
{
    std::string path = "/tmp/my_sniffer_test_whitelist_" + name + ".conf";
    std::ofstream file(path);

    file << content;
    return path;
}

// ===== parseIpv4 =====

Test(IpWhitelist, parse_ipv4_valid)
{
    cr_assert_eq(IpWhitelist::parseIpv4("192.168.1.10").value(), 0xC0A8010Au);
    cr_assert_eq(IpWhitelist::parseIpv4("0.0.0.0").value(), 0x00000000u);
    cr_assert_eq(IpWhitelist::parseIpv4("255.255.255.255").value(), 0xFFFFFFFFu);
    cr_assert_eq(IpWhitelist::parseIpv4("010.001.0.1").value(), 0x0A010001u, "up to 3 digits, leading zeros");
}

Test(IpWhitelist, parse_ipv4_wrong_number_of_bytes)
{
    cr_assert_not(IpWhitelist::parseIpv4("1.2.3").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("1.2.3.4.5").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("").has_value());
}

Test(IpWhitelist, parse_ipv4_empty_byte)
{
    cr_assert_not(IpWhitelist::parseIpv4("1..2.3").has_value());
    cr_assert_not(IpWhitelist::parseIpv4(".1.2.3").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("1.2.3.").has_value());
}

Test(IpWhitelist, parse_ipv4_out_of_range)
{
    cr_assert_not(IpWhitelist::parseIpv4("256.1.1.1").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("1.2.3.999").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("1.2.3.0001").has_value(), "more than 3 digits");
    cr_assert_not(IpWhitelist::parseIpv4("99999999999.1.1.1").has_value());
}

Test(IpWhitelist, parse_ipv4_invalid_characters)
{
    cr_assert_not(IpWhitelist::parseIpv4("-1.2.3.4").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("+1.2.3.4").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("1.2.3.4abc").has_value());
    cr_assert_not(IpWhitelist::parseIpv4(" 1.2.3.4").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("1.2.3.4 ").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("a.b.c.d").has_value());
    cr_assert_not(IpWhitelist::parseIpv4("1.2.3.4/24").has_value(), "a range is not an IP");
}

// ===== parseRange =====

Test(IpWhitelist, parse_range_cidr)
{
    std::optional<IpRange> range = IpWhitelist::parseRange("192.168.1.0/24");

    cr_assert(range.has_value());
    cr_assert_eq(range->network, 0xC0A80100u);
    cr_assert_eq(range->mask, 0xFFFFFF00u);
}

Test(IpWhitelist, parse_range_single_ip_is_32)
{
    std::optional<IpRange> range = IpWhitelist::parseRange("8.8.8.8");

    cr_assert(range.has_value());
    cr_assert_eq(range->network, 0x08080808u);
    cr_assert_eq(range->mask, 0xFFFFFFFFu);
}

Test(IpWhitelist, parse_range_network_is_normalized)
{
    std::optional<IpRange> range = IpWhitelist::parseRange("192.168.1.77/24");

    cr_assert(range.has_value());
    cr_assert_eq(range->network, 0xC0A80100u, "host bits cleared: 192.168.1.0");
    cr_assert(range->contains(0xC0A80101u), "192.168.1.1 in the range");
}

Test(IpWhitelist, parse_range_prefix_limits)
{
    std::optional<IpRange> all = IpWhitelist::parseRange("0.0.0.0/0");
    std::optional<IpRange> one = IpWhitelist::parseRange("10.0.0.1/32");

    cr_assert(all.has_value());
    cr_assert_eq(all->mask, 0u, "/0: no fixed bit");
    cr_assert(all->contains(0xFFFFFFFFu));
    cr_assert(all->contains(0x01020304u));
    cr_assert(one.has_value());
    cr_assert_eq(one->mask, 0xFFFFFFFFu);
}

Test(IpWhitelist, parse_range_invalid)
{
    cr_assert_not(IpWhitelist::parseRange("10.0.0.0/33").has_value());
    cr_assert_not(IpWhitelist::parseRange("10.0.0.0/").has_value());
    cr_assert_not(IpWhitelist::parseRange("10.0.0.0/abc").has_value());
    cr_assert_not(IpWhitelist::parseRange("10.0.0.0/24x").has_value());
    cr_assert_not(IpWhitelist::parseRange("10.0.0.0/-1").has_value());
    cr_assert_not(IpWhitelist::parseRange("10.0.0/8").has_value());
    cr_assert_not(IpWhitelist::parseRange("/8").has_value());
}

// ===== contains / addEntry =====

Test(IpWhitelist, empty_whitelist_contains_nothing)
{
    IpWhitelist whitelist;

    cr_assert_eq(whitelist.size(), 0);
    cr_assert_not(whitelist.contains("127.0.0.1"));
}

Test(IpWhitelist, contains_range_bounds)
{
    IpWhitelist whitelist;

    cr_assert(whitelist.addEntry("192.168.1.0/24"));
    cr_assert(whitelist.contains("192.168.1.0"));
    cr_assert(whitelist.contains("192.168.1.42"));
    cr_assert(whitelist.contains("192.168.1.255"));
    cr_assert_not(whitelist.contains("192.168.0.255"));
    cr_assert_not(whitelist.contains("192.168.2.0"));
}

Test(IpWhitelist, contains_odd_prefix)
{
    IpWhitelist whitelist;

    // 127.0.0.64/26: 127.0.0.64 -> 127.0.0.127
    cr_assert(whitelist.addEntry("127.0.0.64/26"));
    cr_assert_not(whitelist.contains("127.0.0.63"));
    cr_assert(whitelist.contains("127.0.0.64"));
    cr_assert(whitelist.contains("127.0.0.127"));
    cr_assert_not(whitelist.contains("127.0.0.128"));
}

Test(IpWhitelist, contains_single_ip_and_several_entries)
{
    IpWhitelist whitelist;

    cr_assert(whitelist.addEntry("8.8.8.8"));
    cr_assert(whitelist.addEntry("10.0.0.0/8"));
    cr_assert_eq(whitelist.size(), 2);
    cr_assert(whitelist.contains("8.8.8.8"));
    cr_assert_not(whitelist.contains("8.8.8.9"), "a single IP is a /32");
    cr_assert(whitelist.contains("10.200.3.4"));
}

Test(IpWhitelist, contains_invalid_ip_is_false)
{
    IpWhitelist whitelist;

    cr_assert(whitelist.addEntry("0.0.0.0/0"));
    cr_assert_not(whitelist.contains(""));
    cr_assert_not(whitelist.contains("not-an-ip"));
}

Test(IpWhitelist, add_invalid_entry)
{
    IpWhitelist whitelist;

    cr_assert_not(whitelist.addEntry("10.0.0.0/33"));
    cr_assert_not(whitelist.addEntry("hello"));
    cr_assert_eq(whitelist.size(), 0, "invalid entries are not added");
}

// ===== isLan =====

Test(IpWhitelist, is_lan_rfc1918)
{
    cr_assert(IpWhitelist::isLan("10.0.0.1"));
    cr_assert(IpWhitelist::isLan("10.255.255.255"));
    cr_assert(IpWhitelist::isLan("172.16.0.1"));
    cr_assert(IpWhitelist::isLan("172.31.255.255"));
    cr_assert(IpWhitelist::isLan("192.168.178.1"));
}

Test(IpWhitelist, is_lan_bounds_and_public)
{
    cr_assert_not(IpWhitelist::isLan("172.15.255.255"), "just before 172.16.0.0/12");
    cr_assert_not(IpWhitelist::isLan("172.32.0.0"), "just after 172.16.0.0/12");
    cr_assert_not(IpWhitelist::isLan("192.169.0.1"));
    cr_assert_not(IpWhitelist::isLan("11.0.0.1"));
    cr_assert_not(IpWhitelist::isLan("8.8.8.8"));
    cr_assert_not(IpWhitelist::isLan("127.0.0.1"), "loopback is not RFC1918");
    cr_assert_not(IpWhitelist::isLan("not-an-ip"));
}

// ===== load =====

Test(IpWhitelist, load_file_with_comments_and_blank_lines)
{
    std::string path = writeWhitelist("valid",
        "# trusted hosts\n"
        "\n"
        "192.168.1.0/24      # LAN\n"
        "   8.8.8.8\t\n"
        "   # indented comment\n"
        "10.0.0.1\r\n");
    IpWhitelist whitelist;
    std::string error;

    cr_assert(whitelist.load(path, error), "error: %s", error.c_str());
    cr_assert_eq(whitelist.size(), 3);
    cr_assert(whitelist.contains("192.168.1.50"));
    cr_assert(whitelist.contains("8.8.8.8"));
    cr_assert(whitelist.contains("10.0.0.1"), "CRLF line endings accepted");
    cr_assert(error.empty());
}

Test(IpWhitelist, load_empty_file)
{
    std::string path = writeWhitelist("empty", "# only a comment\n\n");
    IpWhitelist whitelist;
    std::string error;

    cr_assert(whitelist.load(path, error));
    cr_assert_eq(whitelist.size(), 0);
}

Test(IpWhitelist, load_invalid_line_reports_line_number)
{
    std::string path = writeWhitelist("invalid", "127.0.0.1\n# comment\nnot-an-ip\n10.0.0.0/8\n");
    IpWhitelist whitelist;
    std::string error;

    cr_assert_not(whitelist.load(path, error));
    cr_assert_neq(error.find("line 3"), std::string::npos, "error: %s", error.c_str());
    cr_assert_neq(error.find("not-an-ip"), std::string::npos, "error: %s", error.c_str());
}

Test(IpWhitelist, load_two_words_on_a_line)
{
    std::string path = writeWhitelist("two_words", "1.2.3.4 5.6.7.8\n");
    IpWhitelist whitelist;
    std::string error;

    cr_assert_not(whitelist.load(path, error));
    cr_assert_neq(error.find("line 1"), std::string::npos, "error: %s", error.c_str());
}

Test(IpWhitelist, load_missing_file)
{
    IpWhitelist whitelist;
    std::string error;

    cr_assert_not(whitelist.load("/tmp/my_sniffer_test_whitelist_does_not_exist.conf", error));
    cr_assert_neq(error.find("cannot open"), std::string::npos, "error: %s", error.c_str());
}
