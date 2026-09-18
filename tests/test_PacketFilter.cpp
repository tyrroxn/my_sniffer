/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_PacketFilter
*/

#include <criterion/criterion.h>
#include <ctime>
#include "PacketFilter.hpp"

using namespace sniffer;

static EthernetHeader makeEthernet(std::uint16_t etherType = 0x0800)
{
    EthernetHeader eth;

    eth.sourceMac = "aa:bb:cc:dd:ee:ff";
    eth.destinationMac = "11:22:33:44:55:66";
    eth.etherType = etherType;
    eth.vlanTagged = false;
    return eth;
}

static Ipv4Header makeIpv4(std::uint8_t protocol, const std::string &src = "10.0.0.1",
    const std::string &dst = "10.0.0.2")
{
    Ipv4Header ip;

    ip.version = 4;
    ip.ihl = 5;
    ip.typeOfService = 0;
    ip.totalLength = 52;
    ip.ttl = 64;
    ip.protocol = protocol;
    ip.headerChecksum = 0;
    ip.checksumValid = true;
    ip.DF_flag = true;
    ip.MF_flag = false;
    ip.isFragmented = false;
    ip.fragmentOffset = 0;
    ip.headerLength = 20;
    ip.sourceAddress = src;
    ip.destinationAddress = dst;
    return ip;
}

static TcpHeader makeTcp(std::uint16_t srcPort = 51000, std::uint16_t dstPort = 443)
{
    TcpHeader tcp{};

    tcp.sourcePort = srcPort;
    tcp.destinationPort = dstPort;
    tcp.ACK_flag = true;
    tcp.windowSize = 254;
    tcp.checksum = 0xbeef;
    return tcp;
}

static UdpHeader makeUdp(std::uint16_t srcPort = 53, std::uint16_t dstPort = 12345)
{
    UdpHeader udp{};

    udp.sourcePort = srcPort;
    udp.destinationPort = dstPort;
    udp.length = 40;
    udp.checksum = 0xcafe;
    return udp;
}

// ===== no filter set: everything passes =====

Test(PacketFilter, no_filters_matches_everything)
{
    PacketFilter filter;

    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(), std::nullopt));
    cr_assert(filter.matches(makeEthernet(0x0806), std::nullopt, 60));
}

// ===== parse: syntax errors =====

Test(PacketFilter_parse, missing_equals_sign_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("garbage"));
}

Test(PacketFilter_parse, unknown_key_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("bogus=tcp"));
}

// ===== proto =====

Test(PacketFilter_proto, matches_tcp_only)
{
    PacketFilter filter;

    cr_assert(filter.parse("proto=tcp"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(17), 66));
}

Test(PacketFilter_proto, matches_arp)
{
    PacketFilter filter;

    cr_assert(filter.parse("proto=arp"));
    cr_assert(filter.matches(makeEthernet(0x0806), std::nullopt, 60));
    cr_assert_not(filter.matches(makeEthernet(0x0800), makeIpv4(6), 66));
}

Test(PacketFilter_proto, matches_ipv6)
{
    PacketFilter filter;

    cr_assert(filter.parse("proto=ipv6"));
    cr_assert(filter.matches(makeEthernet(0x86dd), std::nullopt, 86));
}

Test(PacketFilter_proto, matches_unknown)
{
    PacketFilter filter;

    cr_assert(filter.parse("proto=unknown"));
    cr_assert(filter.matches(makeEthernet(0x88e1), std::nullopt, 60));
}

Test(PacketFilter_proto, or_via_slash)
{
    PacketFilter filter;

    cr_assert(filter.parse("proto=tcp/udp"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(17), 66));
    cr_assert_not(filter.matches(makeEthernet(0x0806), std::nullopt, 60));
}

Test(PacketFilter_proto, or_via_repeated_parse)
{
    PacketFilter filter;

    cr_assert(filter.parse("proto=tcp"));
    cr_assert(filter.parse("proto=udp"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(17), 66));
}

Test(PacketFilter_proto, invalid_value_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("proto=icmp"));
}

// ===== sport / dport / port =====

Test(PacketFilter_port, sport_matches_tcp_source_port)
{
    PacketFilter filter;

    cr_assert(filter.parse("sport=51000"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(51000, 443)));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(9999, 443)));
}

Test(PacketFilter_port, sport_matches_udp_source_port)
{
    PacketFilter filter;

    cr_assert(filter.parse("sport=53"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(17), 66, std::nullopt, makeUdp(53, 12345)));
}

Test(PacketFilter_port, dport_matches_destination_port)
{
    PacketFilter filter;

    cr_assert(filter.parse("dport=443"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(51000, 443)));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(51000, 80)));
}

Test(PacketFilter_port, port_matches_either_source_or_destination)
{
    PacketFilter filter;

    cr_assert(filter.parse("port=443"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(51000, 443)));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(443, 51000)));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(51000, 80)));
}

Test(PacketFilter_port, no_transport_header_fails)
{
    PacketFilter filter;

    cr_assert(filter.parse("sport=443"));
    cr_assert_not(filter.matches(makeEthernet(0x0806), std::nullopt, 60));
}

Test(PacketFilter_port, non_numeric_value_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("sport=abc"));
}

Test(PacketFilter_port, out_of_range_value_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("sport=70000"));
}

// ===== src / dst / ipv4 =====

Test(PacketFilter_address, src_matches_source_address)
{
    PacketFilter filter;

    cr_assert(filter.parse("src=192.168.1.1"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6, "192.168.1.1", "10.0.0.2"), 66));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6, "10.0.0.1", "10.0.0.2"), 66));
}

Test(PacketFilter_address, dst_matches_destination_address)
{
    PacketFilter filter;

    cr_assert(filter.parse("dst=192.168.1.1"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6, "10.0.0.1", "192.168.1.1"), 66));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6, "10.0.0.1", "10.0.0.2"), 66));
}

Test(PacketFilter_address, ipv4_matches_either_src_or_dst)
{
    PacketFilter filter;

    cr_assert(filter.parse("ipv4=192.168.1.1"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6, "192.168.1.1", "10.0.0.2"), 66));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6, "10.0.0.1", "192.168.1.1"), 66));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6, "10.0.0.1", "10.0.0.2"), 66));
}

Test(PacketFilter_address, no_ipv4_header_fails)
{
    PacketFilter filter;

    cr_assert(filter.parse("src=192.168.1.1"));
    cr_assert_not(filter.matches(makeEthernet(0x0806), std::nullopt, 60));
}

Test(PacketFilter_address, malformed_address_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("src=999.1.1.1"));
    cr_assert_not(filter.parse("src=1.2.3"));
    cr_assert_not(filter.parse("src=abc"));
}

// ===== tcpflags =====

Test(PacketFilter_tcpflags, or_semantics)
{
    PacketFilter filter;
    TcpHeader synOnly{};
    synOnly.SYN_flag = true;
    TcpHeader pshOnly{};
    pshOnly.PSH_flag = true;
    TcpHeader ackOnly{};
    ackOnly.ACK_flag = true;

    cr_assert(filter.parse("tcpflags=SYN/PSH"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, synOnly));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, pshOnly));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 66, ackOnly));
}

Test(PacketFilter_tcpflags, no_tcp_header_fails)
{
    PacketFilter filter;

    cr_assert(filter.parse("tcpflags=SYN"));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(17), 66, std::nullopt, makeUdp()));
}

Test(PacketFilter_tcpflags, invalid_flag_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("tcpflags=BOGUS"));
}

// ===== minsize / maxsize =====

Test(PacketFilter_size, minsize_boundary_inclusive)
{
    PacketFilter filter;

    cr_assert(filter.parse("minsize=100"));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 99));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 100));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 200));
}

Test(PacketFilter_size, maxsize_boundary_inclusive)
{
    PacketFilter filter;

    cr_assert(filter.parse("maxsize=200"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 200));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 201));
}

Test(PacketFilter_size, minsize_and_maxsize_combined)
{
    PacketFilter filter;

    cr_assert(filter.parse("minsize=100"));
    cr_assert(filter.parse("maxsize=200"));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 50));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 150));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 300));
}

Test(PacketFilter_size, slash_combination_rejected)
{
    PacketFilter minFilter;
    PacketFilter maxFilter;

    cr_assert_not(minFilter.parse("minsize=50/70"));
    cr_assert_not(maxFilter.parse("maxsize=50/70"));
}

Test(PacketFilter_size, invalid_value_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("minsize=abc"));
    cr_assert_not(filter.parse("minsize="));
}

// ===== AND across different keys =====

Test(PacketFilter_combined, proto_and_dport_and)
{
    PacketFilter filter;

    cr_assert(filter.parse("proto=tcp"));
    cr_assert(filter.parse("dport=443"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(51000, 443)));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(17), 66, std::nullopt, makeUdp(51000, 443)));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 66, makeTcp(51000, 80)));
}

// ===== contains =====

Test(PacketFilter_contains, matches_substring_in_tcp_payload)
{
    PacketFilter filter;
    TcpHeader withGet{};
    withGet.payload = {'G', 'E', 'T', ' ', '/', 'i', 'n', 'd', 'e', 'x'};
    TcpHeader withoutGet{};
    withoutGet.payload = {'P', 'O', 'S', 'T', ' ', '/', 'a', 'p', 'i'};

    cr_assert(filter.parse("contains=GET /"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, withGet));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 66, withoutGet));
}

Test(PacketFilter_contains, matches_substring_in_udp_payload)
{
    PacketFilter filter;
    UdpHeader payload{};
    payload.payload = {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};

    cr_assert(filter.parse("contains=example.com"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(17), 66, std::nullopt, payload));
}

Test(PacketFilter_contains, slash_in_text_is_literal_not_split)
{
    PacketFilter filter;
    TcpHeader exactMatch{};
    exactMatch.payload = {'A', '/', 'B'};
    TcpHeader partialOnly{};
    partialOnly.payload = {'A'};

    cr_assert(filter.parse("contains=A/B"));
    cr_assert(filter.matches(makeEthernet(), makeIpv4(6), 66, exactMatch));
    cr_assert_not(filter.matches(makeEthernet(), makeIpv4(6), 66, partialOnly));
}

Test(PacketFilter_contains, no_payload_fails)
{
    PacketFilter filter;

    cr_assert(filter.parse("contains=GET"));
    cr_assert_not(filter.matches(makeEthernet(0x0806), std::nullopt, 60));
}

Test(PacketFilter_contains, empty_value_rejected)
{
    PacketFilter filter;

    cr_assert_not(filter.parse("contains="));
}
