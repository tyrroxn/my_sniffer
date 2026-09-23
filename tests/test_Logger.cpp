/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_Logger
*/

#include <criterion/criterion.h>
#include <cstdio>
#include <fstream>
#include <sstream>
#include "log/Logger.hpp"

using namespace sniffer;

static std::string readFile(const std::string &path)
{
    std::ifstream file(path);
    std::ostringstream oss;

    oss << file.rdbuf();
    return oss.str();
}

// ===== init / debug / info / warn / error =====

Test(Logger, inactive_does_not_crash_or_create_file)
{
    std::string path = "/tmp/my_sniffer_test_logger_inactive.log";
    std::remove(path.c_str());

    Logger::init(false, path);
    Logger::debug("debug message");
    Logger::info("info message");
    Logger::warn("warn message");
    Logger::error("error message");

    std::ifstream file(path);
    cr_assert_not(file.good(), "no log file should be created when logging is inactive");
}

Test(Logger, active_writes_all_levels_to_file)
{
    std::string path = "/tmp/my_sniffer_test_logger_levels.log";
    std::remove(path.c_str());

    Logger::init(true, path);
    Logger::debug("debug message");
    Logger::info("info message");
    Logger::warn("warn message");
    Logger::error("error message");

    std::string content = readFile(path);
    cr_assert(content.find("[debug] debug message") != std::string::npos);
    cr_assert(content.find("[info] info message") != std::string::npos);
    cr_assert(content.find("warning] warn message") != std::string::npos);
    cr_assert(content.find("[error] error message") != std::string::npos);
}

Test(Logger, no_blank_lines_between_entries)
{
    std::string path = "/tmp/my_sniffer_test_logger_no_blank.log";
    std::remove(path.c_str());

    Logger::init(true, path);
    Logger::debug("line one");
    Logger::debug("line two");

    std::string content = readFile(path);
    cr_assert_eq(content.find("\n\n"), std::string::npos,
        "consecutive log entries must not be separated by a blank line");
}

// ===== writeLog helpers =====

static EthernetHeader makeEthernet()
{
    EthernetHeader eth;

    eth.sourceMac = "aa:bb:cc:dd:ee:ff";
    eth.destinationMac = "11:22:33:44:55:66";
    eth.etherType = 0x0800;
    eth.vlanTagged = false;
    return eth;
}

static Ipv4Header makeIpv4()
{
    Ipv4Header ip;

    ip.version = 4;
    ip.ihl = 5;
    ip.typeOfService = 0;
    ip.totalLength = 52;
    ip.ttl = 64;
    ip.protocol = 6;
    ip.headerChecksum = 0x1234;
    ip.checksumValid = true;
    ip.DF_flag = true;
    ip.MF_flag = false;
    ip.isFragmented = false;
    ip.fragmentOffset = 0;
    ip.headerLength = 20;
    ip.sourceAddress = "10.0.0.1";
    ip.destinationAddress = "10.0.0.2";
    return ip;
}

static TcpHeader makeTcp()
{
    TcpHeader tcp{};

    tcp.sourcePort = 443;
    tcp.destinationPort = 51000;
    tcp.ACK_flag = true;
    tcp.windowSize = 254;
    tcp.checksum = 0xbeef;
    return tcp;
}

// ===== writeLog: Minimum (verbose = false) =====

Test(Logger_writeLog, minimum_ethernet_only)
{
    RawPacket packet;
    packet.buffer = std::vector<std::uint8_t>(66, 0);

    std::string text = Logger::writeLog(packet, makeEthernet(), std::nullopt, std::nullopt, std::nullopt, false);

    cr_assert_eq(text, "aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66  EtherType 0x800  66B");
}

Test(Logger_writeLog, minimum_with_tcp)
{
    RawPacket packet;
    packet.buffer = std::vector<std::uint8_t>(66, 0);

    std::string text = Logger::writeLog(packet, makeEthernet(), makeIpv4(), makeTcp(), std::nullopt, false);

    cr_assert(text.find("10.0.0.1 -> 10.0.0.2") != std::string::npos);
    cr_assert(text.find("TCP") != std::string::npos);
    cr_assert(text.find("443 -> 51000") != std::string::npos);
    cr_assert(text.find("[ACK]") != std::string::npos);
    cr_assert(text.find("66B") != std::string::npos);
    cr_assert_eq(text.find('\n'), std::string::npos, "minimum format must be a single line");
}

Test(Logger_writeLog, minimum_fragmented_tag)
{
    RawPacket packet;
    packet.buffer = std::vector<std::uint8_t>(66, 0);
    Ipv4Header ip = makeIpv4();
    ip.isFragmented = true;
    ip.MF_flag = true;

    std::string text = Logger::writeLog(packet, makeEthernet(), ip, std::nullopt, std::nullopt, false);

    cr_assert(text.find("[FRAGMENTED]") != std::string::npos);
}

// ===== writeLog: Detailed (verbose = true) =====

Test(Logger_writeLog, detailed_contains_all_layers)
{
    RawPacket packet;
    packet.buffer = std::vector<std::uint8_t>(66, 0);

    std::string text = Logger::writeLog(packet, makeEthernet(), makeIpv4(), makeTcp(), std::nullopt, true);

    cr_assert(text.find("Ethernet aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66") != std::string::npos);
    cr_assert(text.find("IPv4 10.0.0.1 -> 10.0.0.2") != std::string::npos);
    cr_assert(text.find("TCP 443 -> 51000") != std::string::npos);
    cr_assert(text.find('\n') != std::string::npos, "detailed format must be multi-line");
}

Test(Logger_writeLog, detailed_with_udp_payload)
{
    RawPacket packet;
    packet.buffer = std::vector<std::uint8_t>(66, 0);

    UdpHeader udp;
    udp.sourcePort = 53;
    udp.destinationPort = 12345;
    udp.length = 40;
    udp.checksum = 0xcafe;
    udp.payload = {0x01, 0x02, 0x03};

    std::string text = Logger::writeLog(packet, makeEthernet(), makeIpv4(), std::nullopt, udp, true);

    cr_assert(text.find("UDP 53 -> 12345") != std::string::npos);
    cr_assert(text.find("payload (3 bytes)") != std::string::npos);
}

Test(Logger_writeLog, detailed_ethernet_only_no_ipv4)
{
    RawPacket packet;
    packet.buffer = std::vector<std::uint8_t>(86, 0);
    EthernetHeader eth = makeEthernet();
    eth.etherType = 0x86dd;

    std::string text = Logger::writeLog(packet, eth, std::nullopt, std::nullopt, std::nullopt, true);

    cr_assert(text.find("EtherType: 0x86dd") != std::string::npos);
    cr_assert(text.find("IPv4") == std::string::npos);
}
