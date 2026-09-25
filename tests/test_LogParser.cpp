/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_LogParser
*/

#include <criterion/criterion.h>
#include "analysis/LogParser.hpp"
#include <ctime>
#include <sstream>

using namespace sniffer;

static const std::string PREFIX = "[2026-09-25 10:21:00.305] [debug] ";
static const std::string MACS = "94:bb:43:5e:d9:b3 -> 3c:37:12:de:ed:88  ";

static std::optional<LogEntry> parseMinimum(const std::string &line)
{
    std::istringstream empty;
    LogParser parser(empty);

    return parser.parseLine(line);
}

static std::optional<LogEntry> parseHeader(const std::string &line)
{
    std::istringstream empty;
    LogParser parser(empty);

    return parser.parseDetailedLine(line);
}

static double localSeconds(int year, int month, int day, int hour, int minute, int second)
{
    std::tm tmValue{};

    tmValue.tm_year = year - 1900;
    tmValue.tm_mon = month - 1;
    tmValue.tm_mday = day;
    tmValue.tm_hour = hour;
    tmValue.tm_min = minute;
    tmValue.tm_sec = second;
    tmValue.tm_isdst = -1;
    return static_cast<double>(std::mktime(&tmValue));
}

// ===== parseLine (minimum mode) =====

Test(LogParser, parse_line_tcp)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS
        + "192.168.178.170 -> 35.190.46.17  TCP  46340 -> 443  [ACK]  66B");

    cr_assert(entry.has_value());
    cr_assert_float_eq(entry->timestampSeconds,
        localSeconds(2026, 9, 25, 10, 21, 0) + 0.305, 0.0001);
    cr_assert_eq(entry->sizeBytes, 66);
    cr_assert_eq(entry->sourceIp, "192.168.178.170");
    cr_assert_eq(entry->sourcePort, 46340);
    cr_assert_eq(entry->destinationIp, "35.190.46.17");
    cr_assert_eq(entry->destinationPort, 443);
    cr_assert_eq(entry->protocol, "TCP");
    cr_assert(entry->tcpFlags.has_value());
    cr_assert_eq(*entry->tcpFlags, "[ACK]");
}

Test(LogParser, parse_line_tcp_multiple_flags)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS
        + "10.0.0.1 -> 10.0.0.2  TCP  443 -> 51000  [SYN, ACK]  74B");

    cr_assert(entry.has_value());
    cr_assert_eq(*entry->tcpFlags, "[SYN, ACK]");
    cr_assert_eq(entry->destinationPort, 51000);
    cr_assert_eq(entry->sizeBytes, 74);
}

Test(LogParser, parse_line_udp)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS
        + "192.168.178.200 -> 224.0.0.251  UDP  5353 -> 5353  103B");

    cr_assert(entry.has_value());
    cr_assert_eq(entry->sizeBytes, 103);
    cr_assert_eq(entry->sourceIp, "192.168.178.200");
    cr_assert_eq(entry->destinationIp, "224.0.0.251");
    cr_assert_eq(entry->sourcePort, 5353);
    cr_assert_eq(entry->destinationPort, 5353);
    cr_assert_eq(entry->protocol, "UDP");
    cr_assert_not(entry->tcpFlags.has_value());
}

Test(LogParser, parse_line_udp_fragmented_has_no_flags)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS
        + "10.0.0.1 -> 10.0.0.2  UDP  1 -> 53  [FRAGMENTED]  1514B");

    cr_assert(entry.has_value());
    cr_assert_eq(entry->destinationPort, 53);
    cr_assert_eq(entry->sizeBytes, 1514);
    cr_assert_not(entry->tcpFlags.has_value());
}

Test(LogParser, parse_line_ipv4_without_transport)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS
        + "10.0.0.1 -> 10.0.0.2  ICMP  98B");

    cr_assert(entry.has_value());
    cr_assert_eq(entry->sourceIp, "10.0.0.1");
    cr_assert_eq(entry->destinationIp, "10.0.0.2");
    cr_assert_eq(entry->protocol, "ICMP");
    cr_assert_eq(entry->sourcePort, 0);
    cr_assert_eq(entry->destinationPort, 0);
    cr_assert_eq(entry->sizeBytes, 98);
}

Test(LogParser, parse_line_ethernet_only)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS + "EtherType 0x86dd  86B");

    cr_assert(entry.has_value());
    cr_assert_eq(entry->sizeBytes, 86);
    cr_assert_eq(entry->sourceIp, "");
    cr_assert_eq(entry->destinationIp, "");
    cr_assert_eq(entry->destinationPort, 0);
    cr_assert_eq(entry->protocol, "");
    cr_assert_not(entry->tcpFlags.has_value());
}

Test(LogParser, parse_line_invalid_port_keeps_ips)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS
        + "10.0.0.1 -> 10.0.0.2  TCP  70000 -> 443  [ACK]  66B");

    cr_assert(entry.has_value());
    cr_assert_eq(entry->sourceIp, "10.0.0.1");
    cr_assert_eq(entry->sourcePort, 0);
    cr_assert_eq(entry->destinationPort, 0);
    cr_assert_not(entry->tcpFlags.has_value());
}

Test(LogParser, parse_line_tcp_without_ports)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS
        + "10.0.0.1 -> 10.0.0.2  TCP  66B");

    cr_assert(entry.has_value());
    cr_assert_eq(entry->protocol, "TCP");
    cr_assert_eq(entry->sourcePort, 0);
    cr_assert_eq(entry->destinationPort, 0);
    cr_assert_not(entry->tcpFlags.has_value());
}

Test(LogParser, parse_line_tcp_without_flags)
{
    std::optional<LogEntry> entry = parseMinimum(PREFIX + MACS
        + "10.0.0.1 -> 10.0.0.2  TCP  1234 -> 80  66B");

    cr_assert(entry.has_value());
    cr_assert_eq(entry->destinationPort, 80);
    cr_assert_not(entry->tcpFlags.has_value());
}

Test(LogParser, parse_line_rejects_non_debug_level)
{
    cr_assert_not(parseMinimum("[2026-09-25 10:20:59.306] [info] Capture started").has_value());
    cr_assert_not(parseMinimum("[2026-09-25 10:21:02.089] [info] Capture stopped: 26 packet(s) "
        "captured, 0 filtered, 0 error(s)").has_value());
}

Test(LogParser, parse_line_rejects_empty_line)
{
    cr_assert_not(parseMinimum("").has_value());
}

Test(LogParser, parse_line_rejects_line_without_brackets)
{
    cr_assert_not(parseMinimum("not a log line at all").has_value());
}

Test(LogParser, parse_line_rejects_bad_size)
{
    cr_assert_not(parseMinimum(PREFIX + "some plain message").has_value());
    cr_assert_not(parseMinimum(PREFIX + MACS + "EtherType 0x86dd  86").has_value());
    cr_assert_not(parseMinimum(PREFIX + MACS + "EtherType 0x86dd  xB").has_value());
    cr_assert_not(parseMinimum(PREFIX + MACS + "EtherType 0x86dd  B").has_value());
}

Test(LogParser, parse_line_rejects_malformed_timestamp)
{
    cr_assert_not(parseMinimum("[not-a-timestamp] [debug] aa -> bb  EtherType 0x800  66B")
        .has_value());
    cr_assert_not(parseMinimum("[2026-09-25 10:21:00] [debug] aa -> bb  EtherType 0x800  66B")
        .has_value());
    cr_assert_not(parseMinimum("[2026-09-25 10:21:00.] [debug] aa -> bb  EtherType 0x800  66B")
        .has_value());
    cr_assert_not(parseMinimum("[2026-09-25 10:21:00.3x5] [debug] aa -> bb  EtherType 0x800  66B")
        .has_value());
    cr_assert_not(parseMinimum("[2026-13-45 10:21:00.305] [debug] aa -> bb  EtherType 0x800  66B")
        .has_value());
    cr_assert_not(parseMinimum("[hello.305] [debug] aa -> bb  EtherType 0x800  66B").has_value());
}

Test(LogParser, parse_line_rejects_detailed_header)
{
    cr_assert_not(parseMinimum(PREFIX + "==== packet (66 bytes) ====").has_value());
}

// ===== parseDetailedLine (detailed mode header) =====

Test(LogParser, parse_detailed_header)
{
    std::optional<LogEntry> entry = parseHeader(PREFIX + "==== packet (160 bytes) ====");

    cr_assert(entry.has_value());
    cr_assert_eq(entry->sizeBytes, 160);
    cr_assert_float_eq(entry->timestampSeconds,
        localSeconds(2026, 9, 25, 10, 21, 0) + 0.305, 0.0001);
    cr_assert_eq(entry->sourceIp, "");
    cr_assert_eq(entry->destinationPort, 0);
}

Test(LogParser, parse_detailed_header_rejects_invalid)
{
    cr_assert_not(parseHeader("").has_value());
    cr_assert_not(parseHeader("[2026-09-25 10:21:04.301] [info] Capture started").has_value());
    cr_assert_not(parseHeader(PREFIX + "==== packet (x bytes) ====").has_value());
    cr_assert_not(parseHeader(PREFIX + "==== packet ( bytes) ====").has_value());
    cr_assert_not(parseHeader(PREFIX + "==== packet (66 bytes)").has_value());
    cr_assert_not(parseHeader(PREFIX + "==== packet (").has_value());
    cr_assert_not(parseHeader(PREFIX + MACS + "EtherType 0x86dd  86B").has_value());
    cr_assert_not(parseHeader("Ethernet 94:bb:43:5e:d9:b3 -> 3c:37:12:de:ed:88 | EtherType: 0x800")
        .has_value());
}

// ===== nextEntry (whole stream) =====

Test(LogParser, next_entry_minimum_log)
{
    std::istringstream input(
        "[2026-09-25 10:20:59.306] [info] Capture started\n"
        "[2026-09-25 10:20:59.717] [debug] 94:bb -> 3c:37  EtherType 0x86dd  86B\n"
        "[2026-09-25 10:21:00.305] [debug] 94:bb -> 3c:37  192.168.178.170 -> 35.190.46.17  "
        "TCP  46340 -> 443  [ACK]  66B\n"
        "[2026-09-25 10:21:01.751] [debug] 32:2a -> 01:00  192.168.178.200 -> 224.0.0.251  "
        "UDP  5353 -> 5353  103B\n"
        "[2026-09-25 10:21:02.089] [info] Capture stopped: 3 packet(s) captured, 0 filtered, "
        "0 error(s)\n"
        "\n");
    LogParser parser(input);

    std::optional<LogEntry> first = parser.nextEntry();
    std::optional<LogEntry> second = parser.nextEntry();
    std::optional<LogEntry> third = parser.nextEntry();

    cr_assert(first.has_value());
    cr_assert_eq(first->sizeBytes, 86);
    cr_assert_eq(first->sourceIp, "");
    cr_assert(second.has_value());
    cr_assert_eq(second->destinationPort, 443);
    cr_assert_eq(*second->tcpFlags, "[ACK]");
    cr_assert(third.has_value());
    cr_assert_eq(third->protocol, "UDP");
    cr_assert_float_eq(third->timestampSeconds - first->timestampSeconds, 2.034, 0.0001);
    cr_assert_not(parser.nextEntry().has_value());
    cr_assert_eq(parser.getNbLines(), 6);
}

Test(LogParser, next_entry_detailed_log)
{
    std::istringstream input(
        "[2026-09-25 10:21:04.301] [info] Capture started\n"
        "[2026-09-25 10:21:04.618] [debug] ==== packet (160 bytes) ====\n"
        "Ethernet 3c:37:12:de:ed:88 -> 94:bb:43:5e:d9:b3 | EtherType: 0x800\n"
        "  IPv4 51.116.246.107 -> 192.168.178.170 | version=4 ihl=5 tos=0 totalLength=146 "
        "ttl=114 protocol=TCP (6) checksum=0xedc6 (valid=true)\n"
        "    TCP 443 -> 36236 [PSH, ACK] seq=3004977021 ack=1265556807 win=16384 "
        "checksum=0xe28a\n"
        "    payload (4 bytes):\n"
        "17 03 03 00\n"
        "\n"
        "[2026-09-25 10:21:04.861] [debug] ==== packet (86 bytes) ====\n"
        "Ethernet 94:bb:43:5e:d9:b3 -> 3c:37:12:de:ed:88 | EtherType: 0x86dd\n"
        "\n"
        "[2026-09-25 10:21:05.100] [debug] ==== packet (92 bytes) ====\n"
        "Ethernet 94:bb:43:5e:d9:b3 -> 3c:37:12:de:ed:88 | EtherType: 0x800\n"
        "  IPv4 192.168.178.170 -> 192.168.178.1 | version=4 ihl=5 tos=0 totalLength=78 ttl=64 "
        "protocol=UDP (17) checksum=0x845b (valid=true)\n"
        "    UDP 60850 -> 53 len=58 checksum=0x495f\n"
        "    payload (2 bytes):\n"
        "a2 8d\n"
        "\n"
        "[2026-09-25 10:21:06.521] [info] Capture stopped: 3 packet(s) captured, 0 filtered, "
        "0 error(s)\n");
    LogParser parser(input);

    std::optional<LogEntry> tcp = parser.nextEntry();
    std::optional<LogEntry> ipv6 = parser.nextEntry();
    std::optional<LogEntry> udp = parser.nextEntry();

    cr_assert(tcp.has_value());
    cr_assert_eq(tcp->sizeBytes, 160);
    cr_assert_eq(tcp->sourceIp, "51.116.246.107");
    cr_assert_eq(tcp->destinationIp, "192.168.178.170");
    cr_assert_eq(tcp->sourcePort, 443);
    cr_assert_eq(tcp->destinationPort, 36236);
    cr_assert_eq(tcp->protocol, "TCP");
    cr_assert_eq(*tcp->tcpFlags, "[PSH, ACK]");
    cr_assert(ipv6.has_value());
    cr_assert_eq(ipv6->sizeBytes, 86);
    cr_assert_eq(ipv6->sourceIp, "");
    cr_assert_eq(ipv6->destinationPort, 0);
    cr_assert(udp.has_value());
    cr_assert_eq(udp->sizeBytes, 92);
    cr_assert_eq(udp->sourceIp, "192.168.178.170");
    cr_assert_eq(udp->destinationPort, 53);
    cr_assert_eq(udp->protocol, "UDP");
    cr_assert_not(udp->tcpFlags.has_value());
    cr_assert_not(parser.nextEntry().has_value());
    cr_assert_eq(parser.getNbLines(), 19);
}

Test(LogParser, next_entry_detailed_keeps_first_transport)
{
    std::istringstream input(
        "[2026-09-25 10:21:04.618] [debug] ==== packet (66 bytes) ====\n"
        "  IPv4 10.0.0.1 -> 10.0.0.2 | protocol=TCP (6)\n"
        "    TCP 5000 -> 22 [SYN] seq=1 ack=0 win=1 checksum=0x0\n"
        "    TCP 1 -> 2 [RST] seq=1 ack=0 win=1 checksum=0x0\n");
    LogParser parser(input);

    std::optional<LogEntry> entry = parser.nextEntry();

    cr_assert(entry.has_value());
    cr_assert_eq(entry->sourcePort, 5000);
    cr_assert_eq(entry->destinationPort, 22);
    cr_assert_eq(*entry->tcpFlags, "[SYN]");
}

Test(LogParser, next_entry_detailed_transport_without_ipv4_is_ignored)
{
    std::istringstream input(
        "[2026-09-25 10:21:04.618] [debug] ==== packet (66 bytes) ====\n"
        "    TCP 5000 -> 22 [SYN] seq=1 ack=0 win=1 checksum=0x0\n");
    LogParser parser(input);

    std::optional<LogEntry> entry = parser.nextEntry();

    cr_assert(entry.has_value());
    cr_assert_eq(entry->destinationPort, 0);
    cr_assert_eq(entry->protocol, "");
    cr_assert_not(entry->tcpFlags.has_value());
}

Test(LogParser, next_entry_mixed_records)
{
    std::istringstream input(
        "[2026-09-25 10:21:00.000] [debug] aa -> bb  10.0.0.1 -> 10.0.0.2  UDP  1 -> 53  40B\n"
        "[2026-09-25 10:21:00.100] [debug] ==== packet (60 bytes) ====\n"
        "  IPv4 10.0.0.3 -> 10.0.0.4 | protocol=UDP (17)\n"
        "[2026-09-25 10:21:00.200] [debug] aa -> bb  10.0.0.5 -> 10.0.0.6  UDP  1 -> 123  42B");
    LogParser parser(input);

    cr_assert_eq(parser.nextEntry()->destinationPort, 53);
    cr_assert_eq(parser.nextEntry()->sourceIp, "10.0.0.3");
    cr_assert_eq(parser.nextEntry()->destinationPort, 123);
    cr_assert_not(parser.nextEntry().has_value());
    cr_assert_eq(parser.getNbLines(), 4);
}

Test(LogParser, next_entry_skips_garbage_lines)
{
    std::istringstream input(
        "garbage\n"
        "[2026-09-25 10:21:00.000] [debug] hello world\n"
        "[2026-09-25 10:21:00.100] [warning] something\n"
        "[2026-09-25 10:21:00.200] [debug] aa -> bb  EtherType 0x800  60B\n");
    LogParser parser(input);

    std::optional<LogEntry> entry = parser.nextEntry();

    cr_assert(entry.has_value());
    cr_assert_eq(entry->sizeBytes, 60);
    cr_assert_eq(parser.getNbLines(), 4);
}

Test(LogParser, next_entry_empty_stream)
{
    std::istringstream input("");
    LogParser parser(input);

    cr_assert_not(parser.nextEntry().has_value());
    cr_assert_not(parser.nextEntry().has_value());
    cr_assert_eq(parser.getNbLines(), 0);
}

Test(LogParser, get_entry_returns_last_entry)
{
    std::istringstream input("[2026-09-25 10:21:00.000] [debug] aa -> bb  EtherType 0x800  60B\n");
    LogParser parser(input);

    cr_assert_not(parser.getEntry().has_value());
    parser.nextEntry();
    cr_assert(parser.getEntry().has_value());
    cr_assert_eq(parser.getEntry()->sizeBytes, 60);
    parser.nextEntry();
    cr_assert_not(parser.getEntry().has_value());
}
