/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_Report
*/

#include <criterion/criterion.h>
#include "analysis/Report.hpp"
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

using namespace analyser;

// Local time on 2026-10-<day>, in seconds since the epoch
static double at(int hour, int minute, double second, int day = 1)
{
    std::tm tmValue{};

    tmValue.tm_year = 2026 - 1900;
    tmValue.tm_mon = 9;
    tmValue.tm_mday = day;
    tmValue.tm_hour = hour;
    tmValue.tm_min = minute;
    tmValue.tm_isdst = -1;
    return static_cast<double>(std::mktime(&tmValue)) + second;
}

static LogEntry packet(double timestamp, std::size_t size = 1024, std::size_t payloadSize = 0)
{
    LogEntry entry;

    entry.timestampSeconds = timestamp;
    entry.sizeBytes = size;
    entry.payloadSize = payloadSize;
    return entry;
}

static std::string render(const Report &report)
{
    std::ostringstream output;

    report.print(output);
    return output.str();
}

static bool contains(const std::string &text, const std::string &part)
{
    return text.find(part) != std::string::npos;
}

static std::vector<std::string> alertLines(const std::string &text)
{
    std::istringstream input(text);
    std::vector<std::string> lines;
    std::string line;

    while (std::getline(input, line))
        if (!line.empty() && line[0] == '[')
            lines.push_back(line);
    return lines;
}

static std::string spaces(std::size_t count)
{
    return std::string(count, ' ');
}

static ProtocolMismatchAlert mismatch(const std::vector<std::uint8_t> &preview, std::size_t payloadSize,
    Protocol expected = Protocol::Http, Protocol detected = Protocol::Unknown)
{
    return ProtocolMismatchAlert{at(10, 0, 0.0), "127.0.0.1", 80, "127.0.0.3", 51234, "TCP", 80,
        expected, detected, payloadSize, preview};
}

static std::vector<std::uint8_t> bytes(const std::string &text)
{
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

// ===== formatting =====

Test(Report, format_bytes)
{
    cr_assert_eq(Report::formatBytes(0), "0 B");
    cr_assert_eq(Report::formatBytes(1023), "1023 B");
    cr_assert_eq(Report::formatBytes(1024), "1.0 KB");
    cr_assert_eq(Report::formatBytes(1536), "1.5 KB");
    cr_assert_eq(Report::formatBytes(1024 * 1024), "1.0 MB");
    cr_assert_eq(Report::formatBytes(1024 * 1024 - 1), "1.0 MB", "never displayed as 1024.0 KB");
    cr_assert_eq(Report::formatBytes(5ull * 1024 * 1024 * 1024), "5.0 GB");
}

Test(Report, format_duration)
{
    cr_assert_eq(Report::formatDuration(0.0), "0.0s");
    cr_assert_eq(Report::formatDuration(8.34), "8.3s");
    cr_assert_eq(Report::formatDuration(59.9), "59.9s");
    cr_assert_eq(Report::formatDuration(59.96), "1m 00s", "never displayed as 60.0s");
    cr_assert_eq(Report::formatDuration(125.0), "2m 05s");
    cr_assert_eq(Report::formatDuration(3725.0), "1h 02m 05s");
}

Test(Report, format_time)
{
    cr_assert_eq(Report::formatTime(at(14, 36, 59.266)), "2026-10-01 14:36:59.266");
    cr_assert_eq(Report::formatTime(at(9, 5, 3.0)), "2026-10-01 09:05:03.000");
    cr_assert_eq(Report::formatTime(at(14, 36, 59.9996)), "2026-10-01 14:37:00.000",
        "rounding to the millisecond carries to the next second");
}

Test(Report, names)
{
    cr_assert_eq(Report::name(Detection::ServiceSpike), "SERVICE-SPIKE");
    cr_assert_eq(Report::name(Detection::NetworkSpike), "NETWORK-SPIKE");
    cr_assert_eq(Report::name(Detection::Beacon), "BEACON");
    cr_assert_eq(Report::name(Detection::ProtocolMismatch), "PROTO-MISMATCH");
    cr_assert_eq(Report::name(Detection::ForeignIp), "FOREIGN-IP");
}

Test(Report, descriptions_use_the_detector_settings)
{
    cr_assert(contains(Report::description(Detection::ServiceSpike),
        "more than " + std::to_string(SpikeServicesDetector::limit) + " packets"));
    cr_assert(contains(Report::description(Detection::NetworkSpike), "at least 3x"));
    cr_assert(contains(Report::description(Detection::Beacon),
        std::to_string(BeaconDetector::minOccurrences) + " connections"));
    cr_assert(contains(Report::description(Detection::ProtocolMismatch), "standard TCP port"));
    cr_assert(contains(Report::description(Detection::ForeignIp), "outside the whitelist"));
}

// ===== one line per alert =====

Test(Report, service_spike_line)
{
    Report report;

    report.add(SpikeAlert{at(10, 0, 8.3), at(10, 0, 0.0), "10.0.0.1", "10.0.0.2", 443, 612, 62669});

    std::vector<std::string> lines = alertLines(render(report));
    cr_assert_eq(lines.size(), 1);
    cr_assert_eq(lines[0], "[2026-10-01 10:00:08.300] [SERVICE-SPIKE]  10.0.0.1 -> 10.0.0.2:443  "
        "612 packets, 61.2 KB in 8.3s (limit " + std::to_string(SpikeServicesDetector::limit) + " per 10s)");
}

Test(Report, network_spike_line)
{
    Report report;

    report.add(NetworkSpikeAlert{at(10, 0, 9.8), at(10, 0, 0.0), 1200, 1300000, 100.0});

    std::vector<std::string> lines = alertLines(render(report));
    cr_assert_eq(lines.size(), 1);
    cr_assert_eq(lines[0], "[2026-10-01 10:00:09.800] [NETWORK-SPIKE]  whole network  "
        "1200 packets, 1.2 MB in 9.8s (>= 3x usual 100.0 packets per 10s)");
}

Test(Report, beacon_line)
{
    Report report;

    report.add(BeaconAlert{at(10, 0, 40.0), "192.168.1.10", "203.0.113.10", 443, 5, 10.0, 0.024});

    std::vector<std::string> lines = alertLines(render(report));
    cr_assert_eq(lines.size(), 1);
    cr_assert_eq(lines[0], "[2026-10-01 10:00:40.000] [BEACON]" + spaces(9) + "192.168.1.10 -> 203.0.113.10:443  "
        "5 connections every 10.0s (deviation 0.02s)");
}

Test(Report, protocol_mismatch_text_payload)
{
    Report report;

    report.add(mismatch(bytes("hello fr"), 35));

    std::vector<std::string> lines = alertLines(render(report));
    cr_assert_eq(lines.size(), 1);
    cr_assert_eq(lines[0], "[2026-10-01 10:00:00.000] [PROTO-MISMATCH] 127.0.0.1:80 -> 127.0.0.3:51234 TCP  "
        "expected HTTP on port 80, got unknown (35 B, starts with \"hello fr...\")");
}

Test(Report, protocol_mismatch_short_text_is_not_truncated)
{
    Report report;

    report.add(mismatch(bytes("hello\n"), 6));
    cr_assert(contains(render(report), "(6 B, starts with \"hello.\")"), "line feed displayed as a dot");
}

Test(Report, protocol_mismatch_binary_payload_in_hex)
{
    Report report;

    report.add(mismatch({0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01}, 517, Protocol::Ssh, Protocol::Tls));
    cr_assert(contains(render(report),
        "expected SSH on port 80, got TLS (517 B, starts with 16 03 01 02 00 01 00 01 ...)"));
}

Test(Report, protocol_mismatch_without_preview)
{
    Report report;

    report.add(mismatch({}, 35));
    cr_assert(contains(render(report), "got unknown (35 B)"));
}

Test(Report, foreign_ip_lines)
{
    Report report;

    report.add(ForeignIpAlert{at(10, 0, 1.0), "140.82.113.22", Direction::Outgoing, Zone::Wan,
        "192.168.1.10", 59050, "140.82.113.22", 443, "TCP"});
    report.add(ForeignIpAlert{at(10, 0, 2.0), "192.168.1.99", Direction::Incoming, Zone::Lan,
        "192.168.1.99", 40000, "192.168.1.10", 22, "TCP"});
    report.add(ForeignIpAlert{at(10, 0, 3.0), "10.0.0.5", Direction::Transit, Zone::Lan,
        "10.0.0.5", 0, "8.8.8.8", 0, "ICMP"});

    std::vector<std::string> lines = alertLines(render(report));
    cr_assert_eq(lines.size(), 3);
    cr_assert(contains(lines[0], "[FOREIGN-IP]" + spaces(5) + "192.168.1.10:59050 -> 140.82.113.22:443 TCP"));
    cr_assert(contains(lines[0], "outgoing to WAN" + spaces(4) + "=> destination 140.82.113.22 not in whitelist"));
    cr_assert(contains(lines[1], "[FOREIGN-IP]" + spaces(5) + "192.168.1.99:40000 -> 192.168.1.10:22 TCP"));
    cr_assert(contains(lines[1], "incoming from LAN  => source 192.168.1.99 not in whitelist"));
    cr_assert(contains(lines[2], "[FOREIGN-IP]" + spaces(5) + "10.0.0.5 -> 8.8.8.8 ICMP"), "no port: only the IPs");
    cr_assert(contains(lines[2], "transit, LAN" + spaces(7) + "=> 10.0.0.5 not in whitelist"));
    for (const std::string &line : lines)
        cr_assert_eq(line.find("=>"), lines[0].find("=>"), "arrows in the same column: %s", line.c_str());
}

Test(Report, tags_are_left_aligned)
{
    Report report;

    report.add(BeaconAlert{at(10, 0, 1.0), "10.0.0.1", "10.0.0.2", 80, 5, 10.0, 0.0});
    report.add(mismatch(bytes("hello fr"), 35));
    report.add(SpikeAlert{at(10, 0, 8.3), at(10, 0, 0.0), "10.0.0.1", "10.0.0.2", 443, 612, 62669});

    std::vector<std::string> lines = alertLines(render(report));
    cr_assert_eq(lines.size(), 3);
    for (const std::string &line : lines)
        cr_assert_eq(line.find("] [") + 2, 26, "tag right after the time: %s", line.c_str());
    cr_assert(contains(lines[0], "] [BEACON] "));
    cr_assert(contains(lines[1], "] [PROTO-MISMATCH] 127.0.0.1:80"));
    cr_assert(contains(lines[2], "] [SERVICE-SPIKE] "));
}

// ===== layout =====


Test(Report, very_long_flow_does_not_widen_the_column)
{
    Report report;
    std::string longIp(Report::maxFlowWidth + 20, '9');

    report.add(BeaconAlert{at(10, 0, 1.0), "10.0.0.1", "10.0.0.2", 80, 5, 10.0, 0.0});
    report.add(BeaconAlert{at(10, 0, 2.0), longIp, "10.0.0.2", 80, 5, 10.0, 0.0});

    std::vector<std::string> lines = alertLines(render(report));
    std::size_t flowStart = lines[0].find("10.0.0.1");
    cr_assert_eq(lines[0].find("5 connections"), flowStart + Report::maxFlowWidth + 2);
    cr_assert(contains(lines[1], ":80  5 connections"), "the long line is not cut");
}

Test(Report, alerts_keep_their_order)
{
    Report report;

    report.add(BeaconAlert{at(10, 0, 1.0), "10.0.0.1", "10.0.0.2", 80, 5, 10.0, 0.0});
    report.add(NetworkSpikeAlert{at(10, 0, 2.0), at(10, 0, 0.0), 1200, 1300000, 100.0});
    report.add(BeaconAlert{at(10, 0, 3.0), "10.0.0.1", "10.0.0.3", 80, 5, 10.0, 0.0});

    std::vector<std::string> lines = alertLines(render(report));
    cr_assert_eq(lines.size(), 3);
    cr_assert(contains(lines[0], "10:00:01.000"));
    cr_assert(contains(lines[1], "[NETWORK-SPIKE]"));
    cr_assert(contains(lines[2], "10.0.0.3:80"));
}

Test(Report, sections_order)
{
    Report report;
    std::string text = render(report);

    cr_assert_eq(text.find("===== Log analysis ====="), 0);
    cr_assert_lt(text.find("===== Log analysis ====="), text.find("===== Alerts: 0 ====="));
    cr_assert_lt(text.find("===== Alerts: 0 ====="), text.find("===== Summary ====="));
}

// ===== overview =====

Test(Report, overview)
{
    Report report;

    report.setLog("capture.log", 2);
    report.addLines(60);
    report.addLines(40);
    report.addPacket(packet(at(10, 0, 0.0)));
    report.addPacket(packet(at(10, 0, 23.5)));
    report.addPacket(packet(at(10, 0, 10.0)));

    std::string text = render(report);
    cr_assert(contains(text, "Log:       capture.log, 2 file(s), 100 line(s) read\n"));
    cr_assert(contains(text, "Capture:   2026-10-01 10:00:00 -> 10:00:23 (23.5s)\n"), "date not repeated: %s",
        text.c_str());
    cr_assert(contains(text, "Traffic:   3 packet record(s), 3.0 KB\n"));
    cr_assert(contains(text, "Whitelist: none\n"));
}

Test(Report, overview_capture_over_two_days)
{
    Report report;

    report.addPacket(packet(at(23, 59, 50.0, 1)));
    report.addPacket(packet(at(0, 0, 10.0, 2)));
    cr_assert(contains(render(report), "Capture:   2026-10-01 23:59:50 -> 2026-10-02 00:00:10 (20.0s)\n"));
}

Test(Report, overview_without_packet)
{
    Report report;
    std::string text = render(report);

    cr_assert(contains(text, "Capture:   no packet record\n"));
    cr_assert(contains(text, "Traffic:   0 packet record(s), 0 B\n"));
}

Test(Report, overview_whitelist)
{
    Report report;

    report.setWhitelist("config/whitelist.conf", 8);
    cr_assert(contains(render(report), "Whitelist: 8 range(s) from config/whitelist.conf\n"));
}

// ===== summary =====

Test(Report, summary_without_alert)
{
    Report report;
    std::string text = render(report);

    cr_assert(contains(text, "===== Alerts: 0 =====\nNo alert raised.\n"));
    cr_assert(contains(text, "SERVICE-SPIKE" + spaces(10) + "0  more than "));
    cr_assert(contains(text, "NETWORK-SPIKE" + spaces(10) + "0  network traffic"));
    cr_assert(contains(text, "BEACON" + spaces(17) + "0  "));
    cr_assert(contains(text, "Total" + spaces(18) + "0  alert(s)\n"));
}

Test(Report, summary_disabled_detections)
{
    Report report;
    std::string text = render(report);

    cr_assert_eq(*report.disabledReason(Detection::ProtocolMismatch), "no payload in the log, capture with my_sniffer -d");
    cr_assert_eq(*report.disabledReason(Detection::ForeignIp), "no whitelist, use -w <whitelist>");
    cr_assert_not(report.disabledReason(Detection::Beacon).has_value());
    cr_assert(contains(text, "PROTO-MISMATCH  disabled  no payload in the log, capture with my_sniffer -d\n"));
    cr_assert(contains(text, "FOREIGN-IP" + spaces(6) + "disabled  no whitelist, use -w <whitelist>\n"));
}

Test(Report, summary_enabled_detections)
{
    Report report;

    report.setWhitelist("whitelist.conf", 1);
    report.addPacket(packet(at(10, 0, 0.0), 100, 0));
    cr_assert(report.disabledReason(Detection::ProtocolMismatch).has_value(), "no payload yet");
    report.addPacket(packet(at(10, 0, 1.0), 100, 12));
    cr_assert_not(report.disabledReason(Detection::ProtocolMismatch).has_value());
    cr_assert_not(report.disabledReason(Detection::ForeignIp).has_value());

    std::string text = render(report);
    cr_assert(contains(text, "PROTO-MISMATCH" + spaces(9) + "0  payload not matching"));
    cr_assert(contains(text, "FOREIGN-IP" + spaces(13) + "0  traffic to or from an IP outside the whitelist\n"));
}

Test(Report, summary_counts)
{
    Report report;

    report.setWhitelist("whitelist.conf", 1);
    report.add(SpikeAlert{at(10, 0, 8.3), at(10, 0, 0.0), "10.0.0.1", "10.0.0.2", 443, 612, 62669});
    report.add(ForeignIpAlert{at(10, 0, 1.0), "8.8.8.8", Direction::Outgoing, Zone::Wan,
        "192.168.1.10", 40000, "8.8.8.8", 53, "UDP"});
    report.add(ForeignIpAlert{at(10, 0, 2.0), "1.1.1.1", Direction::Outgoing, Zone::Wan,
        "192.168.1.10", 40001, "1.1.1.1", 53, "UDP"});

    std::string text = render(report);
    cr_assert_eq(report.count(Detection::ServiceSpike), 1);
    cr_assert_eq(report.count(Detection::ForeignIp), 2);
    cr_assert_eq(report.count(Detection::Beacon), 0);
    cr_assert(contains(text, "===== Alerts: 3 =====\n["));
    cr_assert(contains(text, "SERVICE-SPIKE" + spaces(10) + "1  "));
    cr_assert(contains(text, "FOREIGN-IP" + spaces(13) + "2  "));
    cr_assert(contains(text, "Total" + spaces(18) + "3  alert(s)\n"));
}
