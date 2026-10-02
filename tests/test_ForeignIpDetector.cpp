/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_ForeignIpDetector
*/

#include <criterion/criterion.h>
#include "analysis/ForeignIpDetector.hpp"
#include <vector>

using namespace analyser;

static const std::string LOCAL = "192.168.1.10";
static const std::string GATEWAY = "192.168.1.1";
static const std::string UNKNOWN_LAN = "192.168.2.20";
static const std::string INTERNET = "203.0.113.10";

// Detector trusting only the 192.168.1.0/24 subnet
static ForeignIpDetector makeDetector()
{
    IpWhitelist whitelist;

    whitelist.addEntry("192.168.1.0/24");
    return ForeignIpDetector(whitelist);
}

static std::vector<ForeignIpAlert> send(ForeignIpDetector &detector, const std::string &source,
    const std::string &destination, double timestamp = 0.0, std::uint16_t sourcePort = 50000,
    std::uint16_t destinationPort = 443, const std::string &protocol = "TCP")
{
    return detector.addPacket(timestamp, 100, source, sourcePort, destination, destinationPort, protocol);
}

// ===== trusted traffic =====

Test(ForeignIpDetector, trusted_traffic_no_alert)
{
    ForeignIpDetector detector = makeDetector();

    cr_assert(send(detector, LOCAL, GATEWAY).empty());
    cr_assert(send(detector, GATEWAY, LOCAL).empty());
}

Test(ForeignIpDetector, empty_whitelist_reports_everything)
{
    ForeignIpDetector detector{IpWhitelist()};

    cr_assert_eq(send(detector, LOCAL, GATEWAY).size(), 2, "both IPs are foreign");
}

Test(ForeignIpDetector, ignores_packets_without_ip)
{
    ForeignIpDetector detector = makeDetector();

    cr_assert(send(detector, "", INTERNET).empty(), "ARP / non IPv4 record");
    cr_assert(send(detector, INTERNET, "").empty());
    cr_assert(send(detector, LOCAL, INTERNET).size() == 1, "the IP is still new afterwards");
}

// ===== direction and zone =====

Test(ForeignIpDetector, outgoing_to_wan)
{
    ForeignIpDetector detector = makeDetector();
    std::vector<ForeignIpAlert> alerts = send(detector, LOCAL, INTERNET, 12.5, 50000, 443, "TCP");

    cr_assert_eq(alerts.size(), 1);
    cr_assert_float_eq(alerts[0].timestampSeconds, 12.5, 1e-9);
    cr_assert_eq(alerts[0].foreignIp, INTERNET);
    cr_assert_eq(alerts[0].direction, Direction::Outgoing);
    cr_assert_eq(alerts[0].zone, Zone::Wan);
    cr_assert_eq(alerts[0].sourceIp, LOCAL);
    cr_assert_eq(alerts[0].sourcePort, 50000);
    cr_assert_eq(alerts[0].destinationIp, INTERNET);
    cr_assert_eq(alerts[0].destinationPort, 443);
    cr_assert_eq(alerts[0].protocol, "TCP");
}

Test(ForeignIpDetector, incoming_from_wan)
{
    ForeignIpDetector detector = makeDetector();
    std::vector<ForeignIpAlert> alerts = send(detector, INTERNET, LOCAL, 0.0, 443, 50000);

    cr_assert_eq(alerts.size(), 1);
    cr_assert_eq(alerts[0].foreignIp, INTERNET);
    cr_assert_eq(alerts[0].direction, Direction::Incoming);
    cr_assert_eq(alerts[0].zone, Zone::Wan);
}

Test(ForeignIpDetector, outgoing_to_lan)
{
    ForeignIpDetector detector = makeDetector();
    std::vector<ForeignIpAlert> alerts = send(detector, LOCAL, UNKNOWN_LAN, 0.0, 36556, 53, "UDP");

    cr_assert_eq(alerts.size(), 1);
    cr_assert_eq(alerts[0].foreignIp, UNKNOWN_LAN);
    cr_assert_eq(alerts[0].direction, Direction::Outgoing);
    cr_assert_eq(alerts[0].zone, Zone::Lan, "192.168.2.20 is RFC1918");
}

Test(ForeignIpDetector, incoming_from_lan)
{
    ForeignIpDetector detector = makeDetector();
    std::vector<ForeignIpAlert> alerts = send(detector, "10.0.0.5", LOCAL);

    cr_assert_eq(alerts.size(), 1);
    cr_assert_eq(alerts[0].direction, Direction::Incoming);
    cr_assert_eq(alerts[0].zone, Zone::Lan);
}

Test(ForeignIpDetector, transit_reports_both_ips)
{
    ForeignIpDetector detector = makeDetector();
    std::vector<ForeignIpAlert> alerts = send(detector, UNKNOWN_LAN, INTERNET);

    cr_assert_eq(alerts.size(), 2);
    cr_assert_eq(alerts[0].foreignIp, UNKNOWN_LAN, "source first");
    cr_assert_eq(alerts[0].direction, Direction::Transit);
    cr_assert_eq(alerts[0].zone, Zone::Lan);
    cr_assert_eq(alerts[1].foreignIp, INTERNET);
    cr_assert_eq(alerts[1].direction, Direction::Transit);
    cr_assert_eq(alerts[1].zone, Zone::Wan, "each alert has the zone of its own IP");
}

Test(ForeignIpDetector, transit_with_one_ip_already_reported)
{
    ForeignIpDetector detector = makeDetector();

    cr_assert_eq(send(detector, LOCAL, INTERNET).size(), 1);

    std::vector<ForeignIpAlert> alerts = send(detector, UNKNOWN_LAN, INTERNET);
    cr_assert_eq(alerts.size(), 1, "only the new IP");
    cr_assert_eq(alerts[0].foreignIp, UNKNOWN_LAN);
    cr_assert_eq(alerts[0].direction, Direction::Transit);
}

// ===== reported once =====

Test(ForeignIpDetector, reported_once_per_ip)
{
    ForeignIpDetector detector = makeDetector();
    std::size_t alerts = 0;

    for (int i = 0; i < 50; i++)
        alerts += send(detector, LOCAL, INTERNET, i).size();
    cr_assert_eq(alerts, 1, "50 packets, one alert");
}

Test(ForeignIpDetector, reply_does_not_alert_again)
{
    ForeignIpDetector detector = makeDetector();

    cr_assert_eq(send(detector, LOCAL, INTERNET, 0.0, 50000, 443).size(), 1);
    cr_assert(send(detector, INTERNET, LOCAL, 0.1, 443, 50000).empty(), "same IP, other direction");
}

Test(ForeignIpDetector, other_port_same_ip_no_new_alert)
{
    ForeignIpDetector detector = makeDetector();

    cr_assert_eq(send(detector, LOCAL, INTERNET, 0.0, 50000, 443).size(), 1);
    cr_assert(send(detector, LOCAL, INTERNET, 1.0, 50001, 22).empty(), "one alert per IP, not per port");
}

Test(ForeignIpDetector, each_foreign_ip_reported)
{
    ForeignIpDetector detector = makeDetector();

    cr_assert_eq(send(detector, LOCAL, "203.0.113.10").size(), 1);
    cr_assert_eq(send(detector, LOCAL, "203.0.113.11").size(), 1);
    cr_assert_eq(send(detector, LOCAL, "198.51.100.1").size(), 1);
}

// ===== packets without ports =====

Test(ForeignIpDetector, packet_without_ports)
{
    ForeignIpDetector detector = makeDetector();
    std::vector<ForeignIpAlert> alerts = send(detector, LOCAL, INTERNET, 0.0, 0, 0, "ICMP");

    cr_assert_eq(alerts.size(), 1);
    cr_assert_eq(alerts[0].sourcePort, 0);
    cr_assert_eq(alerts[0].destinationPort, 0);
    cr_assert_eq(alerts[0].protocol, "ICMP");
}
