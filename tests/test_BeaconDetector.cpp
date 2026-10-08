/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_BeaconDetector
*/

#include <criterion/criterion.h>
#include "analysis/BeaconDetector.hpp"
#include <vector>

using namespace analyser;

static constexpr std::size_t OCCURRENCES = BeaconDetector::minOccurrences;
static constexpr double CONNECTION_GAP = BeaconDetector::connectionGapSeconds;

// One connection (one packet) at each timestamp, returns the alerts
static std::vector<BeaconAlert> connect(BeaconDetector &detector, const std::vector<double> &timestamps,
    const std::string &destination = "203.0.113.10", std::uint16_t port = 443)
{
    std::vector<BeaconAlert> alerts;

    for (double timestamp : timestamps)
        if (std::optional<BeaconAlert> alert = detector.addPacket(timestamp, "192.168.1.10", destination, port))
            alerts.push_back(*alert);
    return alerts;
}

// `count` connections every `interval` seconds starting at `start`
static std::vector<double> every(double interval, std::size_t count, double start = 0.0)
{
    std::vector<double> timestamps;

    for (std::size_t i = 0; i < count; i++)
        timestamps.push_back(start + i * interval);
    return timestamps;
}

// ===== regular connections =====

Test(BeaconDetector, no_alert_before_min_occurrences)
{
    BeaconDetector detector;

    cr_assert(connect(detector, every(10.0, OCCURRENCES - 1)).empty());
}

Test(BeaconDetector, alert_at_min_occurrences)
{
    BeaconDetector detector;
    std::vector<BeaconAlert> alerts = connect(detector, every(10.0, OCCURRENCES, 100.0));

    cr_assert_eq(alerts.size(), 1);
    cr_assert_float_eq(alerts[0].timestampSeconds, 100.0 + (OCCURRENCES - 1) * 10.0, 1e-9,
        "alert on the last connection of the series");
    cr_assert_eq(alerts[0].sourceIp, "192.168.1.10");
    cr_assert_eq(alerts[0].destinationIp, "203.0.113.10");
    cr_assert_eq(alerts[0].destinationPort, 443);
    cr_assert_eq(alerts[0].occurrences, OCCURRENCES);
    cr_assert_float_eq(alerts[0].intervalSeconds, 10.0, 1e-9);
    cr_assert_float_eq(alerts[0].deviationSeconds, 0.0, 1e-9);
}

Test(BeaconDetector, reported_once)
{
    BeaconDetector detector;

    cr_assert_eq(connect(detector, every(10.0, OCCURRENCES * 5)).size(), 1,
        "the beacon goes on: still one alert");
}

Test(BeaconDetector, long_interval)
{
    BeaconDetector detector;

    // one connection per hour
    cr_assert_eq(connect(detector, every(3600.0, OCCURRENCES)).size(), 1);
}

// ===== jitter =====

// `count` connections every `interval` seconds, every other one `offset` seconds late
static std::vector<double> jittered(double interval, double offset, std::size_t count)
{
    std::vector<double> timestamps = every(interval, count);

    for (std::size_t i = 1; i < count; i += 2)
        timestamps[i] += offset;
    return timestamps;
}

Test(BeaconDetector, small_jitter_alerts)
{
    BeaconDetector detector;
    // intervals 10.5, 9.5, 10.5...: deviation 0.5s, 5% of 10s
    std::vector<BeaconAlert> alerts = connect(detector, jittered(10.0, 0.5, OCCURRENCES));

    cr_assert_eq(alerts.size(), 1);
    cr_assert_float_eq(alerts[0].intervalSeconds, 10.0, 0.2);
    cr_assert_gt(alerts[0].deviationSeconds, 0.0);
    cr_assert_leq(alerts[0].deviationSeconds, BeaconDetector::maxDeviation * alerts[0].intervalSeconds);
}

Test(BeaconDetector, large_jitter_does_not_alert)
{
    BeaconDetector detector;

    // intervals 13, 7, 13...: deviation 3s, 30% of 10s
    cr_assert(connect(detector, jittered(10.0, 3.0, OCCURRENCES * 2)).empty());
}

Test(BeaconDetector, irregular_traffic_does_not_alert)
{
    BeaconDetector detector;

    cr_assert(connect(detector, {0.0, 3.0, 25.0, 27.5, 60.0, 61.2, 90.0, 140.0, 141.5, 200.0}).empty());
}

Test(BeaconDetector, regular_after_irregular_start)
{
    BeaconDetector detector;
    // irregular, then every 5s: only the last minOccurrences connections count
    std::vector<double> timestamps = {0.0, 2.0, 11.0, 13.5};
    for (double timestamp : every(5.0, OCCURRENCES, 20.0))
        timestamps.push_back(timestamp);

    std::vector<BeaconAlert> alerts = connect(detector, timestamps);
    cr_assert_eq(alerts.size(), 1);
    cr_assert_float_eq(alerts[0].intervalSeconds, 5.0, 1e-9);
}

// ===== packets grouped into connections =====

Test(BeaconDetector, packets_of_one_request_are_one_connection)
{
    BeaconDetector detector;
    std::vector<BeaconAlert> alerts;

    // each request: 5 packets in 0.2s (handshake, data, close)
    for (double start : every(10.0, OCCURRENCES))
        for (double offset : {0.0, 0.01, 0.05, 0.1, 0.2})
            for (const BeaconAlert &alert : connect(detector, {start + offset}))
                alerts.push_back(alert);

    cr_assert_eq(alerts.size(), 1);
    cr_assert_eq(alerts[0].occurrences, OCCURRENCES, "5 packets per request count as 1 connection");
    cr_assert_float_eq(alerts[0].intervalSeconds, 10.0, 1e-9, "interval measured between connection starts");
}

Test(BeaconDetector, continuous_stream_is_one_connection)
{
    BeaconDetector detector;

    // a packet every 0.5s for 100s: one long connection, not a beacon
    cr_assert(connect(detector, every(0.5, 200)).empty());
}

Test(BeaconDetector, connection_gap_boundary)
{
    BeaconDetector detector;

    // just under the gap: one long connection, never a beacon
    cr_assert(connect(detector, every(CONNECTION_GAP - 0.001, OCCURRENCES * 3)).empty());

    // exactly the gap: each packet is a new connection, at a constant interval
    BeaconDetector other;
    std::vector<BeaconAlert> alerts = connect(other, every(CONNECTION_GAP, OCCURRENCES));
    cr_assert_eq(alerts.size(), 1, "a gap of exactly connectionGapSeconds starts a new connection");
    cr_assert_float_eq(alerts[0].intervalSeconds, CONNECTION_GAP, 1e-9);
}

// ===== one series per destination =====

Test(BeaconDetector, destinations_tracked_separately)
{
    BeaconDetector detector;
    std::vector<BeaconAlert> alerts;

    // two beacons interleaved: port 443 every 10s, port 8080 every 7s
    for (std::size_t i = 0; i < OCCURRENCES; i++) {
        for (const BeaconAlert &alert : connect(detector, {i * 10.0}, "203.0.113.10", 443))
            alerts.push_back(alert);
        for (const BeaconAlert &alert : connect(detector, {i * 7.0 + 3.0}, "203.0.113.10", 8080))
            alerts.push_back(alert);
    }
    cr_assert_eq(alerts.size(), 2);
    cr_assert_neq(alerts[0].destinationPort, alerts[1].destinationPort, "one alert per destination");
}

Test(BeaconDetector, same_port_other_ip_is_another_destination)
{
    BeaconDetector detector;

    // 3 connections to each IP: neither reaches minOccurrences on its own
    for (double timestamp : every(10.0, 3)) {
        cr_assert(connect(detector, {timestamp}, "203.0.113.10", 443).empty());
        cr_assert(connect(detector, {timestamp + 5.0}, "203.0.113.11", 443).empty());
    }
}

Test(BeaconDetector, ignores_packets_without_destination)
{
    BeaconDetector detector;

    for (double timestamp : every(10.0, OCCURRENCES * 2)) {
        cr_assert_not(detector.addPacket(timestamp, "192.168.1.10", "", 443).has_value());
        cr_assert_not(detector.addPacket(timestamp, "192.168.1.10", "203.0.113.10", 0).has_value(),
            "port 0 (ICMP) is not a destination service");
    }
}

// ===== TCP: only new connections (SYN) and data (PSH) count =====

// One TCP packet with these flags at each timestamp, returns the alerts
static std::vector<BeaconAlert> tcp(BeaconDetector &detector, const std::vector<double> &timestamps,
    const std::string &flags, const std::string &source = "192.168.1.10", const std::string &destination = "203.0.113.10",
    std::uint16_t port = 443)
{
    std::vector<BeaconAlert> alerts;

    for (double timestamp : timestamps)
        if (std::optional<BeaconAlert> alert = detector.addPacket(timestamp, source, destination, port, flags))
            alerts.push_back(*alert);
    return alerts;
}

Test(BeaconDetector, keep_alive_acks_do_not_alert)
{
    BeaconDetector detector;
    std::vector<BeaconAlert> alerts;

    // an open connection exchanging empty ACKs every 1.05s, in both directions
    for (double timestamp : every(1.05, 40)) {
        for (const BeaconAlert &alert : tcp(detector, {timestamp}, "[ACK]", "10.56.223.124", "35.190.46.17", 443))
            alerts.push_back(alert);
        for (const BeaconAlert &alert : tcp(detector, {timestamp + 0.2}, "[ACK]", "35.190.46.17", "10.56.223.124", 44990))
            alerts.push_back(alert);
    }
    cr_assert(alerts.empty(), "pure ACKs are not connections");
}

Test(BeaconDetector, tcp_new_connection_every_interval)
{
    BeaconDetector detector;
    std::vector<BeaconAlert> alerts;

    // each beacon: SYN, ACK, request, ACK, close
    for (double start : every(10.0, OCCURRENCES)) {
        for (const auto &[offset, flags] : std::vector<std::pair<double, std::string>>{
                {0.0, "[SYN]"}, {0.02, "[ACK]"}, {0.03, "[PSH, ACK]"}, {0.1, "[ACK]"}, {0.2, "[FIN, ACK]"}})
            for (const BeaconAlert &alert : tcp(detector, {start + offset}, flags))
                alerts.push_back(alert);
    }
    cr_assert_eq(alerts.size(), 1);
    cr_assert_float_eq(alerts[0].intervalSeconds, 10.0, 1e-9);
}

Test(BeaconDetector, tcp_requests_on_persistent_connection)
{
    BeaconDetector detector;
    std::vector<BeaconAlert> alerts;

    // a request (PSH) every 10s on a connection that stays open, keep-alive ACKs in between
    for (double start : every(10.0, OCCURRENCES)) {
        for (const BeaconAlert &alert : tcp(detector, {start}, "[PSH, ACK]"))
            alerts.push_back(alert);
        for (const BeaconAlert &alert : tcp(detector, every(1.05, 8, start + 1.0), "[ACK]"))
            alerts.push_back(alert);
    }
    cr_assert_eq(alerts.size(), 1);
    cr_assert_float_eq(alerts[0].intervalSeconds, 10.0, 1e-9, "the keep-alive ACKs must not break the series");
}
