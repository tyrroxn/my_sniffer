/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_SpikeServicesDetector
*/

#include <criterion/criterion.h>
#include "analysis/SpikeServicesDetector.hpp"

using namespace analyser;

static constexpr std::size_t LIMIT = SpikeServicesDetector::limit;
static constexpr double WINDOW = SpikeServicesDetector::windowSeconds;
static constexpr double REALERT = SpikeServicesDetector::realertSeconds;

// Sends `count` packets at `timestamp` to one service, returns the last result
static std::optional<SpikeAlert> send(SpikeServicesDetector &detector, std::size_t count,
    double timestamp = 0.0, std::uint16_t port = 443, const std::string &source = "10.0.0.1",
    const std::string &destination = "10.0.0.2", std::size_t bytes = 100)
{
    std::optional<SpikeAlert> last;

    for (std::size_t i = 0; i < count; i++)
        last = detector.addPacket(timestamp, bytes, source, destination, port);
    return last;
}

// Sends `perSecond` packets every second from `from` to `to` (included), returns the alert count
static std::size_t sendSteady(SpikeServicesDetector &detector, int from, int to, std::size_t perSecond)
{
    std::size_t alerts = 0;

    for (int second = from; second <= to; second++)
        for (std::size_t i = 0; i < perSecond; i++)
            if (detector.addPacket(second, 100, "10.0.0.1", "10.0.0.2", 443))
                alerts++;
    return alerts;
}

// ===== threshold =====

Test(SpikeServicesDetector, no_alert_at_limit)
{
    SpikeServicesDetector detector;

    for (std::size_t i = 0; i < LIMIT; i++)
        cr_assert_not(detector.addPacket(0.0, 100, "10.0.0.1", "10.0.0.2", 443).has_value(),
            "packet %zu must not alert", i + 1);
}

Test(SpikeServicesDetector, alert_above_limit)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT, 1.0);
    std::optional<SpikeAlert> alert = detector.addPacket(2.5, 100, "10.0.0.1", "10.0.0.2", 443);

    cr_assert(alert.has_value(), "the packet over the limit must alert");
    cr_assert_float_eq(alert->timestampSeconds, 2.5, 1e-9);
    cr_assert_float_eq(alert->windowStartSeconds, 1.0, 1e-9);
    cr_assert_eq(alert->sourceIp, "10.0.0.1");
    cr_assert_eq(alert->destinationIp, "10.0.0.2");
    cr_assert_eq(alert->destinationPort, 443);
    cr_assert_eq(alert->packetCount, LIMIT + 1);
    cr_assert_eq(alert->byteCount, (LIMIT + 1) * 100);
}

Test(SpikeServicesDetector, byte_count_sums_every_packet_size)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT, 0.0, 443, "10.0.0.1", "10.0.0.2", 60);
    std::optional<SpikeAlert> alert = send(detector, 1, 0.0, 443, "10.0.0.1", "10.0.0.2", 1500);

    cr_assert(alert.has_value());
    cr_assert_eq(alert->byteCount, LIMIT * 60 + 1500);
}

// ===== packets that are not a service =====

Test(SpikeServicesDetector, ignores_packets_without_service)
{
    SpikeServicesDetector detector;

    for (std::size_t i = 0; i < LIMIT * 2; i++) {
        cr_assert_not(detector.addPacket(0.0, 100, "", "10.0.0.2", 443).has_value());
        cr_assert_not(detector.addPacket(0.0, 100, "10.0.0.1", "", 443).has_value());
        cr_assert_not(detector.addPacket(0.0, 100, "10.0.0.1", "10.0.0.2", 0).has_value());
        cr_assert_not(detector.addPacket(0.0, 100, "", "", 0).has_value());
    }
}

Test(SpikeServicesDetector, ignored_packets_are_not_counted)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT * 2, 0.0, 0);
    cr_assert_not(send(detector, LIMIT, 0.0, 443).has_value(),
        "port 0 packets must not count towards port 443");
}

// ===== one window per service =====

Test(SpikeServicesDetector, services_counted_per_destination_port)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT, 0.0, 53);
    cr_assert_not(send(detector, LIMIT, 0.0, 443).has_value(),
        "port 53 traffic must not count towards port 443");
    std::optional<SpikeAlert> alert = send(detector, 1, 0.0, 443);
    cr_assert(alert.has_value());
    cr_assert_eq(alert->destinationPort, 443);
    cr_assert_eq(alert->packetCount, LIMIT + 1);
}

Test(SpikeServicesDetector, services_counted_per_source_ip)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT, 0.0, 443, "10.0.0.9");
    cr_assert_not(send(detector, LIMIT, 0.0, 443, "10.0.0.1").has_value(),
        "another source must start its own count");
}

Test(SpikeServicesDetector, services_counted_per_destination_ip)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT, 0.0, 443, "10.0.0.1", "10.0.0.3");
    cr_assert_not(send(detector, LIMIT, 0.0, 443, "10.0.0.1", "10.0.0.2").has_value(),
        "another destination must start its own count");
}

Test(SpikeServicesDetector, services_alert_independently)
{
    SpikeServicesDetector detector;

    cr_assert(send(detector, LIMIT + 1, 0.0, 443).has_value());
    cr_assert(send(detector, LIMIT + 1, 1.0, 80).has_value(),
        "an alert on :443 must not silence :80");
}

// ===== sliding window =====

Test(SpikeServicesDetector, old_packets_leave_the_window)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT, 0.0);
    cr_assert_not(send(detector, 1, WINDOW + 0.001).has_value(),
        "packets older than the window must be forgotten");
}

Test(SpikeServicesDetector, packet_exactly_window_old_is_kept)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT, 0.0);
    std::optional<SpikeAlert> alert = send(detector, 1, WINDOW);

    cr_assert(alert.has_value(), "a packet exactly windowSeconds old is still in the window");
    cr_assert_float_eq(alert->windowStartSeconds, 0.0, 1e-9);
}

Test(SpikeServicesDetector, window_start_is_oldest_packet_kept)
{
    SpikeServicesDetector detector;

    send(detector, 100, 0.0);
    send(detector, LIMIT - 100, 5.0);
    std::optional<SpikeAlert> alert = send(detector, 101, 12.0);

    // packets at 0.0 are more than 10s old at 12.0: window = 5.0 -> 12.0
    cr_assert(alert.has_value());
    cr_assert_float_eq(alert->windowStartSeconds, 5.0, 1e-9);
    cr_assert_eq(alert->packetCount, LIMIT + 1);
}

Test(SpikeServicesDetector, byte_count_excludes_evicted_packets)
{
    SpikeServicesDetector detector;

    send(detector, LIMIT, 0.0, 443, "10.0.0.1", "10.0.0.2", 1000);
    std::optional<SpikeAlert> alert = send(detector, LIMIT + 1, 20.0, 443, "10.0.0.1", "10.0.0.2", 10);

    cr_assert(alert.has_value());
    cr_assert_eq(alert->byteCount, (LIMIT + 1) * 10, "evicted 1000-byte packets must not count");
}

// ===== reminders while the spike lasts =====

Test(SpikeServicesDetector, no_repeat_while_spike_lasts)
{
    SpikeServicesDetector detector;

    cr_assert(send(detector, LIMIT + 1, 0.0).has_value());
    for (std::size_t i = 0; i < LIMIT; i++)
        cr_assert_not(send(detector, 1, 1.0).has_value(), "must stay silent after the first alert");
}

Test(SpikeServicesDetector, reminder_after_realert_seconds)
{
    SpikeServicesDetector detector;

    // 100 packets/s: the window always holds ~1000 packets, well over the limit
    cr_assert_eq(sendSteady(detector, 0, static_cast<int>(REALERT) - 1, 100), 1,
        "only the first alert before realertSeconds");
    std::optional<SpikeAlert> reminder = send(detector, 1, REALERT + 5.0);
    cr_assert(reminder.has_value(), "the spike still lasts: reminder expected");
}

Test(SpikeServicesDetector, reminder_timing)
{
    SpikeServicesDetector detector;

    // 100 packets/s from 0s to 29s: first alert on the 501st packet, at 5s
    sendSteady(detector, 0, static_cast<int>(REALERT) - 1, 100);
    cr_assert_not(send(detector, 1, 5.0 + REALERT - 0.001).has_value(), "too early for a reminder");
    cr_assert(send(detector, 1, 5.0 + REALERT).has_value(), "exactly realertSeconds later: reminder");
}

Test(SpikeServicesDetector, steady_flood_alerts_every_realert_seconds)
{
    SpikeServicesDetector detector;

    // 100 packets/s during 95s: alerts at ~5s, ~35s, ~65s, ~95s
    cr_assert_eq(sendSteady(detector, 0, 95, 100), 4);
}

// ===== back to normal =====

Test(SpikeServicesDetector, new_spike_after_calm_alerts_immediately)
{
    SpikeServicesDetector detector;

    cr_assert(send(detector, LIMIT + 1, 0.0).has_value());
    cr_assert_not(send(detector, 1, WINDOW + 1.0).has_value(), "window emptied: back to normal");
    cr_assert(send(detector, LIMIT, WINDOW + 2.0).has_value(),
        "a new spike must alert at once, without waiting realertSeconds");
}

Test(SpikeServicesDetector, spike_continues_if_never_back_under_limit)
{
    SpikeServicesDetector detector;

    // stays over the limit the whole time: every burst is the same spike
    cr_assert(send(detector, LIMIT + 1, 0.0).has_value());
    for (double timestamp : {WINDOW - 1.0, 2 * WINDOW - 2.0})
        for (std::size_t i = 0; i < LIMIT + 1; i++)
            cr_assert_not(send(detector, 1, timestamp).has_value(), "no alert at %.1fs", timestamp);
}
