/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** test_SpikeNetworkDetector
*/

#include <criterion/criterion.h>
#include "analysis/SpikeNetworkDetector.hpp"

using namespace analyser;

static constexpr double WINDOW = SpikeNetworkDetector::windowSeconds;
static constexpr double FACTOR = SpikeNetworkDetector::spikeFactor;
static constexpr std::size_t MINIMUM = SpikeNetworkDetector::minimumPackets;
static constexpr double REALERT = SpikeNetworkDetector::realertSeconds;

// first second where alerts are possible: averagedPeriods calm periods are known
static constexpr int WARMED_UP = static_cast<int>(WINDOW * SpikeNetworkDetector::averagedPeriods);

// Sends `count` packets at `timestamp`, returns the alert count and keeps the last alert
static std::size_t send(SpikeNetworkDetector &detector, std::size_t count, double timestamp,
    std::optional<NetworkSpikeAlert> *last = nullptr, std::size_t bytes = 100)
{
    std::size_t alerts = 0;

    for (std::size_t i = 0; i < count; i++) {
        std::optional<NetworkSpikeAlert> alert = detector.addPacket(timestamp, bytes);
        if (alert) {
            alerts++;
            if (last)
                *last = alert;
        }
    }
    return alerts;
}

// Sends `perSecond` packets every second from `from` to `to` (included), returns the alert count
static std::size_t sendSteady(SpikeNetworkDetector &detector, int from, int to, std::size_t perSecond,
    std::optional<NetworkSpikeAlert> *last = nullptr)
{
    std::size_t alerts = 0;

    for (int second = from; second <= to; second++)
        alerts += send(detector, perSecond, second, last);
    return alerts;
}

// ===== warm-up =====

Test(SpikeNetworkDetector, no_alert_before_history_is_full)
{
    SpikeNetworkDetector detector;

    // huge traffic from the start: nothing to compare to yet
    cr_assert_eq(sendSteady(detector, 0, WARMED_UP - 1, MINIMUM * 10), 0);
}

Test(SpikeNetworkDetector, alert_possible_once_warmed_up)
{
    SpikeNetworkDetector detector;

    sendSteady(detector, 0, WARMED_UP - 1, 10);
    cr_assert_eq(send(detector, MINIMUM * 10, WARMED_UP), 1);
}

// ===== threshold: spikeFactor x the average =====

Test(SpikeNetworkDetector, steady_traffic_never_alerts)
{
    SpikeNetworkDetector detector;

    cr_assert_eq(sendSteady(detector, 0, 300, 100), 0, "constant traffic is the usual traffic");
}

Test(SpikeNetworkDetector, alert_at_factor_times_average)
{
    SpikeNetworkDetector detector;
    std::optional<NetworkSpikeAlert> alert;

    // 50 packets/s -> usual 500 packets per window, threshold 1500
    sendSteady(detector, 0, WARMED_UP - 1, 50);
    // window at WARMED_UP still holds 10 seconds (500) of the old rate: 1000 more reach 1500
    cr_assert_eq(send(detector, 999, WARMED_UP), 0, "1499 packets: under 3x the average");
    cr_assert_eq(send(detector, 1, WARMED_UP, &alert), 1, "1500 packets: exactly 3x the average");
    cr_assert(alert.has_value());
    cr_assert_eq(alert->packetCount, 1500);
    cr_assert_float_eq(alert->averagePackets, 500.0, 1e-6);
    cr_assert_float_eq(alert->packetCount / alert->averagePackets, FACTOR, 1e-6);
}

Test(SpikeNetworkDetector, alert_fields)
{
    SpikeNetworkDetector detector;
    std::optional<NetworkSpikeAlert> alert;

    sendSteady(detector, 0, WARMED_UP - 1, 10);
    send(detector, MINIMUM * 10, WARMED_UP + 0.5, &alert, 60);

    cr_assert(alert.has_value());
    cr_assert_float_eq(alert->timestampSeconds, WARMED_UP + 0.5, 1e-9);
    cr_assert_float_eq(alert->windowStartSeconds, WARMED_UP - WINDOW + 1, 1e-9,
        "oldest packet still in the window");
    cr_assert_float_eq(alert->averagePackets, 100.0, 1e-6);
    cr_assert_eq(alert->byteCount, (alert->packetCount - 90) * 60 + 90 * 100,
        "90 old packets of 100 bytes + the new ones of 60 bytes");
}

Test(SpikeNetworkDetector, minimum_packets_on_quiet_network)
{
    SpikeNetworkDetector detector;

    // 1 packet/s: 3x the average is 30, but under minimumPackets it is still normal
    // (the window already holds 10 packets)
    sendSteady(detector, 0, WARMED_UP - 1, 1);
    cr_assert_eq(send(detector, MINIMUM - 11, WARMED_UP), 0);
    cr_assert_eq(send(detector, 1, WARMED_UP), 1, "minimumPackets reached");
}

Test(SpikeNetworkDetector, silent_network_then_burst)
{
    SpikeNetworkDetector detector;

    // one packet at 0s, then nothing: average 0, only minimumPackets applies
    send(detector, 1, 0.0);
    cr_assert_eq(send(detector, MINIMUM - 1, WARMED_UP + 100), 0);
    cr_assert_eq(send(detector, 1, WARMED_UP + 100), 1);
}

// ===== reminders while the spike lasts =====

Test(SpikeNetworkDetector, no_repeat_while_spike_lasts)
{
    SpikeNetworkDetector detector;

    sendSteady(detector, 0, WARMED_UP - 1, 10);
    cr_assert_eq(send(detector, MINIMUM * 10, WARMED_UP), 1);
    cr_assert_eq(send(detector, MINIMUM * 10, WARMED_UP + 1), 0);
}

Test(SpikeNetworkDetector, reminder_every_realert_seconds)
{
    SpikeNetworkDetector detector;

    // usual 10 packets/s, then a 1000 packets/s flood during 65s: alerts at 0s, 30s, 60s
    sendSteady(detector, 0, WARMED_UP - 1, 10);
    cr_assert_eq(sendSteady(detector, WARMED_UP, WARMED_UP + 65, 1000), 3);
}

Test(SpikeNetworkDetector, reminder_timing)
{
    SpikeNetworkDetector detector;

    sendSteady(detector, 0, WARMED_UP - 1, 10);
    sendSteady(detector, WARMED_UP, WARMED_UP + static_cast<int>(REALERT) - 1, 1000);
    cr_assert_eq(send(detector, 1, WARMED_UP + REALERT - 0.001), 0, "too early for a reminder");
    cr_assert_eq(send(detector, 1, WARMED_UP + REALERT), 1, "exactly realertSeconds later");
}

// ===== the average =====

Test(SpikeNetworkDetector, flood_does_not_raise_the_average)
{
    SpikeNetworkDetector detector;
    std::optional<NetworkSpikeAlert> alert;

    // long flood: if its packets entered the history, the average would reach the flood
    // rate and the reminders would stop
    sendSteady(detector, 0, WARMED_UP - 1, 10);
    cr_assert_eq(sendSteady(detector, WARMED_UP, WARMED_UP + 125, 1000, &alert), 5);
    cr_assert(alert.has_value());
    cr_assert_lt(alert->averagePackets, 100.0 + 1e-6, "average must stay the usual traffic");
}

Test(SpikeNetworkDetector, average_follows_slow_change)
{
    SpikeNetworkDetector detector;

    // traffic doubles slowly (x2 is under x3): no alert, the average adapts
    sendSteady(detector, 0, WARMED_UP - 1, 50);
    cr_assert_eq(sendSteady(detector, WARMED_UP, WARMED_UP + 100, 100), 0);
    // now usual = 1000 per window: 2000 is not a spike, 3000 is
    cr_assert_eq(sendSteady(detector, WARMED_UP + 101, WARMED_UP + 105, 150), 0);
}

Test(SpikeNetworkDetector, average_uses_only_baseline_history)
{
    SpikeNetworkDetector detector;
    std::optional<NetworkSpikeAlert> alert;

    // old busy traffic, then a long calm period: only the last calm periods count
    sendSteady(detector, 0, 50, 100);
    sendSteady(detector, 51, 200, 20);
    send(detector, 1000, 201, &alert);

    cr_assert(alert.has_value());
    cr_assert_float_eq(alert->averagePackets, 200.0, 1e-6);
}

// ===== back to normal =====

Test(SpikeNetworkDetector, new_spike_after_calm_alerts_immediately)
{
    SpikeNetworkDetector detector;

    sendSteady(detector, 0, WARMED_UP - 1, 10);
    cr_assert_eq(send(detector, MINIMUM * 10, WARMED_UP), 1);
    // back to usual traffic: the flood leaves the window
    sendSteady(detector, WARMED_UP + 1, WARMED_UP + 15, 10);
    cr_assert_eq(send(detector, MINIMUM * 10, WARMED_UP + 16), 1,
        "a new spike must alert at once, without waiting realertSeconds");
}

Test(SpikeNetworkDetector, no_false_alert_after_long_spike)
{
    SpikeNetworkDetector detector;

    // usual 10 packets/s, a 2 minutes flood, then usual traffic again:
    // the usual traffic must still be known as 100 packets per window
    sendSteady(detector, 0, WARMED_UP - 1, 10);
    cr_assert_eq(sendSteady(detector, WARMED_UP, WARMED_UP + 120, 1000), 5);
    cr_assert_eq(sendSteady(detector, WARMED_UP + 121, WARMED_UP + 300, 10), 0,
        "usual traffic after the flood is not a spike");
}
