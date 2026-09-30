/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** SpikeNetworkDetector
*/

#include "analysis/SpikeNetworkDetector.hpp"
#include <algorithm>
#include <numeric>

namespace analyser {

std::optional<NetworkSpikeAlert> SpikeNetworkDetector::addPacket(double timestampSeconds, std::size_t sizeBytes)
{
    if (!periodStart)
        periodStart = timestampSeconds;

    while (timestampSeconds >= *periodStart + windowSeconds) {
        if (!periodHadSpike) {
            calmPeriods.push_back(periodPackets);
            if (calmPeriods.size() > averagedPeriods)
                calmPeriods.pop_front();
        }
        *periodStart += windowSeconds;
        periodPackets = 0;
        periodHadSpike = false;
    }
    periodPackets++;

    while (!recentPackets.empty() && timestampSeconds - recentPackets.front().first > windowSeconds)
        recentPackets.pop_front();
    recentPackets.emplace_back(timestampSeconds, sizeBytes);

    if (calmPeriods.size() < averagedPeriods)
        return std::nullopt;

    double averagePackets = std::accumulate(calmPeriods.begin(), calmPeriods.end(), 0.0) / calmPeriods.size();
    double maxPackets = std::max(spikeFactor * averagePackets, static_cast<double>(minimumPackets));

    if (recentPackets.size() < maxPackets) {
        lastAlert.reset();
        return std::nullopt;
    }
    periodHadSpike = true;
    if (lastAlert && timestampSeconds - *lastAlert < realertSeconds)
        return std::nullopt;
    lastAlert = timestampSeconds;

    std::size_t byteCount = 0;
    for (const auto &[timestamp, bytes] : recentPackets)
        byteCount += bytes;
    return NetworkSpikeAlert{timestampSeconds, recentPackets.front().first, recentPackets.size(),
        byteCount, averagePackets};
}

}
