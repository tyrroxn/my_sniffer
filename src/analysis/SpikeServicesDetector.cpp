/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** SpikeServicesDetector
*/

#include "analysis/SpikeServicesDetector.hpp"

namespace analyser {

std::optional<SpikeAlert> SpikeServicesDetector::addPacket(double timestampSeconds, std::size_t sizeBytes,
    const std::string &sourceIp, const std::string &destinationIp, std::uint16_t destinationPort)
{

    if (sourceIp.empty() || destinationIp.empty() || destinationPort == 0)
        return std::nullopt;

    Service service{sourceIp, destinationIp, destinationPort};

    // Récupère la liste des paquets récents associés à ce service.
    std::deque<std::pair<double, std::size_t>> &recentPackets = recentPacketsByService[service];

    while (!recentPackets.empty() && timestampSeconds - recentPackets.front().first > windowSeconds)
        recentPackets.pop_front();
    recentPackets.emplace_back(timestampSeconds, sizeBytes);

    if (recentPackets.size() <= limit) {
        lastAlerts.erase(service);
        return std::nullopt;
    }

    auto lastAlert = lastAlerts.find(service);
    if (lastAlert != lastAlerts.end() && timestampSeconds - lastAlert->second < realertSeconds)
        return std::nullopt;
    lastAlerts[service] = timestampSeconds;

    std::size_t byteCount = 0;
    for (const auto &[timestamp, bytes] : recentPackets)
        byteCount += bytes;
    return SpikeAlert{timestampSeconds, recentPackets.front().first, sourceIp, destinationIp,
        destinationPort, recentPackets.size(), byteCount};
}

}
