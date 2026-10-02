/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** ForeignIpDetector
*/

#include "analysis/ForeignIpDetector.hpp"
#include <algorithm>

namespace analyser {

bool ForeignIpDetector::record(const std::string &ip, double timestampSeconds, std::size_t sizeBytes,
    bool isDestination, std::uint16_t servicePort)
{
    auto [it, isNew] = foreignIps.try_emplace(ip);
    ForeignIpStats &stats = it->second;

    if (isNew) {
        stats.zone = IpWhitelist::isLan(ip) ? Zone::Lan : Zone::Wan;
        stats.firstSeconds = timestampSeconds;
    }
    stats.lastSeconds = timestampSeconds;
    stats.byteCount += sizeBytes;
    if (isDestination)
        stats.packetsTo++;
    else
        stats.packetsFrom++;
    if (servicePort != 0)
        stats.servicePorts.insert(servicePort);
    return isNew;
}

std::vector<ForeignIpAlert> ForeignIpDetector::addPacket(double timestampSeconds, std::size_t sizeBytes,
    const std::string &sourceIp, std::uint16_t sourcePort, const std::string &destinationIp,
    std::uint16_t destinationPort, const std::string &protocol)
{
    std::vector<ForeignIpAlert> alerts;

    if (sourceIp.empty() || destinationIp.empty())
        return alerts;

    bool sourceForeign = !whitelist.contains(sourceIp);
    bool destinationForeign = !whitelist.contains(destinationIp);
    Direction direction = Direction::Transit;

    if (!sourceForeign && !destinationForeign)
        return alerts;
    if (!sourceForeign)
        direction = Direction::Outgoing;
    else if (!destinationForeign)
        direction = Direction::Incoming;
    std::uint16_t servicePort = direction == Direction::Incoming ? sourcePort : destinationPort;

    ForeignIpAlert alert{timestampSeconds, "", direction, Zone::Wan, sourceIp, sourcePort,
        destinationIp, destinationPort, protocol};

    if (sourceForeign && record(sourceIp, timestampSeconds, sizeBytes, false, servicePort)) {
        alert.foreignIp = sourceIp;
        alert.zone = foreignIps.at(sourceIp).zone;
        alerts.push_back(alert);
    }
    if (destinationForeign && record(destinationIp, timestampSeconds, sizeBytes, true, servicePort)) {
        alert.foreignIp = destinationIp;
        alert.zone = foreignIps.at(destinationIp).zone;
        alerts.push_back(alert);
    }
    return alerts;
}

}
