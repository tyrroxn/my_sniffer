/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** BeaconDetector
*/

#include "analysis/BeaconDetector.hpp"
#include <cmath>

namespace analyser {

std::optional<BeaconAlert> BeaconDetector::addPacket(double timestampSeconds, const std::string &sourceIp,
    const std::string &destinationIp, std::uint16_t destinationPort, const std::optional<std::string> &tcpFlags)
{
    if (destinationIp.empty() || destinationPort == 0)
        return std::nullopt;

    if (tcpFlags && tcpFlags->find("SYN") == std::string::npos && tcpFlags->find("PSH") == std::string::npos)
        return std::nullopt;

    Destination destination{destinationIp, destinationPort};
    auto last = lastPacket.find(destination);
    bool newConnection = false;

    if (last == lastPacket.end() || timestampSeconds - last->second >= connectionGapSeconds)
        newConnection = true;
    lastPacket[destination] = timestampSeconds;

    if (!newConnection)
        return std::nullopt;

    std::deque<double> &starts = connectionStarts[destination];
    starts.push_back(timestampSeconds);

    if (starts.size() > minOccurrences)
        starts.pop_front();
    if (starts.size() < minOccurrences || reported.count(destination))
        return std::nullopt;

    std::size_t intervals = starts.size() - 1;
    double intervalSeconds = (starts.back() - starts.front()) / intervals;
    double variance = 0.0;
    double deviationSeconds = 0.0;

    for (std::size_t i = 1; i < starts.size(); i++)
        variance += std::pow(starts[i] - starts[i - 1] - intervalSeconds, 2);
    deviationSeconds = std::sqrt(variance / intervals);

    if (deviationSeconds > maxDeviation * intervalSeconds)
        return std::nullopt;
    reported.insert(destination);

    return BeaconAlert{timestampSeconds, sourceIp, destinationIp, destinationPort, starts.size(),
        intervalSeconds, deviationSeconds};
}


}
