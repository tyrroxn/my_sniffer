/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** BeaconDetector
*/

#ifndef BEACONDETECTOR_HPP_
#define BEACONDETECTOR_HPP_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

namespace analyser {

struct BeaconAlert {
    double timestampSeconds = 0.0;
    std::string sourceIp;
    std::string destinationIp;
    std::uint16_t destinationPort = 0;
    std::size_t occurrences = 0;
    double intervalSeconds = 0.0;
    double deviationSeconds = 0.0; 
};

struct Destination {
    std::string ip;
    std::uint16_t port;

    bool operator<(const Destination &other) const
    {
        if (ip != other.ip)
            return ip < other.ip;
        return port < other.port;
    }
};

class BeaconDetector {
    public:
        static constexpr double connectionGapSeconds = 1.0;
        static constexpr std::size_t minOccurrences = 5;
        static constexpr double maxDeviation = 0.1;

        std::optional<BeaconAlert> addPacket(double timestampSeconds, const std::string &sourceIp,
            const std::string &destinationIp, std::uint16_t destinationPort,
            const std::optional<std::string> &tcpFlags = std::nullopt);

    private:
        std::map<Destination, std::deque<double>> connectionStarts;
        std::map<Destination, double> lastPacket;
        std::set<Destination> reported;

};
}
#endif /* !BEACONDETECTOR_HPP_ */
