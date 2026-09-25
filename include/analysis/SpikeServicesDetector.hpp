/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** SpikeServicesDetector
*/

#ifndef SPIKESERVICESDETECTOR_HPP_
#define SPIKESERVICESDETECTOR_HPP_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

namespace analyser {

struct SpikeAlert {
    double timestampSeconds = 0.0;   
    double windowStartSeconds = 0.0;
    std::string sourceIp;
    std::string destinationIp;
    std::uint16_t destinationPort = 0;
    std::size_t packetCount = 0;
    std::size_t byteCount = 0;
};

class SpikeServicesDetector {
    public:
        static constexpr double windowSeconds = 10.0;
        static constexpr std::size_t limit = 500;
        static constexpr double realertSeconds = 30.0;

        std::optional<SpikeAlert> addPacket(double timestampSeconds, std::size_t sizeBytes,
            const std::string &sourceIp, const std::string &destinationIp,
            std::uint16_t destinationPort);

    private:
        using Service = std::tuple<std::string, std::string, std::uint16_t>;

        std::map<Service, std::deque<std::pair<double, std::size_t>>> recentPacketsByService; 
        std::map<Service, double> lastAlerts;
};

}

#endif /* !SPIKESERVICESDETECTOR_HPP_ */
