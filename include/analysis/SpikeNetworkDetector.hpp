/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** SpikeNetworkDetector
*/

#ifndef SPIKENETWORKDETECTOR_HPP_
#define SPIKENETWORKDETECTOR_HPP_

#include <cstddef>
#include <deque>
#include <optional>
#include <utility>

namespace analyser {

struct NetworkSpikeAlert {
    double timestampSeconds = 0.0;
    double windowStartSeconds = 0.0;
    std::size_t packetCount = 0;
    std::size_t byteCount = 0;
    double averagePackets = 0.0;
};

class SpikeNetworkDetector {
    public:
        static constexpr double windowSeconds = 10.0;
        static constexpr std::size_t averagedPeriods = 3;
        static constexpr double spikeFactor = 3.0;
        static constexpr std::size_t minimumPackets = 100;
        static constexpr double realertSeconds = 30.0;

        std::optional<NetworkSpikeAlert> addPacket(double timestampSeconds, std::size_t sizeBytes);

    private:
        std::deque<std::pair<double, std::size_t>> recentPackets;
        std::deque<std::size_t> calmPeriods;
        std::optional<double> periodStart;
        std::size_t periodPackets = 0;
        bool periodHadSpike = false;
        std::optional<double> lastAlert;
};

}

#endif /* !SPIKENETWORKDETECTOR_HPP_ */
