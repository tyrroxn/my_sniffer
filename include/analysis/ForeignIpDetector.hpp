/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** ForeignIpDetector
*/

#ifndef FOREIGNIPDETECTOR_HPP_
#define FOREIGNIPDETECTOR_HPP_

#include "analysis/IpWhitelist.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace analyser {

enum class Direction {
    Outgoing, 
    Incoming,
    Transit,
};

enum class Zone {
    Lan,
    Wan,
};

struct ForeignIpAlert {
    double timestampSeconds = 0.0;
    std::string foreignIp;
    Direction direction = Direction::Outgoing;
    Zone zone = Zone::Wan;
    std::string sourceIp;
    std::uint16_t sourcePort = 0;
    std::string destinationIp;
    std::uint16_t destinationPort = 0;
    std::string protocol;
};

struct ForeignIpStats {
    Zone zone = Zone::Wan;
    double firstSeconds = 0.0;
    double lastSeconds = 0.0;
    std::size_t packetsTo = 0;
    std::size_t packetsFrom = 0;
    std::size_t byteCount = 0;
    std::set<std::uint16_t> servicePorts;
};

class ForeignIpDetector {
    public:
       ForeignIpDetector(IpWhitelist whitelist) : whitelist(std::move(whitelist)) {}

        std::vector<ForeignIpAlert> addPacket(double timestampSeconds, std::size_t sizeBytes,
            const std::string &sourceIp, std::uint16_t sourcePort,
            const std::string &destinationIp, std::uint16_t destinationPort,
            const std::string &protocol);

    private:
        IpWhitelist whitelist;
        std::map<std::string, ForeignIpStats> foreignIps;

        bool record(const std::string &ip, double timestampSeconds, std::size_t sizeBytes,
            bool isDestination, std::uint16_t servicePort);
};

}

#endif /* !FOREIGNIPDETECTOR_HPP_ */
