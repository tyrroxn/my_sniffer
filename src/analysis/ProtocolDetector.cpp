/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** ProtocolDetector
*/

#include "analysis/ProtocolDetector.hpp"
#include <algorithm>

namespace analyser {

bool startsWith(const std::vector<std::uint8_t> &payload, const std::string &prefix)
{
    if (payload.size() < prefix.size())
        return false;
    return std::equal(prefix.begin(), prefix.end(), payload.begin());
}

static bool isHttp(const std::vector<std::uint8_t> &payload)
{
    for (const std::string &start : HTTP_STARTS)
        if (startsWith(payload, start))
            return true;
    return false;
}


static bool isTls(const std::vector<std::uint8_t> &payload)
{
    return payload.size() >= 3 && payload[0] >= 0x14 && payload[0] <= 0x17
        && payload[1] == 0x03 && payload[2] <= 0x04 && payload[2] >= 0x00;
}

static bool isSsh(const std::vector<std::uint8_t> &payload)
{
    return startsWith(payload, "SSH-");
}

std::optional<Protocol> ProtocolDetector::expectedProtocol(const std::string &transport, std::uint16_t port)
{
    for (const ServiceEntry &service : SERVICES)
        if (service.transport == transport && service.port == port)
            return service.protocol;
    return std::nullopt;
}

bool ProtocolDetector::matches(Protocol protocol, const std::string &transport,
    const std::vector<std::uint8_t> &payload)
{
    switch (protocol) {
        case Protocol::Http:
            return isHttp(payload);
        case Protocol::Tls:
            return isTls(payload);
        case Protocol::Ssh:
            return isSsh(payload);
        default:
            return false;
    }
}

Protocol ProtocolDetector::detect(const std::vector<std::uint8_t> &payload)
{
    if (isTls(payload))
        return Protocol::Tls;
    if (isSsh(payload))
        return Protocol::Ssh;
    if (isHttp(payload))
        return Protocol::Http;
    return Protocol::Unknown;
}

std::string ProtocolDetector::name(Protocol protocol)
{
    switch (protocol) {
        case Protocol::Http:
            return "HTTP";
        case Protocol::Tls:
            return "TLS";
        case Protocol::Ssh:
            return "SSH";
        default:
            return "unknown";
    }
}

bool ProtocolDetector::isFirstTcpData(const LogEntry &entry)
{
    Flow forward{entry.sourceIp, entry.sourcePort, entry.destinationIp, entry.destinationPort};
    Flow backward{entry.destinationIp, entry.destinationPort, entry.sourceIp, entry.sourcePort};
    const std::string flags = entry.tcpFlags.value_or("");

    if (flags.find("SYN") != std::string::npos) {
        awaitingData.insert(forward);
        awaitingData.insert(backward);
    }

    bool firstData = entry.payloadSize > 0 && awaitingData.erase(forward) > 0;

    if (flags.find("FIN") != std::string::npos || flags.find("RST") != std::string::npos) {
        awaitingData.erase(forward);
        awaitingData.erase(backward);
    }
    return firstData;
}

std::optional<ProtocolMismatchAlert> ProtocolDetector::addPacket(const LogEntry &entry)
{
    if (entry.sourceIp.empty() || entry.destinationIp.empty())
        return std::nullopt;
    if (entry.protocol == "TCP") {
        if (!isFirstTcpData(entry))
            return std::nullopt;
    } else if (entry.protocol != "UDP" || entry.payloadSize == 0)
        return std::nullopt;

    std::optional<Protocol> expectedProtocols = expectedProtocol(entry.protocol, entry.destinationPort);
    bool serverIsDestination = expectedProtocols.has_value();

    if (!expectedProtocols)
        expectedProtocols = expectedProtocol(entry.protocol, entry.sourcePort);
    if (!expectedProtocols || matches(*expectedProtocols, entry.protocol, entry.payload))
        return std::nullopt;

    const std::string &serverIp = serverIsDestination ? entry.destinationIp : entry.sourceIp;
    const std::string &clientIp = serverIsDestination ? entry.sourceIp : entry.destinationIp;
    std::uint16_t servicePort = serverIsDestination ? entry.destinationPort : entry.sourcePort;

    if (!reported.insert(Service{serverIp, servicePort, clientIp}).second)
        return std::nullopt;

    std::size_t previewSize = std::min(previewBytes, entry.payload.size());

    return ProtocolMismatchAlert{entry.timestampSeconds, entry.sourceIp, entry.sourcePort,
        entry.destinationIp, entry.destinationPort, entry.protocol, servicePort, *expectedProtocols,
        detect(entry.payload), entry.payloadSize,
        std::vector<std::uint8_t>(entry.payload.begin(), entry.payload.begin() + previewSize)};
}

}
