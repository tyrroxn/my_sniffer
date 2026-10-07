/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** ProtocolDetector
*/

#ifndef PROTOCOLDETECTOR_HPP_
#define PROTOCOLDETECTOR_HPP_

#include "analysis/LogParser.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace analyser {

enum class Protocol {
    Http,
    Tls,
    Ssh,
    Unknown,
};

struct ServiceEntry {
    std::string transport;
    std::uint16_t port;
    Protocol protocol;
};

inline const std::array<ServiceEntry, 10> SERVICES = {{
    {"TCP", 80, Protocol::Http},
    {"TCP", 8080, Protocol::Http},
    {"TCP", 443, Protocol::Tls},
    {"TCP", 8443, Protocol::Tls},
    {"TCP", 465, Protocol::Tls},     // SMTPS
    {"TCP", 993, Protocol::Tls},     // IMAPS
    {"TCP", 995, Protocol::Tls},     // POP3S
    {"TCP", 22, Protocol::Ssh},
}};

inline const std::array<std::string, 11> HTTP_STARTS = {
    "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    "PRI * HTTP/2", "HTTP/1.",
};

struct ProtocolMismatchAlert {
    double timestampSeconds = 0.0;
    std::string sourceIp;
    std::uint16_t sourcePort = 0;
    std::string destinationIp;
    std::uint16_t destinationPort = 0;
    std::string transport;
    std::uint16_t servicePort = 0;
    Protocol expected = Protocol::Unknown;
    Protocol detected = Protocol::Unknown;
    std::size_t payloadSize = 0;
    std::vector<std::uint8_t> preview;
};

class ProtocolDetector {
    public:
        static constexpr std::size_t previewBytes = 8;

        std::optional<ProtocolMismatchAlert> addPacket(const LogEntry &entry);

        static std::optional<Protocol> expectedProtocol(const std::string &transport, std::uint16_t port);
        static bool matches(Protocol protocol, const std::string &transport,
            const std::vector<std::uint8_t> &payload);
        static Protocol detect(const std::vector<std::uint8_t> &payload);
        static std::string name(Protocol protocol);

    private:
        using Flow = std::tuple<std::string, std::uint16_t, std::string, std::uint16_t>;
        using Service = std::tuple<std::string, std::uint16_t, std::string>;

        std::set<Flow> awaitingData;
        std::set<Service> reported;

        bool isFirstTcpData(const LogEntry &entry);
};

}

#endif /* !PROTOCOLDETECTOR_HPP_ */
