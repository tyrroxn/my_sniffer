/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** PacketFilter
*/

#ifndef PACKETFILTER_HPP_
#define PACKETFILTER_HPP_

#include "Packet.hpp"
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace sniffer {

class PacketFilter {
    public:
        PacketFilter() = default;
        ~PacketFilter() = default;

     
        bool parse(const std::string &expr);
        bool matches(const EthernetHeader &ethernet, const std::optional<Ipv4Header> &ipv4,
            std::size_t packetSize,
            const std::optional<TcpHeader> &tcp = std::nullopt,
            const std::optional<UdpHeader> &udp = std::nullopt) const;

       

    private:
        std::vector<std::string> validProtocols = {"tcp", "udp", "arp", "ipv6", "unknown"};
        std::vector<std::string> validFlags = {"NS", "CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"};
        std::map<std::string, std::vector<std::string>> filters;
        bool matchesPort(const std::string &key, std::uint16_t port) const;
        bool matchesProtocol(const std::string &key, const std::string &value) const;
        bool matchesIpv4Address(const std::string &key, const std::string &address) const;
        bool matchesTcpFlags(const std::vector<std::string> &flags, const TcpHeader &tcp) const;
        bool matchesSize(const std::string &key, std::size_t packetSize, bool isMinimum) const;
        static std::string classifyProtocol(const EthernetHeader &ethernet,
            const std::optional<Ipv4Header> &ipv4);
        void addValues(const std::string &key, const std::vector<std::string> &values);
        bool isKnownKey(const std::string &key) const;
        bool isValidProtocol(const std::string &value) const;
        bool isValidPort(const std::string &value) const;
        bool isValidIpv4Address(const std::string &address) const;
        bool isValidSize(const std::string &value) const;
        bool isValueValidForKey(const std::string &key, const std::string &value) const;
        bool isValidTcpFlag(const std::string &flag) const;
        bool validateValues(const std::string &key, const std::vector<std::string> &values) const;
        std::vector<std::string> splitValues(const std::string &rawValues);
};

}

#endif /* !PACKETFILTER_HPP_ */
