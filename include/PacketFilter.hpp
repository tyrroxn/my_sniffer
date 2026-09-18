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
            const std::optional<TcpHeader> &tcp = std::nullopt,
            const std::optional<UdpHeader> &udp = std::nullopt) const;

       

    private:
        std::map<std::string, std::vector<std::string>> filters;
        bool matchesPort(const std::string &key, std::uint16_t port) const;
        bool matchesProtocol(const std::string &key, const std::string &value) const;
        static std::string classifyProtocol(const EthernetHeader &ethernet,
            const std::optional<Ipv4Header> &ipv4);

        void addValues(const std::string &key, const std::vector<std::string> &values);
};

}

#endif /* !PACKETFILTER_HPP_ */
