/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** UdpParser
*/

#ifndef UDPPARSER_HPP_
#define UDPPARSER_HPP_
#include "utils/Packet.hpp"

namespace sniffer {
class UdpParser {
    public:
        UdpParser() = default;
        ~UdpParser() = default;
        static bool parse(const std::vector<std::uint8_t> &buffer, UdpHeader &header);

    protected:
    private:
};
}

#endif /* !UDPPARSER_HPP_ */
