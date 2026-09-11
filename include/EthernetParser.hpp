/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** EthernetParser
*/

#ifndef ETHERNETPARSER_HPP_
#define ETHERNETPARSER_HPP_

#include "Packet.hpp"
static constexpr std::uint16_t VLAN_TAG = 0x8100;
static constexpr std::size_t VLAN_TAG_LEN = 4;

namespace sniffer {

class EthernetParser {
    public:
        EthernetParser() = default;
        ~EthernetParser() = default;

        static bool parse(const std::vector<std::uint8_t> &buffer,
            EthernetHeader &header);
        static const char *protocolName(std::uint16_t etherType);

    protected:
    private:
};

}

#endif /* !ETHERNETPARSER_HPP_ */
