/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** EthernetParser
*/

#include "EthernetParser.hpp"
#include "Helper.hpp"

using namespace sniffer;

char const *EthernetParser::protocolName(std::uint16_t etherType)
{
    switch (etherType) {
        case static_cast<std::uint16_t>(EthernetType::IPv4):
            return "IPv4";
        case static_cast<std::uint16_t>(EthernetType::ARP):
            return "ARP";
        case static_cast<std::uint16_t>(EthernetType::IPv6):
            return "IPv6";
        default:
            return "Unknown";
    }
}


bool EthernetParser::parse(const std::vector<std::uint8_t> &buffer, EthernetHeader &header)
{
    std::uint16_t tagOrEtherType = 0;

    // 2 adresses mac de 6 bytes + 2 bytes pour EtherType + 4 bytes si tag VLAN
    if (buffer.size() < 14 + VLAN_TAG_LEN)
        return false;

    const unsigned char *data = buffer.data();

    if (!Helper::bynaryMACToString(data, header.destinationMac))
        return false;
    if (!Helper::bynaryMACToString(data + 6, header.sourceMac))
        return false;

    if (!Helper::readUint16(data, buffer.size(), 12, tagOrEtherType))
        return false;

    if (tagOrEtherType == VLAN_TAG)
        header.vlanTagged = true;
    else
        header.vlanTagged = false;

    if (!header.vlanTagged) {
        header.etherType = tagOrEtherType;
        return true;
    }

    return Helper::readUint16(data, buffer.size(), 12 + VLAN_TAG_LEN, header.etherType);
}
