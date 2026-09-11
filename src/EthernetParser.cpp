/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** EthernetParser
*/

#include "EthernetParser.hpp"
#include "Helper.hpp"

using namespace sniffer;



bool EthernetParser::parse(const std::vector<std::uint8_t> &buffer, EthernetHeader &header)
{
    // 2 adresses mac de 6 bytes + 2 bytes pour EtherType
    if (buffer.size() < 14)
        return false;

    const unsigned char *data = buffer.data();

    if (!Helper::bynaryMACToString(data, header.destinationMac))
        return false;
    if (!Helper::bynaryMACToString(data + 6, header.sourceMac))
        return false;
    if (!Helper::readUint16(data, buffer.size(), 12, header.etherType))
        return false;

    return true;
}
