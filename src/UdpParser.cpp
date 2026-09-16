/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** UdpParser
*/

#include "UdpParser.hpp"
#include "Helper.hpp"

using namespace sniffer;

bool UdpParser::parse(const std::vector<std::uint8_t> &buffer, UdpHeader &header)
{
    if (buffer.size() < 8)
        return false;

    const unsigned char *data = buffer.data();

    if (!Helper::readUint16(data, buffer.size(), 0, header.sourcePort))
        return false;

    if (!Helper::readUint16(data, buffer.size(), 2, header.destinationPort))
        return false;

    if (!Helper::readUint16(data, buffer.size(), 4, header.length))
        return false;

    if (!Helper::readUint16(data, buffer.size(), 6, header.checksum))
        return false;

    header.payload.assign(buffer.begin() + 8, buffer.end());

    return true;
}

