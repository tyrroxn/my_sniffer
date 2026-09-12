/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Ipv4Parser
*/

#include "Ipv4Parser.hpp"
#include "Helper.hpp"

using namespace sniffer;



bool Ipv4Parser::parse(const std::vector<std::uint8_t> &buffer, Ipv4Header &header)
{
    if (buffer.size() < IPV4_MIN_HEADER_LEN)
        return false;

    const unsigned char *data = buffer.data();

    header.version = data[0] >> 4;
    header.ihl = data[0] & 0x0F;

  
    std::size_t headerLength = static_cast<std::size_t>(header.ihl) * 4;

    if (header.ihl < IPV4_MIN_IHL || headerLength > buffer.size())
        return false;

    header.typeOfService = data[1];

    if (!Helper::readUint16(data, buffer.size(), 2, header.totalLength))
        return false;

    header.ttl = data[8];
    header.protocol = data[9];

    if (!Helper::readUint16(data, buffer.size(), 10, header.headerChecksum))
        return false;

    if (!Helper::bynaryIPV4ToString(data + 12, header.sourceAddress))
        return false;
    if (!Helper::bynaryIPV4ToString(data + 16, header.destinationAddress))
        return false;

    return true;
}
