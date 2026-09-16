/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Ipv4Parser
*/

#include "Ipv4Parser.hpp"
#include "Helper.hpp"

using namespace sniffer;

const char *Ipv4Parser::protocolName(std::uint8_t protocol)
{
    switch (protocol) {
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        default:
            return "Unknown";
    }
}

bool Ipv4Parser::checkSum(const unsigned char *data, std::size_t headerLength) {

    uint32_t checksum = 0;
    uint16_t twoBytes;

    for (std::size_t i = 0; i < headerLength; i += 2) {
        twoBytes = static_cast<uint16_t>(data[i] << 8) + data[i + 1];
        checksum += twoBytes;

        if (checksum > 0xFFFF)
            checksum = (checksum & 0xFFFF) + 1;
    }

    if  (checksum != 0xFFFF)
        return false;

    return true;
}


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

    header.headerLength = headerLength;
    header.typeOfService = data[1];

    if (!Helper::readUint16(data, buffer.size(), 2, header.totalLength))
        return false;

    uint16_t flagsAndOffset;

    if (!Helper::readUint16(data, buffer.size(), 6, flagsAndOffset))
        return false;

    //14 eme bit
    header.DF_flag = (flagsAndOffset & 0x4000) != 0;
    //13 eme bit
    header.MF_flag = (flagsAndOffset & 0x2000) != 0;
    // 0-12 eme bits
    header.fragmentOffset = flagsAndOffset & 0x1FFF;
    header.isFragmented = header.MF_flag || header.fragmentOffset != 0;

    header.ttl = data[8];
    header.protocol = data[9];

    if (!Helper::readUint16(data, buffer.size(), 10, header.headerChecksum))
        return false;

    header.checksumValid = checkSum(data, headerLength);

    if (!Helper::bynaryIPV4ToString(data + 12, header.sourceAddress))
        return false;
    if (!Helper::bynaryIPV4ToString(data + 16, header.destinationAddress))
        return false;

    return true;
}
