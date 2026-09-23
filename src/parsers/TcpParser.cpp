/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** TcpParser
*/

#include "parsers/TcpParser.hpp"
#include "utils/Helper.hpp"

using namespace sniffer;

std::string TcpParser::flagsLabel(const TcpHeader &header)
{
    std::string label = "[";
    bool first = true;

    const std::pair<bool, const char *> flags[] = {
        {header.SYN_flag, "SYN"}, {header.FIN_flag, "FIN"},
        {header.RST_flag, "RST"}, {header.PSH_flag, "PSH"},
        {header.ACK_flag, "ACK"}, {header.URG_flag, "URG"},
        {header.ECE_flag, "ECE"}, {header.CWR_flag, "CWR"},
        {header.NS_flag, "NS"}
    };

    for (const auto &[set, name] : flags) {
        if (!set)
            continue;
        if (!first)
            label += ", ";
        label += name;
        first = false;
    }

    label += "]";
    return label;
}

bool TcpParser::parse(const std::vector<std::uint8_t> &buffer, TcpHeader &header)
{
    if (buffer.size() < 20)
        return false;

    const unsigned char *data = buffer.data();

    if (Helper::readUint16(data, buffer.size(), 0, header.sourcePort) == false)
        return false;

    if (Helper::readUint16(data, buffer.size(), 2, header.destinationPort) == false)
        return false;

    if (Helper::readUint32(data, buffer.size(), 4, header.sequenceNumber) == false)
        return false;

    if (Helper::readUint32(data, buffer.size(), 8, header.acknowledgmentNumber) == false)
        return false;

    std::uint16_t dataOffsetAndFlags;

    if (Helper::readUint16(data, buffer.size(), 12, dataOffsetAndFlags) == false)
        return false;

    header.dataOffset = (dataOffsetAndFlags >> 12) & 0x0F;
    header.NS_flag  = (dataOffsetAndFlags & 0x100) != 0;
    header.CWR_flag = (dataOffsetAndFlags & 0x80)  != 0;
    header.ECE_flag = (dataOffsetAndFlags & 0x40)  != 0;
    header.URG_flag = (dataOffsetAndFlags & 0x20)  != 0;
    header.ACK_flag = (dataOffsetAndFlags & 0x10)  != 0;
    header.PSH_flag = (dataOffsetAndFlags & 0x08)  != 0;
    header.RST_flag = (dataOffsetAndFlags & 0x04)  != 0;
    header.SYN_flag = (dataOffsetAndFlags & 0x02)  != 0;
    header.FIN_flag = (dataOffsetAndFlags & 0x01)  != 0;

    std::size_t headerLength = static_cast<std::size_t>(header.dataOffset) * 4;

    if (headerLength < 20 || headerLength > buffer.size())
        return false;

    header.headerLength = headerLength;

    if (Helper::readUint16(data, buffer.size(), 14, header.windowSize) == false)
        return false;

    if (Helper::readUint16(data, buffer.size(), 16, header.checksum) == false)
        return false;

    if (Helper::readUint16(data, buffer.size(), 18, header.urgentPointer) == false)
        return false;

    header.payload.assign(buffer.begin() + static_cast<std::ptrdiff_t>(headerLength), buffer.end());

    return true;
}