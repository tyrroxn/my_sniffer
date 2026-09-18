/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** PacketDisplay
*/

#include "PacketDisplay.hpp"
#include "EthernetParser.hpp"
#include "Ipv4Parser.hpp"
#include "TcpParser.hpp"
#include "Helper.hpp"

#include <cstdio>
#include <ctime>

using namespace sniffer;

std::string PacketDisplay::formatTimestamp(const std::chrono::system_clock::time_point &tp)
{
    using namespace std::chrono;
    char buffer[16];

    std::time_t seconds = system_clock::to_time_t(tp);
    auto milliseconds = duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % 1000;

    std::tm localTime{};
    localtime_r(&seconds, &localTime);

    std::snprintf(buffer, sizeof(buffer), "%02d:%02d:%02d.%03d", localTime.tm_hour, localTime.tm_min,
        localTime.tm_sec, static_cast<int>(milliseconds.count()));

    return std::string(buffer);
}

void PacketDisplay::show(const RawPacket &packet, const EthernetHeader &ethernet, const std::optional<Ipv4Header> &ipv4,
    const std::optional<TcpHeader> &tcp, const std::optional<UdpHeader> &udp)
{
    if (paused)
        return;

    if (mode == Mode::Detailed)
        showDetailed(packet, ethernet, ipv4, tcp, udp);
    else
        showMinimum(packet, ethernet, ipv4, tcp, udp);
    return;
}

void PacketDisplay::showMinimum(const RawPacket &packet, const EthernetHeader &ethernet,
    const std::optional<Ipv4Header> &ipv4, const std::optional<TcpHeader> &tcp,
    const std::optional<UdpHeader> &udp) const
{
    std::cout << formatTimestamp(packet.timestamp) << ":  " << ethernet.sourceMac
        << " -> " << ethernet.destinationMac << "  ";

    if (ipv4) {
        std::cout << ipv4->sourceAddress << " -> " << ipv4->destinationAddress << "  "
            << Ipv4Parser::protocolName(ipv4->protocol);
        if (tcp)
            std::cout << "  " << tcp->sourcePort << " -> " << tcp->destinationPort << "  "
                << TcpParser::flagsLabel(*tcp);
        else if (udp)
            std::cout << "  " << udp->sourcePort << " -> " << udp->destinationPort;
        if (ipv4->isFragmented)
            std::cout << "  [FRAGMENTED]";
    } else
        std::cout << "EtherType 0x" << std::hex << ethernet.etherType << std::dec;
    std::cout << "  " << packet.buffer.size() << "B" << std::endl;
    return;
}

void PacketDisplay::showDetailed(const RawPacket &packet, const EthernetHeader &ethernet,
    const std::optional<Ipv4Header> &ipv4, const std::optional<TcpHeader> &tcp,
    const std::optional<UdpHeader> &udp) const
{
    std::cout << "==== packet (" << packet.buffer.size() << " bytes) at "
        << formatTimestamp(packet.timestamp) << " ====" << std::endl;

    std::cout << "Ethernet " << ethernet.sourceMac << " -> " << ethernet.destinationMac
        << " | EtherType: 0x" << std::hex << ethernet.etherType << std::dec
        << (ethernet.vlanTagged ? " (VLAN tagged)" : "") << std::endl;

    if (ipv4) {
        std::cout << "  IPv4 " << ipv4->sourceAddress << " -> " << ipv4->destinationAddress
            << " | version=" << static_cast<int>(ipv4->version)
            << " ihl=" << static_cast<int>(ipv4->ihl)
            << " tos=" << static_cast<int>(ipv4->typeOfService)
            << " totalLength=" << ipv4->totalLength
            << " ttl=" << static_cast<int>(ipv4->ttl)
            << " protocol=" << Ipv4Parser::protocolName(ipv4->protocol)
            << " (" << static_cast<int>(ipv4->protocol) << ")"
            << " checksum=0x" << std::hex << ipv4->headerChecksum << std::dec
            << " (valid=" << (ipv4->checksumValid ? "true" : "false") << ")"
            << std::endl;
        if (ipv4->isFragmented) {
            std::cout << "  [FRAGMENTED] offset=" << (ipv4->fragmentOffset * 8)
                << " moreFragments=" << (ipv4->MF_flag ? "true" : "false")
                << " dontFragment=" << (ipv4->DF_flag ? "true" : "false")
                << std::endl;
        }
        if (tcp) {
            std::cout << "    TCP " << tcp->sourcePort << " -> " << tcp->destinationPort
                << " " << TcpParser::flagsLabel(*tcp)
                << " seq=" << tcp->sequenceNumber
                << " ack=" << tcp->acknowledgmentNumber
                << " win=" << tcp->windowSize
                << " checksum=0x" << std::hex << tcp->checksum << std::dec
                << std::endl;
            if (!tcp->payload.empty()) {
                std::cout << "    payload (" << tcp->payload.size() << " bytes):\n"
                    << Helper::hexdump(tcp->payload.data(), tcp->payload.size())
                    << std::endl;
            }
        } else if (udp) {
            std::cout << "    UDP " << udp->sourcePort << " -> " << udp->destinationPort
                << " len=" << udp->length
                << " checksum=0x" << std::hex << udp->checksum << std::dec
                << std::endl;
            if (!udp->payload.empty()) {
                std::cout << "    payload (" << udp->payload.size() << " bytes):\n"
                    << Helper::hexdump(udp->payload.data(), udp->payload.size())
                    << std::endl;
            }
        }
    }
    std::cout << std::endl;
    return;
}

void PacketDisplay::displayStats(std::size_t captured, std::size_t filtered, std::size_t errors) const
{
    std::cout << "\nCapture stopped.\n"
        << "  packets captured: " << captured << "\n"
        << "  packets filtered: " << filtered << "\n"
        << "  errors: " << errors << std::endl;
    std::cout.flush();
    return;
}
