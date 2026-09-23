/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Logger
*/

#include "log/Logger.hpp"


using namespace sniffer;

void Logger::init(bool active, const std::string &logFilePath)
{
    if (!active) {
        logger = nullptr;
        return;
    }

    try {
        auto sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            logFilePath, MAX_LOG_FILE_SIZE, MAX_LOG_FILES);
        logger = std::make_shared<spdlog::logger>("my_sniffer", sink);
    } catch (const spdlog::spdlog_ex &e) {
        std::fprintf(stderr, "Logger: failed to open log file '%s': %s\n",
            logFilePath.c_str(), e.what());
        logger = nullptr;
        return;
    }

    logger->set_level(spdlog::level::debug);
    logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    logger->flush_on(spdlog::level::warn);
    return;
}

void Logger::debug(const std::string &message)
{
    if (logger)
        logger->debug(message);
    return;
}

void Logger::info(const std::string &message)
{
    if (logger)
        logger->info(message);
    return;
}

void Logger::warn(const std::string &message)
{
    if (logger)
        logger->warn(message);
    return;
}

void Logger::error(const std::string &message)
{
    if (logger)
        logger->error(message);
    return;
}

std::string Logger::writeLog(const RawPacket &packet, const EthernetHeader &ethernet,
    const std::optional<Ipv4Header> &ipv4, const std::optional<TcpHeader> &tcp,
    const std::optional<UdpHeader> &udp, bool verbose)
{
    std::ostringstream oss;

    if (verbose) 
        Logger::writeLogDetailed(oss, packet, ethernet, ipv4, tcp, udp);
    else
        Logger::writeLogMinimum(oss, packet, ethernet, ipv4, tcp, udp);

    return oss.str();
}



void Logger::writeLogMinimum(std::ostream &os, const RawPacket &packet, const EthernetHeader &ethernet,
    const std::optional<Ipv4Header> &ipv4, const std::optional<TcpHeader> &tcp,
    const std::optional<UdpHeader> &udp)
{
    os << ethernet.sourceMac
        << " -> " << ethernet.destinationMac << "  ";

    if (ipv4) {
        os << ipv4->sourceAddress << " -> " << ipv4->destinationAddress << "  "
            << Ipv4Parser::protocolName(ipv4->protocol);
        if (tcp)
            os << "  " << tcp->sourcePort << " -> " << tcp->destinationPort << "  "
                << TcpParser::flagsLabel(*tcp);
        else if (udp)
            os << "  " << udp->sourcePort << " -> " << udp->destinationPort;
        if (ipv4->isFragmented)
            os << "  [FRAGMENTED]";
    } else
        os << "EtherType 0x" << std::hex << ethernet.etherType << std::dec;
    os << "  " << packet.buffer.size() << "B";
    return;
}



void Logger::writeLogDetailed(std::ostream &os, const RawPacket &packet, const EthernetHeader &ethernet,
    const std::optional<Ipv4Header> &ipv4, const std::optional<TcpHeader> &tcp,
    const std::optional<UdpHeader> &udp)
{
    os << "==== packet (" << packet.buffer.size() << " bytes) ====" << "\n";
    os << "Ethernet " << ethernet.sourceMac << " -> " << ethernet.destinationMac
        << " | EtherType: 0x" << std::hex << ethernet.etherType << std::dec
        << (ethernet.vlanTagged ? " (VLAN tagged)" : "") << "\n";

    if (ipv4) {
        os << "  IPv4 " << ipv4->sourceAddress << " -> " << ipv4->destinationAddress
            << " | version=" << static_cast<int>(ipv4->version)
            << " ihl=" << static_cast<int>(ipv4->ihl)
            << " tos=" << static_cast<int>(ipv4->typeOfService)
            << " totalLength=" << ipv4->totalLength
            << " ttl=" << static_cast<int>(ipv4->ttl)
            << " protocol=" << Ipv4Parser::protocolName(ipv4->protocol)
            << " (" << static_cast<int>(ipv4->protocol) << ")"
            << " checksum=0x" << std::hex << ipv4->headerChecksum << std::dec
            << " (valid=" << (ipv4->checksumValid ? "true" : "false") << ")"
            << "\n";
        if (ipv4->isFragmented) {
            os << "  [FRAGMENTED] offset=" << (ipv4->fragmentOffset * 8)
                << " moreFragments=" << (ipv4->MF_flag ? "true" : "false")
                << " dontFragment=" << (ipv4->DF_flag ? "true" : "false")
                << "\n";
        }
        if (tcp) {
            os << "    TCP " << tcp->sourcePort << " -> " << tcp->destinationPort
                << " " << TcpParser::flagsLabel(*tcp)
                << " seq=" << tcp->sequenceNumber
                << " ack=" << tcp->acknowledgmentNumber
                << " win=" << tcp->windowSize
                << " checksum=0x" << std::hex << tcp->checksum << std::dec
                << "\n";
            if (!tcp->payload.empty()) {
                os << "    payload (" << tcp->payload.size() << " bytes):\n"
                    << Helper::hexdump(tcp->payload.data(), tcp->payload.size())
                    << "\n";
            }
        } else if (udp) {
            os << "    UDP " << udp->sourcePort << " -> " << udp->destinationPort
                << " len=" << udp->length
                << " checksum=0x" << std::hex << udp->checksum << std::dec
                << "\n";
            if (!udp->payload.empty()) {
                os << "    payload (" << udp->payload.size() << " bytes):\n"
                    << Helper::hexdump(udp->payload.data(), udp->payload.size())
                    << "\n";
            }
        }
    }
    return;
}