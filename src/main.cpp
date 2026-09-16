/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** main
*/
#include "CaptureNetwork.hpp"
#include "SignalHandler.hpp"
#include "EthernetParser.hpp"
#include "Ipv4Parser.hpp"
#include "TcpParser.hpp"
#include "UdpParser.hpp"
#include "PacketDisplay.hpp"
#include "TerminalInput.hpp"
#include <memory>
#include <optional>

#if defined(__APPLE__)
    #include "MacCapture.hpp"
#elif defined(__linux__)
    #include "LinuxCapture.hpp"
#else
    #error "No capture backend implemented for this platform"
#endif

using namespace sniffer;

static void handleKey(int key, PacketDisplay &display)
{
    if (key == 'p')
        display.togglePause();
    else if (key == 'd')
        display.toggleMode();
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    SignalHandler::install();
    PacketDisplay display;
    TerminalInput input;
    std::size_t packetCount = 0;
    std::size_t errorCount = 0;
    std::optional<Ipv4Header> ipv4Header;
    std::optional<TcpHeader> tcpHeader;
    std::optional<UdpHeader> udpHeader;

#if defined(__APPLE__)
    std::unique_ptr<CaptureNetwork> capture = std::make_unique<MacCapture>();
#elif defined(__linux__)
    std::unique_ptr<CaptureNetwork> capture = std::make_unique<LinuxCapture>();
#endif

    capture->start();
    std::cout << "Press 'p' to pause/resume display, 'd' to switch to detailed mode, "
        "Ctrl+C to stop." << std::endl;

    while (SignalHandler::running()) {
        handleKey(input.pollKey(), display);
        RawPacket packet;

        if (!capture->receive(packet)) {
            if (!SignalHandler::running())
                break;
            errorCount++;
            continue;
        }
        packetCount++;

        EthernetHeader ethernetHeader;
        if (!EthernetParser::parse(packet.buffer, ethernetHeader)) {
            errorCount++;
            continue;
        }
        if (ethernetHeader.etherType == static_cast<std::uint16_t>(EthernetType::IPv4)) {
            std::size_t ipv4Offset = ethernetHeader.vlanTagged ? 18 : 14;
            std::vector<std::uint8_t> ipv4Data(packet.buffer.begin() + static_cast<long>(ipv4Offset), packet.buffer.end());
            Ipv4Header parsedIpv4;
    
            if (Ipv4Parser::parse(ipv4Data, parsedIpv4)) {
                ipv4Header = parsedIpv4;

                if (!parsedIpv4.isFragmented) {
                    std::vector<std::uint8_t> payload(ipv4Data.begin() + static_cast<long>(parsedIpv4.headerLength), ipv4Data.end());

                    if (parsedIpv4.protocol == 6) {
                        TcpHeader parsedTcp;
                        if (TcpParser::parse(payload, parsedTcp))
                            tcpHeader = parsedTcp;
                        else
                            errorCount++;
                    } else if (parsedIpv4.protocol == 17) {
                        UdpHeader parsedUdp;
                        if (UdpParser::parse(payload, parsedUdp))
                            udpHeader = parsedUdp;
                        else
                            errorCount++;
                    }
                }
            } else
                errorCount++;
        }
        display.show(packet, ethernetHeader, ipv4Header, tcpHeader, udpHeader);
    }
    capture->stop();
    display.displayStats(packetCount, errorCount);
    return 0;
}
