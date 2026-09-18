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
#include "PacketFilter.hpp"
#include "TerminalInput.hpp"
#include "Logger.hpp"
#include <memory>
#include <optional>
#include <string>

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
    return;
}

static void printUsage(const char *programName)
{
    std::cout << "Usage: " << programName << " [options]\n\n"
        "Options:\n"
        "  -h, --help          Show this help message and exit\n"
        "  -d, --detailed      Write logs in detailed mode and display detailed information (default: minimum)\n"
        "  --log               Write logs to disk at the default path (my_sniffer.log)\n"
        "  --log=<path>        Write logs to disk at <path>\n"
        "  --log <path>        Same as --log=<path>\n"
        "  -f, --filter <expr> Filter packets to display and log\n"
        "                      Available filters:\n"
        "                        proto=<type>       tcp, udp, arp, ipv6, unknown\n"
        "                        sport=<port>       Source port\n"
        "                        dport=<port>       Destination port\n"
        "                        port=<port>        Source or destination port\n"
        "                        src=<ip>           Source IPv4 address\n"
        "                        dst=<ip>           Destination IPv4 address\n"
        "                        ipv4=<ip>          Any matching IPv4 address\n"
        "                        tcpflags=<flags>   NS, CWR, ECE, URG, ACK, PSH,\n"
        "                                           RST, SYN, FIN\n"
        "                        minsize=<size>     Packet size >= <size> bytes\n"
        "                        maxsize=<size>     Packet size <= <size> bytes\n"
        "                        contains=<text>    Payload contains <text> (e.g. \"GET /\")\n"
        "                      Examples:\n"
        "                        --filter proto=tcp\n"
        "                        -f sport=80\n"
        "                        -f src=192.168.1.1\n"
        "                        -f tcpflags=SYN/ACK\n"
        "                      Combine values with '/' or repeat -f.\n\n"
        "Runtime keys (while capturing):\n"
        "  p                   Pause/resume the live display\n"
        "  d                   Toggle minimum/detailed display\n"
        "  Ctrl+C              Stop the capture and print a summary\n";
    return;
}

static int parseArgs(int argc, char **argv, bool &logActive, std::string &logPath, bool &detailed,
    PacketFilter &filter)
{
    logActive = false;
    logPath = "my_sniffer.log";
    detailed = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 1;
        } else if (arg.rfind("--log=", 0) == 0) {
            logActive = true;
            logPath = arg.substr(6);
        } else if (arg == "--log") {
            logActive = true;
            if (i + 1 < argc && argv[i + 1][0] != '-')
                logPath = argv[++i];
        } else if (arg == "-d" || arg == "--detailed")
            detailed = true;
        else if (arg.rfind("--filter=", 0) == 0) {
            if (!filter.parse(arg.substr(9)))
                return 2;
        } else if (arg == "-f" || arg == "--filter") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << std::endl;
                return 2;
            }
            if (!filter.parse(argv[++i]))
                return 2;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            return 2;
        }
    }
    return 0;
}

static std::unique_ptr<CaptureNetwork> createCapture()
{
#if defined(__APPLE__)
    return std::make_unique<MacCapture>();
#elif defined(__linux__)
    return std::make_unique<LinuxCapture>();
#endif
}

static void parseTransportLayer(const std::vector<std::uint8_t> &payload, std::uint8_t protocol,
    std::optional<TcpHeader> &tcpHeader, std::optional<UdpHeader> &udpHeader, std::size_t &errorCount)
{
    if (protocol == 6) {
        TcpHeader parsedTcp;
        if (TcpParser::parse(payload, parsedTcp))
            tcpHeader = parsedTcp;
        else {
            errorCount++;
            Logger::warn("Failed to parse TCP header");
        }
    } else if (protocol == 17) {
        UdpHeader parsedUdp;
        if (UdpParser::parse(payload, parsedUdp))
            udpHeader = parsedUdp;
        else {
            errorCount++;
            Logger::warn("Failed to parse UDP header");
        }
    }
    return;
}

static void parseIpv4Layer(const RawPacket &packet, const EthernetHeader &ethernetHeader,
    std::optional<Ipv4Header> &ipv4Header, std::optional<TcpHeader> &tcpHeader,
    std::optional<UdpHeader> &udpHeader, std::size_t &errorCount)
{
    std::size_t ipv4Offset = ethernetHeader.vlanTagged ? 18 : 14;
    std::vector<std::uint8_t> ipv4Data(
        packet.buffer.begin() + static_cast<long>(ipv4Offset), packet.buffer.end());
    Ipv4Header parsedIpv4;

    if (!Ipv4Parser::parse(ipv4Data, parsedIpv4)) {
        errorCount++;
        Logger::warn("Failed to parse IPv4 header");
        return;
    }

    ipv4Header = parsedIpv4;
    std::vector<std::uint8_t> payload(
        ipv4Data.begin() + static_cast<long>(parsedIpv4.headerLength), ipv4Data.end());
    parseTransportLayer(payload, parsedIpv4.protocol, tcpHeader, udpHeader, errorCount);
    return;
}

static void processPacket(const RawPacket &packet, PacketDisplay &display, bool detailed,
    const PacketFilter &filter, std::size_t &errorCount, std::size_t &filteredCount)
{
    EthernetHeader ethernetHeader;
    std::optional<Ipv4Header> ipv4Header;
    std::optional<TcpHeader> tcpHeader;
    std::optional<UdpHeader> udpHeader;

    if (!EthernetParser::parse(packet.buffer, ethernetHeader)) {
        errorCount++;
        Logger::warn("Failed to parse Ethernet header");
        return;
    }

    if (ethernetHeader.etherType == static_cast<std::uint16_t>(EthernetType::IPv4))
        parseIpv4Layer(packet, ethernetHeader, ipv4Header, tcpHeader, udpHeader, errorCount);

    if (!filter.matches(ethernetHeader, ipv4Header, packet.buffer.size(), tcpHeader, udpHeader)) {
        filteredCount++;
        return;
    }

    Logger::debug(Logger::writeLog(packet, ethernetHeader, ipv4Header, tcpHeader, udpHeader, detailed));
    display.show(packet, ethernetHeader, ipv4Header, tcpHeader, udpHeader);
    return;
}

static void runCaptureLoop(CaptureNetwork &capture, TerminalInput &input, PacketDisplay &display,
    bool detailed, const PacketFilter &filter, std::size_t &packetCount, std::size_t &errorCount,
    std::size_t &filteredCount)
{
    while (SignalHandler::running()) {
        handleKey(input.pollKey(), display);
        RawPacket packet;

        if (!capture.receive(packet)) {
            if (!SignalHandler::running())
                break;
            errorCount++;
            Logger::error("Failed to receive packet");
            continue;
        }
        packetCount++;
        processPacket(packet, display, detailed, filter, errorCount, filteredCount);
    }
    return;
}

int main(int argc, char **argv)
{
    bool logActive;
    std::string logPath;
    bool detailed;
    PacketFilter filter;
    std::size_t packetCount = 0;
    std::size_t errorCount = 0;
    std::size_t filteredCount = 0;

    int result = parseArgs(argc, argv, logActive, logPath, detailed, filter);
    if (result == 1)
        return 0;
    if (result == 2)
        return 1;
    Logger::init(logActive, logPath);

    SignalHandler::install();
    PacketDisplay display;
    TerminalInput input;

    display.setMode(detailed ? PacketDisplay::Mode::Detailed : PacketDisplay::Mode::Minimum);

    std::unique_ptr<CaptureNetwork> capture = createCapture();
    capture->start();
    Logger::info("Capture started");
    std::cout << "Press 'p' to pause/resume display, 'd' to switch to detailed mode, "
        "Ctrl+C to stop." << std::endl;

    runCaptureLoop(*capture, input, display, detailed, filter, packetCount, errorCount, filteredCount);

    capture->stop();
    Logger::info("Capture stopped: " + std::to_string(packetCount) + " packet(s) captured, "
        + std::to_string(filteredCount) + " filtered, "
        + std::to_string(errorCount) + " error(s)\n");
    display.displayStats(packetCount, filteredCount, errorCount);
    return 0;
}
