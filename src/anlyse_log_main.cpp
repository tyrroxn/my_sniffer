/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** analyse_log main
*/

#include "analysis/BeaconDetector.hpp"
#include "analysis/ForeignIpDetector.hpp"
#include "analysis/IpWhitelist.hpp"
#include "analysis/LogParser.hpp"
#include "analysis/ProtocolDetector.hpp"
#include "analysis/Report.hpp"
#include "analysis/SpikeNetworkDetector.hpp"
#include "analysis/SpikeServicesDetector.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

using namespace analyser;

static void printUsage(const char *programName)
{
    std::cout << "Usage: " << programName << " [-w <whitelist>] <log file>\n\n"
        "Analyses a my_sniffer log (minimum or detailed mode) and reports\n"
        "[SERVICE-SPIKE]: abnormal volume from one IP to one service (IP:port).\n"
        "[NETWORK-SPIKE]: whole network traffic at least 3x its usual average.\n"
        "[BEACON]:        connections to one destination (IP:port) at a nearly constant interval.\n"
        "[FOREIGN-IP]:    traffic to or from an IPv4 address outside the whitelist,\n"
        "                 with its direction and LAN (RFC1918) / WAN context (only with -w).\n"
        "[PROTO-MISMATCH]: payload not matching the protocol of a standard port\n"
        "                 (TCP 80 HTTP, 443 TLS, 22 SSH...), detailed logs only.\n"
        "Rotated parts (<name>.1.log, <name>.2.log...) are read too, oldest first.\n\n"
        "Options:\n"
        "  -h, --help                  Show this help message and exit\n"
        "  -w, --whitelist <file>      Trusted IPs and ranges (CIDR), one per line:\n"
        "                              enables [FOREIGN-IP] (e.g. -w config/whitelist.conf)\n";
    return;
}

static int parseArgs(int argc, char **argv, std::string &logPath, std::optional<std::string> &whitelistPath)
{
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 1;
        } else if (arg == "-w" || arg == "--whitelist") {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << arg << std::endl;
                return 2;
            }
            whitelistPath = argv[++i];
        } else if (arg.rfind("--whitelist=", 0) == 0)
            whitelistPath = arg.substr(12);
        else if (logPath.empty() && arg[0] != '-')
            logPath = arg;
        else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            return 2;
        }
    }
    if (logPath.empty()) {
        printUsage(argv[0]);
        return 2;
    }
    return 0;
}

static std::vector<std::filesystem::path> logParts(const std::filesystem::path &path)
{
    std::filesystem::path directory = path.parent_path();
    std::string extension = path.extension().string();
    std::string name = path.stem().string();
    std::size_t dot = name.rfind('.');
    std::vector<std::filesystem::path> parts{directory / (name + extension)};

    if (dot != std::string::npos && dot + 1 < name.size()
        && name.find_first_not_of("0123456789", dot + 1) == std::string::npos
        && std::filesystem::exists(directory / (name.substr(0, dot) + extension))) {
        name.erase(dot);
        parts = {directory / (name + extension)};
    }
    for (int i = 1; std::filesystem::exists(directory / (name + "." + std::to_string(i) + extension)); i++)
        parts.insert(parts.begin(), directory / (name + "." + std::to_string(i) + extension));
    return parts;
}


static bool startsCapture(const std::filesystem::path &path)
{
    std::ifstream file(path);
    std::string firstLine;

    std::getline(file, firstLine);
    return firstLine.find("Capture started") != std::string::npos;
}

int main(int argc, char **argv)
{
    std::string logPath;
    std::optional<std::string> whitelistPath;
    Report report;

    int result = parseArgs(argc, argv, logPath, whitelistPath);
    if (result == 1)
        return 0;
    if (result == 2)
        return 1;

    std::optional<ForeignIpDetector> foreignIps;
    if (whitelistPath) {
        IpWhitelist whitelist;
        std::string error;

        if (!whitelist.load(*whitelistPath, error)) {
            std::cerr << "Error: " << error << std::endl;
            return 1;
        }
        report.setWhitelist(*whitelistPath, whitelist.size());
        foreignIps.emplace(std::move(whitelist));
    }

    std::vector<std::filesystem::path> parts = logParts(logPath);
    SpikeServicesDetector spikes;
    SpikeNetworkDetector networkSpikes;
    BeaconDetector beacons;
    ProtocolDetector protocols;

    report.setLog(logPath, parts.size());
    for (const std::filesystem::path &part : parts) {
        std::ifstream file(part);
        if (!file) {
            std::cerr << "Cannot open log file: " << part.string() << std::endl;
            return 1;
        }
        if (part == parts.front() && !startsCapture(part))
            std::cerr << "Warning: " << part.string() << " does not start the capture, "
                "older parts were deleted by log rotation" << std::endl;

        LogParser parser(file);

        while (std::optional<LogEntry> entry = parser.nextEntry()) {
            report.addPacket(*entry);
            if (std::optional<SpikeAlert> alert = spikes.addPacket(entry->timestampSeconds,
                    entry->sizeBytes, entry->sourceIp, entry->destinationIp, entry->destinationPort))
                report.add(*alert);
            if (std::optional<NetworkSpikeAlert> alert = networkSpikes.addPacket(entry->timestampSeconds,
                    entry->sizeBytes))
                report.add(*alert);
            if (std::optional<BeaconAlert> alert = beacons.addPacket(entry->timestampSeconds,
                    entry->sourceIp, entry->destinationIp, entry->destinationPort, entry->tcpFlags))
                report.add(*alert);
            if (std::optional<ProtocolMismatchAlert> alert = protocols.addPacket(*entry))
                report.add(*alert);
            if (!foreignIps)
                continue;
            for (const ForeignIpAlert &alert : foreignIps->addPacket(entry->timestampSeconds,
                    entry->sizeBytes, entry->sourceIp, entry->sourcePort, entry->destinationIp,
                    entry->destinationPort, entry->protocol))
                report.add(alert);
        }
        report.addLines(parser.getNbLines());
    }

    report.print(std::cout);
    return 0;
}
