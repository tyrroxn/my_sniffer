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
#include "analysis/SpikeNetworkDetector.hpp"
#include "analysis/SpikeServicesDetector.hpp"
#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using namespace analyser;

static constexpr std::size_t MAX_LISTED_PORTS = 10;

static void printUsage(const char *programName)
{
    std::cout << "Usage: " << programName << " [-w <whitelist>] <log file>\n\n"
        "Analyses a my_sniffer log (minimum or detailed mode) and reports\n"
        "[SERVICE-SPIKE]: abnormal volume from one IP to one service (IP:port).\n"
        "[NETWORK-SPIKE]: whole network traffic at least 3x its usual average.\n"
        "[BEACON]:        connections to one destination (IP:port) at a nearly constant interval.\n"
        "[FOREIGN-IP]:    traffic to or from an IPv4 address outside the whitelist,\n"
        "                 with its direction and LAN (RFC1918) / WAN context (only with -w).\n"
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

static std::optional<ForeignIpDetector> loadWhitelist(const std::string &path, bool &failed)
{
    IpWhitelist whitelist;
    std::string error;

    failed = false;
    if (!whitelist.load(path, error)) {
        std::cerr << "Error: " << error << std::endl;
        failed = true;
        return std::nullopt;
    }
    std::cout << "Whitelist: " << whitelist.size() << " range(s) from " << path << std::endl;
    return ForeignIpDetector(std::move(whitelist));
}

static std::string formatTime(double seconds)
{
    std::time_t whole = static_cast<std::time_t>(seconds);
    int milliseconds = static_cast<int>(std::lround((seconds - static_cast<double>(whole)) * 1000.0)) % 1000;
    std::tm tmValue{};
    std::ostringstream oss;

    localtime_r(&whole, &tmValue);
    oss << std::put_time(&tmValue, "%Y-%m-%d %H:%M:%S") << "."
        << std::setw(3) << std::setfill('0') << milliseconds;
    return oss.str();
}

static void reportService(const SpikeAlert &alert)
{
    std::ostringstream duration;

    duration << std::fixed << std::setprecision(1) << alert.timestampSeconds - alert.windowStartSeconds;
    std::cout << "[" << formatTime(alert.timestampSeconds) << "] [SERVICE-SPIKE] "
        << alert.sourceIp << " -> " << alert.destinationIp << ":" << alert.destinationPort
        << "  " << alert.packetCount << " packets (" << alert.byteCount << "B)"
        << " from " << formatTime(alert.windowStartSeconds).substr(11)
        << " to " << formatTime(alert.timestampSeconds).substr(11) << " (" << duration.str() << "s)"
        << "  > limit " << SpikeServicesDetector::limit << " in " << SpikeServicesDetector::windowSeconds << "s";
    std::cout << "  => scan, brute-force or application DoS" << std::endl;
    return;
}

static void reportNetwork(const NetworkSpikeAlert &alert)
{
    std::ostringstream duration;
    std::ostringstream average;

    duration << std::fixed << std::setprecision(1) << alert.timestampSeconds - alert.windowStartSeconds;
    average << std::fixed << std::setprecision(1) << alert.averagePackets;
    std::cout << "[" << formatTime(alert.timestampSeconds) << "] [NETWORK-SPIKE] "
        << alert.packetCount << " packets (" << alert.byteCount << "B)"
        << " from " << formatTime(alert.windowStartSeconds).substr(11)
        << " to " << formatTime(alert.timestampSeconds).substr(11) << " (" << duration.str() << "s)"
        << "  >= " << SpikeNetworkDetector::spikeFactor << "x usual " << average.str()
        << " packets per " << SpikeNetworkDetector::windowSeconds << "s";
    std::cout << "  => flood or DDoS on the network" << std::endl;
    return;
}

static void reportBeacon(const BeaconAlert &alert)
{
    std::ostringstream interval;

    interval << std::fixed << std::setprecision(1) << alert.intervalSeconds << "s (deviation "
        << std::setprecision(2) << alert.deviationSeconds << "s)";
    std::cout << "[" << formatTime(alert.timestampSeconds) << "] [BEACON] "
        << alert.sourceIp << " -> " << alert.destinationIp << ":" << alert.destinationPort
        << "  " << alert.occurrences << " connections every " << interval.str()
        << "  => possible malware / C2 beaconing" << std::endl;
    return;
}

static std::string zoneName(Zone zone)
{
    return zone == Zone::Lan ? "LAN" : "WAN";
}

static std::string directionLabel(Direction direction, Zone zone)
{
    if (direction == Direction::Outgoing)
        return "outgoing to " + zoneName(zone);
    if (direction == Direction::Incoming)
        return "incoming from " + zoneName(zone);
    return "transit, " + zoneName(zone);
}

static std::string endpoint(const std::string &ip, std::uint16_t port)
{
    return port == 0 ? ip : ip + ":" + std::to_string(port);
}

static void reportForeignIp(const ForeignIpAlert &alert)
{
    std::cout << "[" << formatTime(alert.timestampSeconds) << "] [FOREIGN-IP] "
        << directionLabel(alert.direction, alert.zone) << "  "
        << endpoint(alert.sourceIp, alert.sourcePort) << " -> "
        << endpoint(alert.destinationIp, alert.destinationPort)
        << (alert.protocol.empty() ? "" : " " + alert.protocol) << "  => ";
    if (alert.direction == Direction::Outgoing)
        std::cout << "destination ";
    else if (alert.direction == Direction::Incoming)
        std::cout << "source ";
    std::cout << alert.foreignIp << " not in whitelist" << std::endl;
    return;
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
    bool whitelistFailed = false;

    int result = parseArgs(argc, argv, logPath, whitelistPath);
    if (result == 1)
        return 0;
    if (result == 2)
        return 1;

    std::optional<ForeignIpDetector> foreignIps;
    if (whitelistPath) {
        foreignIps = loadWhitelist(*whitelistPath, whitelistFailed);
        if (whitelistFailed)
            return 1;
    }

    std::vector<std::filesystem::path> parts = logParts(logPath);
    SpikeServicesDetector spikes;
    SpikeNetworkDetector networkSpikes;
    BeaconDetector beacons;
    std::size_t lines = 0;
    std::size_t packets = 0;
    std::size_t alerts = 0;
    std::size_t networkAlerts = 0;
    std::size_t beaconAlerts = 0;
    std::size_t foreignAlerts = 0;

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
            packets++;
            std::optional<SpikeAlert> alert = spikes.addPacket(entry->timestampSeconds,
                entry->sizeBytes, entry->sourceIp, entry->destinationIp, entry->destinationPort);
            if (alert) {
                alerts++;
                reportService(*alert);
            }
            std::optional<NetworkSpikeAlert> networkAlert = networkSpikes.addPacket(entry->timestampSeconds,
                entry->sizeBytes);
            if (networkAlert) {
                networkAlerts++;
                reportNetwork(*networkAlert);
            }
            std::optional<BeaconAlert> beaconAlert = beacons.addPacket(entry->timestampSeconds,
                entry->sourceIp, entry->destinationIp, entry->destinationPort, entry->tcpFlags);
            if (beaconAlert) {
                beaconAlerts++;
                reportBeacon(*beaconAlert);
            }
            if (!foreignIps)
                continue;
            const auto foreignAlertsForPacket = foreignIps->addPacket(entry->timestampSeconds,
                entry->sizeBytes, entry->sourceIp, entry->sourcePort, entry->destinationIp,
                entry->destinationPort,entry->protocol);
            for (const ForeignIpAlert &foreignAlert : foreignAlertsForPacket) {
                foreignAlerts++;
                reportForeignIp(foreignAlert);
            }
        }
        lines += parser.getNbLines();
    }

    std::cout << "\n===== Summary =====\n"
        << parts.size() << " file(s), " << lines << " line(s) read, " << packets << " packet record(s)\n"
        << "SERVICE-SPIKE: " << alerts << "\n"
        << "NETWORK-SPIKE: " << networkAlerts << "\n"
        << "BEACON: " << beaconAlerts << std::endl;
    if (!foreignIps) {
        std::cout << "FOREIGN-IP: disabled (use -w <whitelist>)" << std::endl;
        return 0;
    }
    std::cout << "FOREIGN-IP: " << foreignAlerts << std::endl;
    return 0;
}
