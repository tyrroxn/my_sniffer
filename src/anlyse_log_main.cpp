/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** analyse_log main
*/

#include "analysis/BeaconDetector.hpp"
#include "analysis/LogParser.hpp"
#include "analysis/SpikeNetworkDetector.hpp"
#include "analysis/SpikeServicesDetector.hpp"
#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace analyser;


static void printUsage(const char *programName)
{
    std::cout << "Usage: " << programName << " <log file>\n\n"
        "Analyses a my_sniffer log (minimum or detailed mode) and reports\n"
        "[SERVICE-SPIKE]: abnormal volume from one IP to one service (IP:port).\n"
        "[NETWORK-SPIKE]: whole network traffic at least 3x its usual average.\n"
        "[BEACON]:        connections to one destination (IP:port) at a nearly constant interval.\n"
        "Rotated parts (<name>.1.log, <name>.2.log...) are read too, oldest first.\n";
    return;
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
    if (argc == 2 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {
        printUsage(argv[0]);
        return 0;
    }
    if (argc != 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::vector<std::filesystem::path> parts = logParts(argv[1]);
    SpikeServicesDetector spikes;
    SpikeNetworkDetector networkSpikes;
    BeaconDetector beacons;
    std::size_t lines = 0;
    std::size_t packets = 0;
    std::size_t alerts = 0;
    std::size_t networkAlerts = 0;
    std::size_t beaconAlerts = 0;

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
        }
        lines += parser.getNbLines();
    }

    std::cout << "\n===== Summary =====\n"
        << parts.size() << " file(s), " << lines << " line(s) read, " << packets << " packet record(s)\n"
        << "SERVICE-SPIKE: " << alerts << "\n"
        << "NETWORK-SPIKE: " << networkAlerts << "\n"
        << "BEACON: " << beaconAlerts << std::endl;
    return 0;
}
