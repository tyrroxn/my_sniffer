/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Report
*/

#ifndef REPORT_HPP_
#define REPORT_HPP_

#include "analysis/BeaconDetector.hpp"
#include "analysis/ForeignIpDetector.hpp"
#include "analysis/LogParser.hpp"
#include "analysis/ProtocolDetector.hpp"
#include "analysis/SpikeNetworkDetector.hpp"
#include "analysis/SpikeServicesDetector.hpp"
#include <cstddef>
#include <optional>
#include <ostream>
#include <string>
#include <vector>
#include <algorithm>
#include <array>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace analyser {


const std::size_t TAG_ANALYSIS_MAX_WIDTH = 16;
const std::size_t DIRECTION_MAX_WIDTH = 17;
const std::size_t NAME_ANALYSIS_MAX_WIDTH = 14;
const std::size_t COUNT_MAX_WIDTH = 8;
const std::size_t OVERVIEW_MAX_WIDTH = 11;


enum class Detection {
    ServiceSpike,
    NetworkSpike,
    Beacon,
    ProtocolMismatch,
    ForeignIp,
};

struct ReportAlert {
    double timestampSeconds = 0.0;
    Detection detection = Detection::ServiceSpike;
    std::string flow;
    std::string detail;
};

class Report {
    public:
        static constexpr std::size_t maxFlowWidth = 50;

        void setLog(const std::string &name, std::size_t files);
        void setWhitelist(const std::string &path, std::size_t ranges);
        void addLines(std::size_t count) { lines += count; }
        void addPacket(const LogEntry &entry);

        void add(const SpikeAlert &alert);
        void add(const NetworkSpikeAlert &alert);
        void add(const BeaconAlert &alert);
        void add(const ProtocolMismatchAlert &alert);
        void add(const ForeignIpAlert &alert);

        std::size_t count(Detection detection) const;
        std::optional<std::string> disabledReason(Detection detection) const;
        void print(std::ostream &output) const;

        static std::string name(Detection detection);
        static std::string description(Detection detection);
        static std::string formatTime(double seconds);
        static std::string formatBytes(std::size_t bytes);
        static std::string formatDuration(double seconds);

    private:
        std::string logName;
        std::size_t files = 0;
        std::size_t lines = 0;
        std::size_t packets = 0;
        std::size_t bytes = 0;
        std::size_t payloadRecords = 0;
        std::optional<double> firstPacket;
        double lastPacket = 0.0;
        std::optional<std::string> whitelist;
        std::vector<ReportAlert> alerts;
        std::array<Detection, 5> DETECTIONS = { Detection::ServiceSpike, Detection::NetworkSpike,
            Detection::Beacon, Detection::ProtocolMismatch, Detection::ForeignIp,};
        void printOverview(std::ostream &output) const;
        void printAlerts(std::ostream &output) const;
        void printSummary(std::ostream &output) const;
};

}

#endif /* !REPORT_HPP_ */
