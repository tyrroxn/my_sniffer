/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Report
*/

#include "analysis/Report.hpp"


namespace analyser {

static std::string padRight(const std::string &text, std::size_t width)
{
    if (text.size() >= width)
        return text;
    return text + std::string(width - text.size(), ' ');
}

static std::string padLeft(const std::string &text, std::size_t width)
{
    if (text.size() >= width)
        return text;
    return std::string(width - text.size(), ' ') + text;
}

static std::string fixed(double value, int precision)
{
    std::ostringstream oss;

    oss << std::fixed << std::setprecision(precision) << value;
    return oss.str();
}

static std::string plain(double value)
{
    std::ostringstream oss;

    oss << value;
    return oss.str();
}

static std::string endpoint(const std::string &ip, std::uint16_t port)
{
    return port == 0 ? ip : ip + ":" + std::to_string(port);
}

static std::string volume(std::size_t packetCount, std::size_t byteCount, double seconds)
{
    return std::to_string(packetCount) + " packets, " + Report::formatBytes(byteCount)
        + " in " + Report::formatDuration(seconds);
}

static std::string payloadPreview(const std::vector<std::uint8_t> &preview, std::size_t payloadSize)
{
    bool truncated = payloadSize > preview.size();
    bool isText = true;
    std::string text;
    std::ostringstream hex;

    for (std::uint8_t byte : preview) {
        bool printable = byte >= 0x20 && byte < 0x7f;
    
        if (!printable && byte != '\r' && byte != '\n' && byte != '\t')
            isText = false;

        text += printable ? static_cast<char>(byte) : '.';
        hex << (hex.tellp() > 0 ? " " : "") << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    if (isText)
        return "\"" + text + (truncated ? "...\"" : "\"");
    return hex.str() + (truncated ? " ..." : "");
}

std::string Report::formatTime(double seconds)
{
    long long milliseconds = std::llround(seconds * 1000.0);
    std::time_t whole = static_cast<std::time_t>(milliseconds / 1000);
    std::tm tmValue{};
    std::ostringstream oss;

    localtime_r(&whole, &tmValue);
    oss << std::put_time(&tmValue, "%Y-%m-%d %H:%M:%S") << "."
        << std::setw(3) << std::setfill('0') << milliseconds % 1000;
    return oss.str();
}

std::string Report::formatBytes(std::size_t bytes)
{
    static constexpr std::array<const char *, 4> units = {"KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes) / 1024.0;
    std::size_t unit = 0;

    if (bytes < 1024)
        return std::to_string(bytes) + " B";

    while (value >= 1023.95 && unit + 1 < units.size()) {
        value /= 1024.0;
        unit++;
    }
    return fixed(value, 1) + " " + units[unit];
}

std::string Report::formatDuration(double seconds)
{
    if (seconds < 59.95)
        return fixed(seconds, 1) + "s";

    long long total = std::llround(seconds);
    std::ostringstream oss;

    if (total >= 3600)
        oss << total / 3600 << "h " << std::setw(2) << std::setfill('0');
    oss << (total % 3600) / 60 << "m " << std::setw(2) << std::setfill('0') << total % 60 << "s";
    return oss.str();
}

std::string Report::name(Detection detection)
{
    switch (detection) {
        case Detection::ServiceSpike:
            return "SERVICE-SPIKE";
        case Detection::NetworkSpike:
            return "NETWORK-SPIKE";
        case Detection::Beacon:
            return "BEACON";
        case Detection::ProtocolMismatch:
            return "PROTO-MISMATCH";
        default:
            return "FOREIGN-IP";
    }
}

std::string Report::description(Detection detection)
{
    switch (detection) {
        case Detection::ServiceSpike:
            return "more than " + std::to_string(SpikeServicesDetector::limit) + " packets in "
                + plain(SpikeServicesDetector::windowSeconds)
                + "s from one IP to one service (scan, brute-force, application DoS)";
        case Detection::NetworkSpike:
            return "network traffic at least " + plain(SpikeNetworkDetector::spikeFactor)
                + "x its usual volume over " + plain(SpikeNetworkDetector::windowSeconds)
                + "s (flood, DDoS)";
        case Detection::Beacon:
            return std::to_string(BeaconDetector::minOccurrences)
                + " connections to one destination at a constant interval (malware / C2 beaconing)";
        case Detection::ProtocolMismatch:
            return "payload not matching the protocol of a standard TCP port (80 HTTP, 443 TLS, 22 SSH...)";
        default:
            return "traffic to or from an IP outside the whitelist";
    }
}

void Report::setLog(const std::string &name, std::size_t fileCount)
{
    logName = name;
    files = fileCount;
    return;
}

void Report::setWhitelist(const std::string &path, std::size_t ranges)
{
    whitelist = std::to_string(ranges) + " range(s) from " + path;
    return;
}

void Report::addPacket(const LogEntry &entry)
{
    packets++;
    bytes += entry.sizeBytes;
    if (entry.payloadSize > 0)
        payloadRecords++;
    if (!firstPacket || entry.timestampSeconds < *firstPacket)
        firstPacket = entry.timestampSeconds;
    lastPacket = std::max(lastPacket, entry.timestampSeconds);
    return;
}

void Report::add(const SpikeAlert &alert)
{
    alerts.push_back({alert.timestampSeconds, Detection::ServiceSpike,
        alert.sourceIp + " -> " + endpoint(alert.destinationIp, alert.destinationPort),
        volume(alert.packetCount, alert.byteCount, alert.timestampSeconds - alert.windowStartSeconds)
            + " (limit " + std::to_string(SpikeServicesDetector::limit) + " per "
            + plain(SpikeServicesDetector::windowSeconds) + "s)"});
    return;
}

void Report::add(const NetworkSpikeAlert &alert)
{
    alerts.push_back({alert.timestampSeconds, Detection::NetworkSpike, "whole network",
        volume(alert.packetCount, alert.byteCount, alert.timestampSeconds - alert.windowStartSeconds)
            + " (>= " + plain(SpikeNetworkDetector::spikeFactor) + "x usual " + fixed(alert.averagePackets, 1)
            + " packets per " + plain(SpikeNetworkDetector::windowSeconds) + "s)"});
    return;
}

void Report::add(const BeaconAlert &alert)
{
    alerts.push_back({alert.timestampSeconds, Detection::Beacon,
        alert.sourceIp + " -> " + endpoint(alert.destinationIp, alert.destinationPort),
        std::to_string(alert.occurrences) + " connections every " + fixed(alert.intervalSeconds, 1)
            + "s (deviation " + fixed(alert.deviationSeconds, 2) + "s)"});
    return;
}

void Report::add(const ProtocolMismatchAlert &alert)
{
    std::string payload = formatBytes(alert.payloadSize);

    if (!alert.preview.empty())
        payload += ", starts with " + payloadPreview(alert.preview, alert.payloadSize);
    alerts.push_back({alert.timestampSeconds, Detection::ProtocolMismatch,
        endpoint(alert.sourceIp, alert.sourcePort) + " -> "
            + endpoint(alert.destinationIp, alert.destinationPort) + " " + alert.transport,
        "expected " + ProtocolDetector::name(alert.expected) + " on port " + std::to_string(alert.servicePort)
            + ", got " + ProtocolDetector::name(alert.detected) + " (" + payload + ")"});
    return;
}

void Report::add(const ForeignIpAlert &alert)
{
    std::string zone = alert.zone == Zone::Lan ? "LAN" : "WAN";
    std::string direction = "transit, " + zone;
    std::string role;

    if (alert.direction == Direction::Outgoing) {
        direction = "outgoing to " + zone;
        role = "destination ";
    } else if (alert.direction == Direction::Incoming) {
        direction = "incoming from " + zone;
        role = "source ";
    }
    alerts.push_back({alert.timestampSeconds, Detection::ForeignIp,
        endpoint(alert.sourceIp, alert.sourcePort) + " -> "
            + endpoint(alert.destinationIp, alert.destinationPort)
            + (alert.protocol.empty() ? "" : " " + alert.protocol),
        padRight(direction, DIRECTION_MAX_WIDTH) + "  => " + role + alert.foreignIp + " not in whitelist"});
    return;
}

std::size_t Report::count(Detection detection) const
{
    std::size_t matchingAlerts = 0;

    for (const ReportAlert &alert : alerts)
        if (alert.detection == detection)
            matchingAlerts++;
    return matchingAlerts;
}

std::optional<std::string> Report::disabledReason(Detection detection) const
{
    if (detection == Detection::ProtocolMismatch && payloadRecords == 0)
        return "no payload in the log, capture with my_sniffer -d";
    if (detection == Detection::ForeignIp && !whitelist)
        return "no whitelist, use -w <whitelist>";
    return std::nullopt;
}

void Report::printOverview(std::ostream &output) const
{
    output << "===== Log analysis =====\n"
        << padRight("Log:", OVERVIEW_MAX_WIDTH) << logName << ", " << files << " file(s), " << lines << " line(s) read\n"
        << padRight("Capture:", OVERVIEW_MAX_WIDTH) << packets << " packet record(s), " << formatBytes(bytes) << "\n";
    if (!firstPacket)
        output << "no packet record\n";
    else {
        std::string start = formatTime(*firstPacket).substr(0, 19);
        std::string end = formatTime(lastPacket).substr(0, 19);
        output << start << " -> " << (start.substr(0, 10) == end.substr(0, 10) ? end.substr(11) : end)
            << " (" << formatDuration(lastPacket - *firstPacket) << ")\n";
    }
    output << padRight("Traffic:", OVERVIEW_MAX_WIDTH) << packets << " packet record(s), " << formatBytes(bytes) << "\n"
        << padRight("Whitelist:", OVERVIEW_MAX_WIDTH) << whitelist.value_or("none") << "\n";
    return;
}

void Report::printAlerts(std::ostream &output) const
{
    std::size_t flowWidth = 0;

    output << "\n===== Alerts: " << alerts.size() << " =====\n";
    if (alerts.empty()) {
        output << "No alert raised.\n";
        return;
    }
    for (const ReportAlert &alert : alerts)
        flowWidth = std::max(flowWidth, std::min(alert.flow.size(), maxFlowWidth));
    for (const ReportAlert &alert : alerts)
        output << "[" << formatTime(alert.timestampSeconds) << "] "
            << padRight("[" + name(alert.detection) + "]", TAG_ANALYSIS_MAX_WIDTH) << " "
            << padRight(alert.flow, flowWidth) << "  " << alert.detail << "\n";
    return;
}

void Report::printSummary(std::ostream &output) const
{
    output << "\n===== Summary =====\n";
    for (Detection detection : DETECTIONS) {
        std::optional<std::string> reason = disabledReason(detection);
        output << padRight(name(detection), NAME_ANALYSIS_MAX_WIDTH) << "  "
            << padLeft(reason ? "disabled" : std::to_string(count(detection)), COUNT_MAX_WIDTH) << "  "
            << reason.value_or(description(detection)) << "\n";
    }
    output << padRight("Total", NAME_ANALYSIS_MAX_WIDTH) << "  " << padLeft(std::to_string(alerts.size()), COUNT_MAX_WIDTH)
        << "  alert(s)" << std::endl;
    return;
}

void Report::print(std::ostream &output) const
{
    printOverview(output);
    printAlerts(output);
    printSummary(output);
    return;
}

}
