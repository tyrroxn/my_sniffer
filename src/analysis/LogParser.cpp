/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** LogParser
*/

#include "analysis/LogParser.hpp"
#include <charconv>
#include <ctime>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <utility>
#include <vector>

using namespace analyser;

std::optional<double> parseTimestamp(const std::string &text)
{
    std::size_t dot = text.find('.');
    std::tm tmValue{};
    int milliseconds = 0;

    if (dot == std::string::npos)
        return std::nullopt;
    auto [millisecondsEnd, millisecondsError] = std::from_chars(text.data() + dot + 1,
        text.data() + text.size(), milliseconds);
    if (millisecondsError != std::errc() || millisecondsEnd != text.data() + text.size())
        return std::nullopt;
    std::istringstream iss(text.substr(0, dot));
    iss >> std::get_time(&tmValue, "%Y-%m-%d %H:%M:%S");
    if (iss.fail())
        return std::nullopt;
    tmValue.tm_isdst = -1;
    std::time_t seconds = std::mktime(&tmValue);
    if (seconds == static_cast<std::time_t>(-1))
        return std::nullopt;
    return static_cast<double>(seconds) + milliseconds / 1000.0;
}

std::optional<std::pair<double, std::string>> splitPrefix(const std::string &line)
{
    const std::string level = "] [debug] ";
    std::size_t close = line.find(level);

    if (line[0] != '[' || close == std::string::npos)
        return std::nullopt;
    std::optional<double> timestamp = parseTimestamp(line.substr(1, close - 1));
    if (!timestamp)
        return std::nullopt;
    return std::make_pair(*timestamp, line.substr(close + level.size()));
}

bool parsePorts(const std::vector<std::string> &tokens, std::size_t index, LogEntry &entry)
{
    std::uint16_t sourcePort = 0;
    std::uint16_t destinationPort = 0;

    if (tokens.size() < index + 3 || tokens[index + 1] != "->")
        return false;
    const std::string &source = tokens[index];
    const std::string &destination = tokens[index + 2];
    auto [sourceEnd, sourceError] = std::from_chars(source.data(), source.data() + source.size(),
        sourcePort);
    auto [destinationEnd, destinationError] = std::from_chars(destination.data(),
        destination.data() + destination.size(), destinationPort);
    if (sourceError != std::errc() || sourceEnd != source.data() + source.size()
        || destinationError != std::errc() || destinationEnd != destination.data() + destination.size())
        return false;
    entry.sourcePort = sourcePort;
    entry.destinationPort = destinationPort;
    return true;
}

std::optional<std::string> parseFlags(const std::string &text)
{
    std::size_t open = text.find('[');
    std::size_t close = text.find(']', open);

    if (open == std::string::npos || close == std::string::npos)
        return std::nullopt;
    return text.substr(open, close - open + 1);
}

void parseDetailedBody(const std::string &line, LogEntry &entry)
{
    std::istringstream iss(line);
    std::vector<std::string> tokens{std::istream_iterator<std::string>(iss),
        std::istream_iterator<std::string>()};

    if (tokens.empty())
        return;
    if (tokens[0] == "IPv4" && tokens.size() >= 4 && tokens[2] == "->") {
        entry.sourceIp = tokens[1];
        entry.destinationIp = tokens[3];
        for (const std::string &token : tokens)
            if (token.compare(0, std::string("protocol=").size(), "protocol=") == 0)
                entry.protocol = token.substr(9);
        return;
    }
    if ((tokens[0] == "TCP" || tokens[0] == "UDP") && !entry.sourceIp.empty()
        && entry.destinationPort == 0 && parsePorts(tokens, 1, entry)) {
        entry.protocol = tokens[0];
        if (tokens[0] == "TCP")
            entry.tcpFlags = parseFlags(line);
    }
    return;
}


std::optional<LogEntry> LogParser::parseLine(const std::string &line)
{
    std::optional<std::pair<double, std::string>> prefix = splitPrefix(line);

    if (!prefix)
        return std::nullopt;

    LogEntry result;
    std::istringstream iss(prefix->second);
    std::vector<std::string> tokens{std::istream_iterator<std::string>(iss),
        std::istream_iterator<std::string>()};

    if (tokens.size() < 4 || tokens[1] != "->" || tokens.back().back() != 'B')
        return std::nullopt;

    const std::string &size = tokens.back();
    auto [sizeEnd, sizeError] = std::from_chars(size.data(), size.data() + size.size() - 1,
        result.sizeBytes);

    if (sizeError != std::errc() || sizeEnd != size.data() + size.size() - 1)
        return std::nullopt;

    result.timestampSeconds = prefix->first;
    if (tokens[3] == "EtherType" || tokens.size() < 8 || tokens[4] != "->")
        return result;
    result.sourceIp = tokens[3];
    result.destinationIp = tokens[5];
    result.protocol = tokens[6];
    if ((result.protocol == "TCP" || result.protocol == "UDP") && parsePorts(tokens, 7, result)
        && result.protocol == "TCP")
        result.tcpFlags = parseFlags(prefix->second);
    return result;
}

std::optional<LogEntry> LogParser::parseDetailedLine(const std::string &line)
{
    const std::optional<std::pair<double, std::string>> parsedPrefix = splitPrefix(line);

    if (!parsedPrefix)
        return std::nullopt;

    const std::string &message = parsedPrefix->second;
    const bool hasValidStart = message.compare(0, DETAILED_HEADER_START.size(),
        DETAILED_HEADER_START) == 0;
    const bool isLongEnough = message.size() >= DETAILED_HEADER_END.size();
    const bool hasValidEnd = isLongEnough
        && message.compare(message.size() - DETAILED_HEADER_END.size(),
            DETAILED_HEADER_END.size(), DETAILED_HEADER_END) == 0;

    if (!hasValidStart || !hasValidEnd)
        return std::nullopt;

    const std::size_t sizeStart = DETAILED_HEADER_START.size();
    const std::size_t sizeLength = message.size() - sizeStart - DETAILED_HEADER_END.size();
    const std::string packetSize = message.substr(sizeStart, sizeLength);
    LogEntry entry;

    auto [sizeEnd, sizeError] = std::from_chars(packetSize.data(),
        packetSize.data() + packetSize.size(), entry.sizeBytes);
    if (sizeError != std::errc() || sizeEnd != packetSize.data() + packetSize.size())
        return std::nullopt;

    entry.timestampSeconds = parsedPrefix->first;
    return entry;
}

void LogParser::parse()
{
    std::string line;

    entry = std::nullopt;
    while (std::getline(inputStream, line)) {
        nbLines++;
        if (std::optional<LogEntry> header = parseDetailedLine(line)) {
            while (inputStream.peek() != std::char_traits<char>::eof()
                && inputStream.peek() != '[' && std::getline(inputStream, line)) {
                nbLines++;
                parseDetailedBody(line, *header);
            }
            entry = header;
            return;
        }
        if ((entry = parseLine(line)))
            return;
    }
    return;
}

std::optional<LogEntry> LogParser::nextEntry()
{
    parse();
    return entry;
}
