/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** LogParser
*/

#ifndef LOGPARSER_HPP_
#define LOGPARSER_HPP_

#include <cstddef>
#include <cstdint>
#include <istream>
#include <optional>
#include <string>

namespace sniffer {

const std::string DETAILED_HEADER_START = "==== packet (";
const std::string DETAILED_HEADER_END = " bytes) ====";

struct LogEntry {
    double timestampSeconds = 0.0;
    std::size_t sizeBytes = 0;
    std::string sourceIp;
    std::uint16_t sourcePort = 0;
    std::string destinationIp; 
    std::uint16_t destinationPort = 0;
    std::string protocol;
    std::optional<std::string> tcpFlags;
};

class LogParser {
    public:
        LogParser(std::istream &inputStream) : inputStream(inputStream) {};
        std::optional<LogEntry> parseLine(const std::string &line);
        std::optional<LogEntry> getEntry() const { return entry; }
        std::optional<LogEntry> parseDetailedLine(const std::string &line);
        std::optional<LogEntry> nextEntry();
        int getNbLines() const { return nbLines; }
        void parse();
    private:
        std::istream &inputStream;
        std::optional<LogEntry> entry;
        int nbLines = 0;
       
};


}

#endif /* !LOGPARSER_HPP_ */
