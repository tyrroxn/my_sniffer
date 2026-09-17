/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Logger
*/

#ifndef LOGGER_HPP_
#define LOGGER_HPP_

#include "Packet.hpp"
#include "Ipv4Parser.hpp"
#include "TcpParser.hpp"
#include "UdpParser.hpp"
#include "Helper.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <cstdio>
#include <optional>
#include <sstream>

namespace spdlog {
class logger;
}

namespace sniffer {

static constexpr std::size_t MAX_LOG_FILE_SIZE = 10 * 1024 * 1024;
static constexpr std::size_t MAX_LOG_FILES = 3;

class Logger {
    public:
        static void init(bool active, const std::string &logFilePath);
        static void debug(const std::string &message);
        static void info(const std::string &message);
        static void warn(const std::string &message);
        static void error(const std::string &message);
        static std::string writeLog(const RawPacket &packet, const EthernetHeader &ethernet, const std::optional<Ipv4Header> &ipv4,
            const std::optional<TcpHeader> &tcp, const std::optional<UdpHeader> &udp, bool verbose);
        

    private:
        static inline std::shared_ptr<spdlog::logger> logger;
          
        static void writeLogMinimum(std::ostream &os, const RawPacket &packet, const EthernetHeader &ethernet,
            const std::optional<Ipv4Header> &ipv4, const std::optional<TcpHeader> &tcp,
            const std::optional<UdpHeader> &udp);
        static void writeLogDetailed(std::ostream &os, const RawPacket &packet, const EthernetHeader &ethernet,
            const std::optional<Ipv4Header> &ipv4, const std::optional<TcpHeader> &tcp,
            const std::optional<UdpHeader> &udp);
};

}

#endif /* !LOGGER_HPP_ */
