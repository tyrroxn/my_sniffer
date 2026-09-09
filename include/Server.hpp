/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Server
*/

#pragma once

#ifdef _WIN32
    #include <winsock2.h>
    #ifndef WIN32_LEAN_AND_MEAN
    #  define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
    #  define NOMINMAX
    #endif
    #include <windows.h>
    #ifdef ERROR
    #  undef ERROR
    #endif
#else
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <iostream>

namespace sniffer {

enum class InterfaceType {
    Ethernet,
};

enum class NetworkProtocol {
    IPv4
};

enum class TransportProtocol {
    TCP,
    UDP,
};

struct RawPacket {
    std::vector<std::uint8_t> buffer;
    std::chrono::system_clock::time_point timestamp;
    std::string sourceInterface;
};

struct ParsedPacket {
    std::string sourceInterface;
    std::chrono::system_clock::time_point timestamp;
    NetworkProtocol networkProtocol;
    TransportProtocol transportProtocol;
    std::string sourceAddress;
    std::string destinationAddress;
    std::uint16_t sourcePort;
    std::uint16_t destinationPort;
    std::vector<std::uint8_t> data;
};

class Server {
    public:
        Server();
        ~Server();
        int getSocketFd() const { return socketFd; }
        bool getPacket(RawPacket &packet);
    private:
        int socketFd;

};

}

