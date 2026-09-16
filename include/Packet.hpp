/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Server
*/

#pragma once


#include <unistd.h>
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

enum class EthernetType {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD
};

struct Ipv4Header {
    std::uint8_t version;
    std::uint8_t ihl;
    std::uint8_t typeOfService;
    std::uint16_t totalLength;
    std::uint8_t ttl;
    std::uint8_t protocol;
    std::uint16_t headerChecksum;
    bool checksumValid = false;
    bool DF_flag = false;
    bool MF_flag = false;
    bool isFragmented = false;
    std::uint16_t fragmentOffset = 0;
    std::string sourceAddress;
    std::string destinationAddress;
};
struct EthernetHeader {
    std::string destinationMac;
    std::string sourceMac;
    std::uint16_t etherType;
    bool vlanTagged = false;
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

}

