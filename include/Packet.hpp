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
    std::size_t headerLength = 0;
    std::string sourceAddress;
    std::string destinationAddress;
};

struct TcpHeader {
    std::uint16_t sourcePort;
    std::uint16_t destinationPort;
    std::uint32_t sequenceNumber;
    std::uint32_t acknowledgmentNumber;
    std::uint8_t dataOffset;
    bool NS_flag = false;
    bool CWR_flag = false;
    bool ECE_flag = false;
    bool URG_flag = false;
    bool ACK_flag = false;
    bool PSH_flag = false;
    bool RST_flag = false;
    bool SYN_flag = false;
    bool FIN_flag = false;
    std::uint16_t windowSize;
    std::uint16_t checksum;
    std::uint16_t urgentPointer;
    std::size_t headerLength = 0;
    std::vector<std::uint8_t> payload;
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

