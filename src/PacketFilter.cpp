/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** PacketFilter
*/

#include "PacketFilter.hpp"
#include <algorithm>
#include <cctype>
#include <iostream>

using namespace sniffer;

bool PacketFilter::isValidProtocol(const std::string &value) const
{
    for (const auto &proto : validProtocols) {
        if (value == proto)
            return true;
    }
    return false;
}

bool PacketFilter::isKnownKey(const std::string &key) const
{
    if (key == "proto" || key == "sport" || key == "dport" ||
        key == "port" || key == "src" || key == "dst" || key == "ipv4" ||
        key == "tcpflags" || key == "minsize" || key == "maxsize" ||
        key == "contains")
        return true;
    return false;
}

bool PacketFilter::isValidPort(const std::string &value) const
{
    if (value.empty())
        return false;
    for (char c : value) {
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    }
    try {
        return std::stoul(value) <= 65535;
    } catch (const std::out_of_range &) {
        return false;
    }
}

bool PacketFilter::isValidIpv4Address(const std::string &address) const
{
    int dots = 0;
    int num = 0;
    for (char c : address) {
        if (c == '.') {
            if (num < 0 || num > 255)
                return false;
            dots++;
            num = 0;
        } else if (std::isdigit(static_cast<unsigned char>(c))) {
            num = num * 10 + (c - '0');
        } else {
            return false;
        }
    }
    return dots == 3 && num >= 0 && num <= 255;
}

bool PacketFilter::isValidSize(const std::string &value) const
{
    if (value.empty())
        return false;
    for (char c : value) {
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    }
    try {
        std::stoul(value);
        return true;
    } catch (const std::out_of_range &) {
        return false;
    }
}

bool PacketFilter::isValidTcpFlag(const std::string &flag) const
{
    for (const auto &validFlag : validFlags) {
        if (flag == validFlag)
            return true;
    }
    return false;
}

bool PacketFilter::isValueValidForKey(const std::string &key, const std::string &value) const
{
    if (key == "proto")
        return isValidProtocol(value);
    if (key == "sport" || key == "dport" || key == "port")
        return isValidPort(value);
    if (key == "src" || key == "dst" || key == "ipv4")
        return isValidIpv4Address(value);
    if (key == "tcpflags")
        return isValidTcpFlag(value);
    if (key == "minsize" || key == "maxsize")
        return isValidSize(value);
    if (key == "contains")
        return !value.empty();
    return false;
}

std::string PacketFilter::classifyProtocol(const EthernetHeader &ethernet,
    const std::optional<Ipv4Header> &ipv4)
{
    if (ethernet.etherType == static_cast<std::uint16_t>(EthernetType::ARP))
        return "arp";
    if (ethernet.etherType == static_cast<std::uint16_t>(EthernetType::IPv6))
        return "ipv6";
    if (ipv4) {
        if (ipv4->protocol == 6)
            return "tcp";
        if (ipv4->protocol == 17)
            return "udp";
    }
    return "unknown";
}

 std::vector<std::string> PacketFilter::splitValues(const std::string &rawValues)
{
    std::vector<std::string> values;
    std::size_t start = 0;

    while (start <= rawValues.size()) {
        std::size_t slash = rawValues.find('/', start);
        values.push_back(rawValues.substr(start, slash - start));
        if (slash == std::string::npos)
            break;
        start = slash + 1;
    }
    return values;
}

bool PacketFilter::validateValues(const std::string &key, const std::vector<std::string> &values) const
{
    for (const auto &value : values) {
        if (!isValueValidForKey(key, value)) {
            std::cerr << "Invalid value '" << value << "' for filter '" << key << "'" << std::endl;
            return false;
        }
    }
    return true;
}

void PacketFilter::addValues(const std::string &key, const std::vector<std::string> &values)
{
    std::vector<std::string> &ruleValues = filters[key];

    for (const auto &value : values) {
        if (std::find(ruleValues.begin(), ruleValues.end(), value) == ruleValues.end())
            ruleValues.push_back(value);
    }
}

bool PacketFilter::parse(const std::string &expr)
{
    std::size_t eq = expr.find('=');
    if (eq == std::string::npos) {
        std::cerr << "Invalid filter '" << expr
            << "': expected proto=tcp|udp|arp|ipv6|unknown, sport=<port>, dport=<port> or port=<port>"
            " (combine with '/', e.g. proto=tcp/udp)" << std::endl;
        return false;
    }

    std::string key = expr.substr(0, eq);
    std::string rawValues = expr.substr(eq + 1);

    if (!isKnownKey(key)) {
        std::cerr << "Invalid filter key '" << key << "': expected proto, sport, dport or port" << std::endl;
        return false;
    }

    std::vector<std::string> values;

    if (key == "contains") {
        values.push_back(rawValues);
    } else {
        values = splitValues(rawValues);

        if ((key == "minsize" || key == "maxsize") && values.size() > 1) {
            std::cerr << "Invalid filter '" << expr << "': " << key
                << " takes a single value, combining with '/' is not supported" << std::endl;
            return false;
        }
    }

    if (!validateValues(key, values))
        return false;

    addValues(key, values);
    return true;
}

bool PacketFilter::matchesProtocol(const std::string &key, const std::string &value) const
{
    auto it = filters.find(key);
    if (it == filters.end())
        return true;
    return std::find(it->second.begin(), it->second.end(), value) != it->second.end();
}

bool PacketFilter::matchesPort(const std::string &key, std::uint16_t port) const
{
    auto it = filters.find(key);
    if (it == filters.end())
        return true;
    return std::find(it->second.begin(), it->second.end(), std::to_string(port)) != it->second.end();
}

bool PacketFilter::matchesIpv4Address(const std::string &key, const std::string &address) const
{
    auto it = filters.find(key);
    if (it == filters.end())
        return true;
    return std::find(it->second.begin(), it->second.end(), address) != it->second.end();
}

bool PacketFilter::matchesTcpFlags(const std::vector<std::string> &flags, const TcpHeader &tcp) const
{
    for (const auto &flag : flags) {
        if (flag == "NS" && tcp.NS_flag)
            return true;
        if (flag == "CWR" && tcp.CWR_flag)
            return true;
        if (flag == "ECE" && tcp.ECE_flag)
            return true;
        if (flag == "URG" && tcp.URG_flag)
            return true;
        if (flag == "ACK" && tcp.ACK_flag)
            return true;
        if (flag == "PSH" && tcp.PSH_flag)
            return true;
        if (flag == "RST" && tcp.RST_flag)
            return true;
        if (flag == "SYN" && tcp.SYN_flag)
            return true;
        if (flag == "FIN" && tcp.FIN_flag)
            return true;
    }
    return false;
}

bool PacketFilter::matchesSize(const std::string &key, std::size_t packetSize, bool isMinimum) const
{
    auto it = filters.find(key);
    if (it == filters.end())
        return true;

    for (const auto &value : it->second) {
        std::size_t bound = std::stoul(value);
        if (isMinimum && packetSize < bound)
            return false;
        if (!isMinimum && packetSize > bound)
            return false;
    }
    return true;
}

bool PacketFilter::matchesContains(const std::vector<std::uint8_t> &payload) const
{
    auto it = filters.find("contains");
    if (it == filters.end())
        return true;

    std::string payloadText(payload.begin(), payload.end());
    for (const auto &needle : it->second) {
        if (payloadText.find(needle) != std::string::npos)
            return true;
    }
    return false;
}

bool PacketFilter::matches(const EthernetHeader &ethernet, const std::optional<Ipv4Header> &ipv4,
    std::size_t packetSize, const std::optional<TcpHeader> &tcp, const std::optional<UdpHeader> &udp) const
{
    std::string protocol = classifyProtocol(ethernet, ipv4);
    if (!matchesProtocol("proto", protocol))
        return false;

    if (filters.count("sport")) {
        if (!tcp && !udp)
            return false;
        std::uint16_t port = tcp ? tcp->sourcePort : udp->sourcePort;
        if (!matchesPort("sport", port))
            return false;
    }
    if (filters.count("dport")) {
        if (!tcp && !udp)
            return false;
        std::uint16_t port = tcp ? tcp->destinationPort : udp->destinationPort;
        if (!matchesPort("dport", port))
            return false;
    }
    if (filters.count("port")) {
        if (!tcp && !udp)
            return false;
        std::uint16_t sport = tcp ? tcp->sourcePort : udp->sourcePort;
        std::uint16_t dport = tcp ? tcp->destinationPort : udp->destinationPort;
        if (!matchesPort("port", sport) && !matchesPort("port", dport))
            return false;
    }
    if (filters.count("src")) {
        if (!ipv4)
            return false;
        if (!matchesIpv4Address("src", ipv4->sourceAddress))
            return false;
    }
    if (filters.count("dst")) {
        if (!ipv4)
            return false;
        if (!matchesIpv4Address("dst", ipv4->destinationAddress))
            return false;
    }
    if (filters.count("ipv4")) {
        if (!ipv4)
            return false;
        if (!matchesIpv4Address("ipv4", ipv4->sourceAddress) &&
            !matchesIpv4Address("ipv4", ipv4->destinationAddress))
            return false;
    }
    if (filters.count("tcpflags")) {
        if (!tcp)
            return false;
        const std::vector<std::string> &flags = filters.at("tcpflags");
        if (!matchesTcpFlags(flags, *tcp))
            return false;
    }
    if (!matchesSize("minsize", packetSize, true))
        return false;
    if (!matchesSize("maxsize", packetSize, false))
        return false;

    if (filters.count("contains")) {
        const std::vector<std::uint8_t> *payload = nullptr;
        if (tcp)
            payload = &tcp->payload;
        else if (udp)
            payload = &udp->payload;
        if (!payload)
            return false;
        if (!matchesContains(*payload))
            return false;
    }

    return true;
}
