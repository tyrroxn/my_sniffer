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

static const char *VALID_PROTOCOLS[] = {"tcp", "udp", "arp", "ipv6", "unknown"};

static bool isValidProtocol(const std::string &value)
{
    for (const char *proto : VALID_PROTOCOLS) {
        if (value == proto)
            return true;
    }
    return false;
}

static bool isKnownKey(const std::string &key)
{
    return key == "proto" || key == "sport" || key == "dport" || key == "port";
}

static bool isValidPort(const std::string &value)
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

static bool isValueValidForKey(const std::string &key, const std::string &value)
{
    if (key == "proto")
        return isValidProtocol(value);
    if (key == "sport" || key == "dport" || key == "port")
        return isValidPort(value);
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

static std::vector<std::string> splitOrValues(const std::string &rawValues)
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

static bool validateValues(const std::string &key, const std::vector<std::string> &values)
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

    std::vector<std::string> values = splitOrValues(rawValues);
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

bool PacketFilter::matches(const EthernetHeader &ethernet, const std::optional<Ipv4Header> &ipv4,
    const std::optional<TcpHeader> &tcp, const std::optional<UdpHeader> &udp) const
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

    return true;
}
