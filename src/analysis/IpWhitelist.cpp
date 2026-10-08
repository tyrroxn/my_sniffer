/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** IpWhitelist
*/

#include "analysis/IpWhitelist.hpp"
#include <charconv>
#include <fstream>

namespace analyser {



static std::string trim(const std::string &text)
{
    std::size_t start = text.find_first_not_of(" \t\r");
    std::size_t end = text.find_last_not_of(" \t\r");

    if (start == std::string::npos)
        return "";
    return text.substr(start, end - start + 1);
}

std::optional<std::uint32_t> IpWhitelist::parseIpv4(const std::string &text)
{
    std::uint32_t ip = 0;
    std::size_t start = 0;

    for (int i = 0; i < 4; i++) {
        std::size_t dot = text.find('.', start); 

        if ((i < 3) != (dot != std::string::npos))
            return std::nullopt;
        
        std::size_t end = dot == std::string::npos ? text.size() : dot;
        unsigned int byte = 0;
        auto [byteEnd, byteError] = std::from_chars(text.data() + start, text.data() + end, byte);

        if (byteError != std::errc() || byteEnd != text.data() + end || end - start > 3 || byte > 255)
            return std::nullopt;
        ip = (ip << 8) | byte;
        start = end + 1;
    }
    return ip;
}

std::optional<IpRange> IpWhitelist::parseRange(const std::string &text)
{
    std::size_t slash = text.find('/');
    std::optional<std::uint32_t> ip = parseIpv4(text.substr(0, slash));
    unsigned int prefix = 32;

    if (!ip)
        return std::nullopt;

    if (slash != std::string::npos) {
        const char *begin = text.data() + slash + 1;
        const char *end = text.data() + text.size();
        auto [prefixEnd, prefixError] = std::from_chars(begin, end, prefix);

        if (begin == end || prefixError != std::errc() || prefixEnd != end || prefix > 32)
            return std::nullopt;
    }
    std::uint32_t mask = 0;

    if (prefix != 0)
        mask = 0xFFFFFFFFu << (32 - prefix);
    return IpRange{*ip & mask, mask};
}

bool IpWhitelist::isLan(const std::string &ip)
{
    std::optional<std::uint32_t> address = parseIpv4(ip);

    if (!address)
        return false;
    for (const IpRange &range : lanRanges)
        if (range.contains(*address))
            return true;
    return false;
}

bool IpWhitelist::addEntry(const std::string &entry)
{
    std::optional<IpRange> range = parseRange(entry);

    if (!range)
        return false;
    ranges.push_back(*range);
    return true;
}

bool IpWhitelist::load(const std::string &path, std::string &error)
{
    std::ifstream file(path);
    std::string line;
    std::size_t lineNumber = 0;

    if (!file) {
        error = "cannot open whitelist file: " + path;
        return false;
    }
    while (std::getline(file, line)) {
        lineNumber++;
        std::string entry = trim(line.substr(0, line.find('#')));
        if (entry.empty())
            continue;
        if (!addEntry(entry)) {
            error = path + ": line " + std::to_string(lineNumber) + ": invalid entry '" + entry
                + "' (expected an IPv4 address or a range like 192.168.1.0/24)";
            return false;
        }
    }
    return true;
}

bool IpWhitelist::contains(const std::string &ip) const
{
    std::optional<std::uint32_t> address = parseIpv4(ip);

    if (!address)
        return false;
    for (const IpRange &range : ranges)
        if (range.contains(*address))
            return true;
    return false;
}

}
