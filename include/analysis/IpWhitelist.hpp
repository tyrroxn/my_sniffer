/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** IpWhitelist
*/

#ifndef IPWHITELIST_HPP_
#define IPWHITELIST_HPP_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <array>

namespace analyser {

struct IpRange {
    std::uint32_t network = 0;
    std::uint32_t mask = 0;

    bool contains(std::uint32_t ip) const { return (ip & mask) == network; }
};

static const std::array<IpRange, 3> lanRanges = {{
    {0x0A000000, 0xFF000000},
    {0xAC100000, 0xFFF00000},
    {0xC0A80000, 0xFFFF0000},
}};

class IpWhitelist {
    public:
        bool load(const std::string &path, std::string &error);
        bool addEntry(const std::string &entry);
        bool contains(const std::string &ip) const;
        std::size_t size() const { return ranges.size(); }

        static std::optional<std::uint32_t> parseIpv4(const std::string &text);
        static std::optional<IpRange> parseRange(const std::string &text);
        static bool isLan(const std::string &ip);

    private:
        std::vector<IpRange> ranges;
};

}

#endif /* !IPWHITELIST_HPP_ */
