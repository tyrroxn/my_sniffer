/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Ipv4Parser
*/

#ifndef IPV4PARSER_HPP_
#define IPV4PARSER_HPP_

#include "Packet.hpp"

namespace sniffer {
static constexpr std::size_t IPV4_MIN_HEADER_LEN = 20;
static constexpr std::uint8_t IPV4_MIN_IHL = 5;

class Ipv4Parser {
    public:
        Ipv4Parser() = default;
        ~Ipv4Parser() = default;

        static bool parse(const std::vector<std::uint8_t> &buffer,
            Ipv4Header &header);

    protected:
    private:
        static bool checkSum(const unsigned char *data, std::size_t headerLength);
};

}

#endif /* !IPV4PARSER_HPP_ */
