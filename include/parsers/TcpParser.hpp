/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** TcpParser
*/

#ifndef TCPPARSER_HPP_
#define TCPPARSER_HPP_

#include "utils/Packet.hpp"

namespace sniffer {
class TcpParser {
    public:
        TcpParser() = default;
        ~TcpParser() = default;
        static bool parse(const std::vector<std::uint8_t> &buffer,
            TcpHeader &header);
        static std::string flagsLabel(const TcpHeader &header);

    protected:
    private:
};

}
#endif /* !TCPPARSER_HPP_ */
