/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** EternetParser
*/

#ifndef ETERNETPARSER_HPP_
#define ETERNETPARSER_HPP_

#include "Packet.hpp"

namespace sniffer {

class EternetParser {
    public:
        EternetParser() = default;
        ~EternetParser() = default;

        static bool parse(const std::vector<std::uint8_t> &buffer,
            EthernetHeader &header);

    protected:
    private:
};

}

#endif /* !ETERNETPARSER_HPP_ */
