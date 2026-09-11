/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** EternetParser
*/

#ifndef ETHERNETPARSER_HPP_
#define ETHERNETPARSER_HPP_

#include "Packet.hpp"

namespace sniffer {

class EthernetParser {
    public:
        EthernetParser() = default;
        ~EthernetParser() = default;

        static bool parse(const std::vector<std::uint8_t> &buffer,
            EthernetHeader &header);

    protected:
    private:
};

}

#endif /* !ETERNETPARSER_HPP_ */
