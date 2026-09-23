/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** CaptureNetwork
*/

#ifndef CAPTURENETWORK_HPP_
#define CAPTURENETWORK_HPP_
#include "utils/Packet.hpp"

namespace sniffer {

class CaptureNetwork {
    public:
        CaptureNetwork() = default;
        virtual ~CaptureNetwork() = default;
        virtual void start() = 0;
        virtual void stop() = 0;
        virtual bool receive(RawPacket &packet) = 0;
    private:
};

}
#endif /* !CAPTURENETWORK_HPP_ */
