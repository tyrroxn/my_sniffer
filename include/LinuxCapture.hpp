/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** LinuxCapture
*/

#ifndef LINUXCAPTURE_HPP_
#define LINUXCAPTURE_HPP_
#include "CaptureNetwork.hpp"
#include "Helper.hpp"
#include "Packet.hpp"
#include <sys/socket.h>

namespace sniffer {

class LinuxCapture : public CaptureNetwork {
    public:
        LinuxCapture() = default;
        ~LinuxCapture() = default;
        void start() override;
        void stop() override;
        bool receive(RawPacket &packet) override;
        int getSocketFd() const { return socketFd; }
    private:
        int socketFd;
};

}
#endif /* !LINUXCAPTURE_HPP_ */
