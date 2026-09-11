/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** MacCapture
*/

#ifndef MACCAPTURE_HPP_
#define MACCAPTURE_HPP_
#include "CaptureNetwork.hpp"
#include "Packet.hpp"

namespace sniffer {

class MacCapture: public CaptureNetwork {
    public:
        MacCapture() = default;
        ~MacCapture() = default;
        void start() override;
        void stop() override;
        bool capture(RawPacket &packet) override;
        int getSocketFd() const { return socketFd; }

    private:
        int socketFd = -1;
        std::vector<unsigned char> buffer;
        std::size_t bufferLen = 0;
        std::size_t pos = 0;
        std::size_t validLen = 0;
};

}
#endif /* !MACCAPTURE_HPP_ */
