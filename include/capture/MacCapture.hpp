/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** MacCapture
*/

#ifndef MACCAPTURE_HPP_
#define MACCAPTURE_HPP_
#include "capture/CaptureNetwork.hpp"
#include "utils/Packet.hpp"

namespace sniffer {

class MacCapture: public CaptureNetwork {
    public:
        MacCapture() = default;
        ~MacCapture() = default;
        void start() override;
        void stop() override;
        bool receive(RawPacket &packet) override;
        int getSocketFd() const { return socketFd; }

    private:
        int socketFd = -1;
        std::vector<unsigned char> buffer;
        std::size_t bufferLen = 0;
        std::size_t pos = 0;
        std::size_t validLen = 0;

        bool fillBuffer();
        bool extractRecord(RawPacket &packet);
};

}
#endif /* !MACCAPTURE_HPP_ */
