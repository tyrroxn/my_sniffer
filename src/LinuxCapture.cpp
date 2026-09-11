/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** LinuxCapture
*/

#include "LinuxCapture.hpp"
using namespace sniffer;


void LinuxCapture::start()
{
    socketFd = socket(AF_PACKET, SOCK_RAW, Helper::hostToNetwork16(0x0003));
    if (socketFd < 0) {
        perror("socket");
        std::cerr << "Use sudo setcap cap_net_raw+ep ./my_sniffer to allow raw socket usage without root privileges." << std::endl;
        exit(1);
    }
}

void LinuxCapture::stop()
{
    if (socketFd >= 0)
        close(socketFd);
}

bool LinuxCapture::receive(RawPacket &packet)
{

    uint8_t buffer[65536];
    ssize_t size = recvfrom(socketFd, buffer, sizeof(buffer), 0,
        nullptr,
        nullptr
    );

    if (size < 0) {
        if (errno != EINTR)
            perror("recvfrom");
        return false;
    }

    packet.buffer.assign(buffer, buffer + size);
    packet.timestamp = std::chrono::system_clock::now();
    return true;
}
