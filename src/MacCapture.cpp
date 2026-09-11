/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** MacCapture
*/

#include "MacCapture.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

using namespace sniffer;


static const char *DEFAULT_INTERFACE = "en0";

void MacCapture::start()
{
    char path[16];
    struct ifreq ifr;
    unsigned int enable = 1;
    unsigned int len = 0;

    for (int i = 0; i < 256; i++) {
        std::snprintf(path, sizeof(path), "/dev/bpf%d", i);
        socketFd = open(path, O_RDWR);
        if (socketFd >= 0)
            break;
    }

    if (socketFd < 0) {
        perror("open(/dev/bpf*)");
        if (errno == EACCES || errno == EPERM)
            std::cerr << "Insufficient privileges: run with sudo, or add "
                "this user to the BPF access group with "
                "'sudo dseditgroup -o edit -a $(whoami) -t user access_bpf'."
                << std::endl;
        exit(1);
    }

    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, DEFAULT_INTERFACE, sizeof(ifr.ifr_name) - 1);

    if (ioctl(socketFd, BIOCSETIF, &ifr) < 0) {
        perror("ioctl(BIOCSETIF)");
        std::cerr << "Could not bind to interface \"" << DEFAULT_INTERFACE
            << "\", edit DEFAULT_INTERFACE in MacCapture.cpp if yours is named "
            "differently." << std::endl;
        stop();
        exit(1);
    }

    if (ioctl(socketFd, BIOCIMMEDIATE, &enable) < 0) {
        perror("ioctl(BIOCIMMEDIATE)");
        stop();
        exit(1);
    }

    if (ioctl(socketFd, BIOCGBLEN, &len) < 0) {
        perror("ioctl(BIOCGBLEN)");
        stop();
        exit(1);
    }

    bufferLen = len;
    buffer.resize(bufferLen);
}

void MacCapture::stop()
{
    if (socketFd >= 0) {
        close(socketFd);
        socketFd = -1;
    }
    validLen = 0;
    pos = 0;
}

bool MacCapture::capture(RawPacket &packet)
{
    if (pos >= validLen) {
        const ssize_t bytesRead = read(socketFd, buffer.data(), buffer.size());

        if (bytesRead <= 0) {
            if (bytesRead < 0 && errno != EINTR)
                perror("read(bpf)");
            return false;
        }
        validLen = static_cast<std::size_t>(bytesRead);
        pos = 0;
    }

    const auto *header = reinterpret_cast<const struct bpf_hdr *>(buffer.data() + pos);
    const std::size_t headerLength = header->bh_hdrlen;
    const std::size_t capturedLength = header->bh_caplen;

    if (headerLength < sizeof(struct bpf_hdr) ||
        pos + headerLength > validLen ||
        capturedLength > validLen - pos - headerLength) {
        validLen = 0;
        pos = 0;
        return false;
    }

    packet.buffer.assign(buffer.begin() + pos + headerLength,
        buffer.begin() + pos + headerLength + capturedLength);
    packet.timestamp = std::chrono::system_clock::now();

    pos += BPF_WORDALIGN(headerLength + capturedLength);
    return true;
}
