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

        if (errno == ENOENT)
            break;

        if (errno == EACCES || errno == EPERM) {
            std::cerr << "Permission denied while opening " << path
                      << ". Run the program with sudo." << std::endl;
            break;
        }
    }

    if (socketFd < 0) {
        perror("open(/dev/bpf*)");
        if (errno == EACCES || errno == EPERM)
            std::cerr << "Insufficient privileges: run with sudo, or add "
                "this user to the BPF access group with "
                "'sudo dseditgroup -o edit -a $(whoami) -t user access_bpf'."
                << std::endl;
        else if (errno == EBUSY)
            std::cerr << "All BPF devices are in use by another process "
                "(e.g. Wireshark, tcpdump). Close it and retry." << std::endl;
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

bool MacCapture::fillBuffer()
{
    ssize_t bytesRead = read(socketFd, buffer.data(), buffer.size());

    while (bytesRead < 0 && errno == EINTR)
        bytesRead = read(socketFd, buffer.data(), buffer.size());

    if (bytesRead < 0) {
        perror("read(bpf)");
        return false;
    }
    if (bytesRead == 0) {
        std::cerr << "read(bpf): unexpected EOF on capture device" << std::endl;
        return false;
    }

    validLen = static_cast<std::size_t>(bytesRead);
    pos = 0;
    return true;
}

bool MacCapture::extractRecord(RawPacket &packet)
{
    // Check si assez de place pour contenir Header BPF complet.
    if (validLen - pos < sizeof(struct bpf_hdr)) {
        std::cerr << "MacCapture: truncated BPF record, dropping remainder of buffer" << std::endl;
        validLen = 0;
        pos = 0;
        return false;
    }

    const auto *header =
        reinterpret_cast<const struct bpf_hdr *>(buffer.data() + pos);
    const std::size_t headerLength = header->bh_hdrlen;
    const std::size_t capturedLength = header->bh_caplen;
    const std::size_t minimumHeaderLength = offsetof(struct bpf_hdr, bh_hdrlen) + sizeof(header->bh_hdrlen);

    // Check si on reste dans le buffer
    if (headerLength < minimumHeaderLength ||
        headerLength > validLen - pos ||
        capturedLength > validLen - pos - headerLength) {
        std::cerr << "MacCapture: invalid BPF packet header, dropping remainder of buffer" << std::endl;
        validLen = 0;
        pos = 0;
        return false;
    }

    packet.buffer.assign(
        buffer.begin() + pos + headerLength,
        buffer.begin() + pos + headerLength + capturedLength);
    packet.timestamp = std::chrono::system_clock::now();

    const std::size_t recordLength = BPF_WORDALIGN(headerLength + capturedLength);

    if (recordLength > validLen - pos) {
        validLen = 0;
        pos = 0;
    } else
        pos += recordLength;

    return true;
}

bool MacCapture::receive(RawPacket &packet)
{
    if (socketFd < 0) {
        std::cerr << "MacCapture: device not open" << std::endl;
        return false;
    }

    if (pos >= validLen && !fillBuffer())
        return false;

    return extractRecord(packet);
}
