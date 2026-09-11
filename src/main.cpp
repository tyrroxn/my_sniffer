/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** main
*/
#include "CaptureNetwork.hpp"
#include "SignalHandler.hpp"
#include "EthernetParser.hpp"
#include <memory>

#if defined(__APPLE__)
    #include "MacCapture.hpp"
#elif defined(__linux__)
    #include "LinuxCapture.hpp"
#else
    #error "No capture backend implemented for this platform"
#endif

using namespace sniffer;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    SignalHandler::install();

#if defined(__APPLE__)
    std::unique_ptr<CaptureNetwork> capture = std::make_unique<MacCapture>();
#elif defined(__linux__)
    std::unique_ptr<CaptureNetwork> capture = std::make_unique<LinuxCapture>();
#endif

    capture->start();
    std::size_t packetCount = 0;

    while (SignalHandler::running()) {
        RawPacket packet;
        if (!capture->receive(packet)) {
            if (!SignalHandler::running())
                break;
            std::cerr << "Failed to get packet" << std::endl;
            continue;
        }
        packetCount++;
    }

    capture->stop();
    std::cout << "\nCapture stopped, " << packetCount
              << " packet(s) captured." << std::endl;
    return 0;
}
