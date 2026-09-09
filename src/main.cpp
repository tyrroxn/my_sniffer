/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** main
*/
#include "Helper.hpp"
#include "Server.hpp"
#include "SignalHandler.hpp"
using namespace sniffer;

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    SignalHandler::install();
    Server server;
    std::size_t packetCount = 0;

    while (SignalHandler::running()) {
        RawPacket packet;
        if (!server.getPacket(packet)) {
            if (!SignalHandler::running())
                break;
            std::cerr << "Failed to get packet" << std::endl;
            continue;
        }
        packetCount++;
    }

    std::cout << "\nCapture stopped, " << packetCount
              << " packet(s) captured." << std::endl;
    return 0;
}
