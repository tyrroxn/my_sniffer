/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** PacketDisplay
*/

#ifndef PACKETDISPLAY_HPP_
#define PACKETDISPLAY_HPP_

#include "Packet.hpp"
#include <optional>

namespace sniffer {

class PacketDisplay {
    public:
        enum class Mode {
            Minimum,
            Detailed,
        };

        PacketDisplay() = default;
        ~PacketDisplay() = default;

        void setMode(Mode mod) { mode = mod; return; }
        void toggleMode() { mode = (mode == Mode::Minimum) ? Mode::Detailed : Mode::Minimum; return; }
        Mode getMode() const { return mode; }
        void togglePause() { paused = !paused; return; }
        bool getPaused() const { return paused; }

        void show(const RawPacket &packet, const EthernetHeader &ethernet, const std::optional<Ipv4Header> &ipv4 = std::nullopt,
            const std::optional<TcpHeader> &tcp = std::nullopt, const std::optional<UdpHeader> &udp = std::nullopt);
        void displayStats(std::size_t captured, std::size_t filtered, std::size_t errors) const;

    private:
        Mode mode = Mode::Minimum;
        bool paused = false;

        static std::string formatTimestamp(const std::chrono::system_clock::time_point &tp);

        void showMinimum(const RawPacket &packet, const EthernetHeader &ethernet, const std::optional<Ipv4Header> &ipv4,
            const std::optional<TcpHeader> &tcp, const std::optional<UdpHeader> &udp) const;
        void showDetailed(const RawPacket &packet, const EthernetHeader &ethernet, const std::optional<Ipv4Header> &ipv4,
            const std::optional<TcpHeader> &tcp, const std::optional<UdpHeader> &udp) const;
};

}

#endif /* !PACKETDISPLAY_HPP_ */
