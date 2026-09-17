/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Helper
*/

#ifndef HELPER_HPP_
#define HELPER_HPP_

#include <cstddef>
#include <cstdint>
#include <string>
#include <cstdio>
#include <cstring>

namespace sniffer {
class Helper {
    public:
        Helper() = default;
        ~Helper() = default;
        
        static bool bynaryIPV4ToString(const unsigned char *ip, std::string &output);
        static bool bynaryMACToString(const unsigned char *mac, std::string &output);

        static bool stringToBinaryIPV4(const std::string &text,
        unsigned char *ip);
        static bool stringToBinaryMAC(const std::string &text,
        unsigned char *mac);

        static std::uint16_t hostToNetwork16(std::uint16_t value);
        static std::uint16_t networkToHost16(std::uint16_t value);
        static std::uint32_t hostToNetwork32(std::uint32_t value);
        static std::uint32_t networkToHost32(std::uint32_t value);

        static bool readUint16(const unsigned char *buffer, std::size_t size,
        std::size_t offset, std::uint16_t &value, bool networkOrder = true);
        static bool readUint32(const unsigned char *buffer, std::size_t size,
        std::size_t offset, std::uint32_t &value, bool networkOrder = true);

        static std::string hexdump(const unsigned char *buffer, std::size_t size);
        static std::string rawBufferToString(const unsigned char *buffer,
        std::size_t size);


    private:
};

}

#endif /* !HELPER_HPP_ */
