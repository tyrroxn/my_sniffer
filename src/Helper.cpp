/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Helper
*/

#include "Helper.hpp"




namespace sniffer {
bool Helper::bynaryIPV4ToString(const unsigned char *ip, std::string &output)
{
  if (!ip)
    return false;
  output = std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
    std::to_string(ip[2]) + "." + std::to_string(ip[3]);
  return true;
}

bool Helper::bynaryMACToString(const unsigned char *mac, std::string &output)
{
  char buf[18];
  if (!mac)
    return false;
  snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  output = buf;
  return true;
}

bool Helper::stringToBinaryIPV4(const std::string &text, unsigned char *ip)
{
  if (text.empty())
    return false;

  return sscanf(text.c_str(), "%hhu.%hhu.%hhu.%hhu",
    &ip[0], &ip[1], &ip[2], &ip[3]) == 4;
}

bool Helper::stringToBinaryMAC(const std::string &text, unsigned char *mac)
{
  if (text.empty())
    return false;

  return sscanf(text.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

std::uint16_t Helper::hostToNetwork16(std::uint16_t value)
{
  if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) {
    return (value << 8) | (value >> 8);
  } else {
    return value;
  }
}

std::uint16_t Helper::networkToHost16(std::uint16_t value)
{
  return hostToNetwork16(value);
}

std::uint32_t Helper::hostToNetwork32(std::uint32_t value)
{
  if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) {
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8) |
           ((value & 0x00FF0000) >> 8) |
           ((value & 0xFF000000) >> 24);
  } else {
    return value;
  }
}

std::uint32_t Helper::networkToHost32(std::uint32_t value)
{
  return hostToNetwork32(value);
}

bool Helper::readUint16(const unsigned char *buffer, std::size_t size,
  std::size_t offset, std::uint16_t &value, bool networkOrder)
{
  if (!buffer || offset + sizeof(std::uint16_t) > size)
    return false;
  
  memcpy(&value, buffer + offset, sizeof(std::uint16_t));
  if (networkOrder)
    value = networkToHost16(value);
  return true;

}

bool Helper::readUint32(const unsigned char *buffer, std::size_t size,
  std::size_t offset, std::uint32_t &value, bool networkOrder)
{
  if (!buffer || offset + sizeof(std::uint32_t) > size)
    return false;
  
  memcpy(&value, buffer + offset, sizeof(std::uint32_t));
  if (networkOrder)
    value = networkToHost32(value);
  return true;
}

std::string Helper::hexdump(const unsigned char *buffer, std::size_t size)
{
  std::string output;
  char buf[3];
  for (std::size_t i = 0; i < size; i++) {
    snprintf(buf, sizeof(buf), "%02x", buffer[i]);
    output += buf;
    if (i < size - 1)
      output += " ";
  }
  return output;
}

std::string Helper::rawBufferToString(const unsigned char *buffer, std::size_t size)
{
  std::string output;
  for (std::size_t i = 0; i < size; i++) {
    output += static_cast<char>(buffer[i]);
  }
  return output;
}


}