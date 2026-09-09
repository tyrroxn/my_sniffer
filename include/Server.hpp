/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** Server
*/

#pragma once

#ifdef _WIN32
    #include <winsock2.h>
    #ifndef WIN32_LEAN_AND_MEAN
    #  define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
    #  define NOMINMAX
    #endif
    #include <windows.h>
    #ifdef ERROR
    #  undef ERROR
    #endif
#else
    #include <sys/socket.h>
    #include <unistd.h>
#endif

#include <string>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>

namespace sniffer {
namespace server {

class Commands;

class Server {
    public:
        Server(int port);
        ~Server();
    private:
};

}
}
