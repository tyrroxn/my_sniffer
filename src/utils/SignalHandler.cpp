/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** SignalHandler
*/
#include "utils/SignalHandler.hpp"
#include <cstring>
using namespace sniffer;

volatile std::sig_atomic_t SignalHandler::running_ = 1;

void SignalHandler::install()
{
    struct sigaction sa;

    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    return;
}

bool SignalHandler::running()
{
    return running_ != 0;
}

void SignalHandler::handle(int)
{
    running_ = 0;
    return;
}
