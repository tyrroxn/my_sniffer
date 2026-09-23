/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** SignalHandler
*/

#ifndef SIGNALHANDLER_HPP_
#define SIGNALHANDLER_HPP_

#include <csignal>

namespace sniffer {

class SignalHandler {
    public:
        static void install();
        static bool running();

    private:
        static volatile std::sig_atomic_t running_;
        static void handle(int signum);
};

}

#endif /* !SIGNALHANDLER_HPP_ */
