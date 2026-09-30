/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** TerminalInput
*/

#ifndef TERMINALINPUT_HPP_
#define TERMINALINPUT_HPP_

#include <termios.h>

namespace sniffer {

class TerminalInput {
    public:
        TerminalInput();
        ~TerminalInput();

        int pollKey();

    private:
        struct termios original {};
        bool enabled = false;
};

}

#endif /* !TERMINALINPUT_HPP_ */
