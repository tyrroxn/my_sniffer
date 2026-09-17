/*
** EPITECH PROJECT, 2026
** my_sniffer
** File description:
** TerminalInput
*/

#include "TerminalInput.hpp"

#include <poll.h>
#include <unistd.h>

using namespace sniffer;

TerminalInput::TerminalInput()
{
    if (!isatty(STDIN_FILENO))
        return;
    if (tcgetattr(STDIN_FILENO, &original) != 0)
        return;

    struct termios raw = original;

    raw.c_lflag &= static_cast<unsigned int>(~(ICANON | ECHO)); // desactive l'affichage et le mode entrer
    // empeche le read de bloqué sur mac
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0)
        return;

    enabled = true;
}

TerminalInput::~TerminalInput()
{
    if (enabled)
        tcsetattr(STDIN_FILENO, TCSANOW, &original);
}

int TerminalInput::pollKey()
{
    if (!enabled)
        return -1;

    struct pollfd pfd = {STDIN_FILENO, POLLIN, 0};
    int ready = poll(&pfd, 1, 0);
    unsigned char key;

    if (ready <= 0 || !(pfd.revents & POLLIN))
        return -1;

    if (read(STDIN_FILENO, &key, 1) != 1)
        return -1;
    return key;
}
