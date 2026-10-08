#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

SUDO="sudo"
if [[ $EUID -eq 0 ]]; then
    SUDO=""
fi

if command -v apt-get >/dev/null; then
    if ! dpkg -s build-essential cmake pkg-config libcap2-bin >/dev/null 2>&1; then
        $SUDO apt-get update
        $SUDO apt-get install -y build-essential cmake pkg-config libcap2-bin
    fi
    pkg-config --exists criterion || $SUDO apt-get install -y libcriterion-dev gcovr || true
elif command -v dnf >/dev/null; then
    rpm -q gcc-c++ make cmake pkgconf-pkg-config libcap >/dev/null 2>&1 \
        || $SUDO dnf install -y gcc-c++ make cmake pkgconf-pkg-config libcap
    pkg-config --exists criterion || $SUDO dnf install -y criterion-devel gcovr || true
elif command -v pacman >/dev/null; then
    pacman -Qi base-devel cmake pkgconf libcap >/dev/null 2>&1 \
        || $SUDO pacman -S --needed --noconfirm base-devel cmake pkgconf libcap
    pkg-config --exists criterion || $SUDO pacman -S --needed --noconfirm criterion gcovr || true
else
    echo "No supported package manager (apt, dnf, pacman): install a C++20 compiler, cmake and libcap yourself" >&2
fi

cmake -S . -B build
cmake --build build

scripts/linux-capture-access.sh build/my_sniffer
