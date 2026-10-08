#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v brew >/dev/null || { echo "Homebrew is required: https://brew.sh" >&2; exit 1; }

brew install cmake pkg-config
brew install criterion gcovr || true

cmake -S . -B build -DCMAKE_PREFIX_PATH="$(brew --prefix)"
cmake --build build
