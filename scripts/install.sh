#!/usr/bin/env bash

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -s)" in
    Linux)  exec "$SCRIPTS_DIR/install-linux.sh" ;;
    Darwin) exec "$SCRIPTS_DIR/install-macos.sh" ;;
    *)
        echo "Unsupported platform '$(uname -s)': my_sniffer runs on Linux and macOS" >&2
        exit 1
        ;;
esac
