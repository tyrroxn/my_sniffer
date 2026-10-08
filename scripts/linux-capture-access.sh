#!/usr/bin/env bash

set -euo pipefail

sudo setcap cap_net_raw+ep "${1:-$(dirname "${BASH_SOURCE[0]}")/../build/my_sniffer}"
