#!/usr/bin/env bash

set -euo pipefail

sudo chown "$(id -un)" /dev/bpf*
