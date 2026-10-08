# my_sniffer

A network packet sniffer for Linux and macOS, with an offline log analyser.

- **`my_sniffer`** captures packets, decodes Ethernet / IPv4 / TCP / UDP, shows them live, filters them and logs them.
- **`analyse_log`** reads a `my_sniffer` log and reports suspicious traffic: traffic spikes, beaconing, unknown IPs, wrong protocol on a standard port.

## Contents

- [Supported platforms](#supported-platforms)
- [Quick start](#quick-start)
- [Scripts](#scripts)
- [Requirements](#requirements)
- [Build by hand](#build-by-hand)
- [Install](#install)
- [Privileges needed to capture](#privileges-needed-to-capture)
- [Run](#run)
- [Configuration](#configuration)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)

## Supported platforms

| Platform | Capture backend | Interfaces captured |
|---|---|---|
| Linux | `AF_PACKET` raw socket | all of them |
| macOS | BPF device (`/dev/bpf*`) | `en0` only (see [macOS](#macos)) |

`analyse_log` only reads files: it needs no privilege on either platform.
CMake refuses to configure the project on any other platform.

## Quick start

One command installs the dependencies and builds everything:

```sh
git clone https://github.com/tyrroxn/my_sniffer.git
cd my_sniffer
scripts/install.sh
```

Then, from the project directory:

```sh
build/my_sniffer --log capture.log          # capture (sudo build/my_sniffer on macOS)
build/analyse_log capture_<date>.log        # analyse the log
```

Nothing is copied outside the project. To gather the programs in one directory, see [Install](#install).

## Scripts

The scripts take no option, except the optional path of `linux-capture-access.sh`.

| Script | What it does |
|---|---|
| `scripts/install.sh` | Runs `install-linux.sh` or `install-macos.sh` depending on the platform |
| `scripts/install-linux.sh` | Installs the missing dependencies, builds in `build/`, then runs `linux-capture-access.sh` |
| `scripts/install-macos.sh` | Installs the dependencies with Homebrew, then builds in `build/` |
| `scripts/linux-capture-access.sh [binary]` | Lets `my_sniffer` capture without `sudo` on Linux |
| `scripts/macos-capture-access.sh` | Lets your user capture without `sudo` on macOS |

What the install script does on each platform:

| Step | Linux | macOS |
|---|---|---|
| Compiler, CMake, pkg-config | apt, dnf or pacman, only if something is missing | `brew install cmake pkg-config` |
| Criterion and gcovr (unit tests) | installed if Criterion is not found | `brew install criterion gcovr` |
| Build `my_sniffer`, `analyse_log` and `unit_tests` in `build/` | yes | yes |
| Capture without `sudo` | yes: `scripts/linux-capture-access.sh build/my_sniffer` | no: see [macOS](#macos) |

- **Linux:** `sudo` asks for your password when packages are missing, and once at the end for the capture rights.
- **macOS:** Homebrew and the Xcode Command Line Tools must already be installed. Run the script as your normal user, not with `sudo`: Homebrew refuses to run as root.
- **Criterion** is optional: if it cannot be installed, everything else is built and only the unit tests are skipped.

## Requirements

| | Linux | macOS |
|---|---|---|
| Compiler | C++20 (GCC or Clang) | Xcode Command Line Tools (`xcode-select --install`) |
| Build system | CMake 3.16 or newer | CMake 3.16 or newer |
| Package manager | apt, dnf or pacman | [Homebrew](https://brew.sh) |
| Library | spdlog: downloaded and built by CMake if it is not installed | same |
| Capture rights | `setcap` (libcap) | none |
| Unit tests (optional) | Criterion, gcovr for coverage | Criterion, gcovr for coverage |

The install scripts install these for you. To do it by hand:

```sh
# Debian, Ubuntu, Kali
sudo apt-get install build-essential cmake pkg-config libcap2-bin libcriterion-dev gcovr

# Fedora
sudo dnf install gcc-c++ make cmake pkgconf-pkg-config libcap

# Arch
sudo pacman -S --needed base-devel cmake pkgconf libcap

# macOS (Homebrew)
brew install cmake pkg-config criterion gcovr
```

On Fedora and Arch, Criterion may not be in the official repositories: build it from [its sources](https://github.com/Snaipe/Criterion) if you want the unit tests.

## Build by hand

```sh
cmake -S . -B build
cmake --build build
```

This produces `build/my_sniffer`, `build/analyse_log` and, when Criterion is found, `build/unit_tests`.

- **spdlog:** the first command looks for spdlog on the system. If it is not installed, CMake downloads spdlog 1.15.3 from GitHub and builds it with the project. This needs an internet connection the first time, and `my_sniffer` then contains spdlog instead of depending on the system library.
- **Apple Silicon:** add `-DCMAKE_PREFIX_PATH="$(brew --prefix)"` to the first command so CMake finds what Homebrew installed. `scripts/install-macos.sh` does it.
- **Build type:** none is set by default, so the binaries are not optimised. Add `-DCMAKE_BUILD_TYPE=Release` to the first command for an optimised build, or `-DCMAKE_BUILD_TYPE=Debug` for a debug build.
- **Warnings:** the sources are compiled with `-Wall -Wextra -Werror`, so a compiler warning stops the build.

| CMake target | Command | Effect |
|---|---|---|
| (default) | `cmake --build build` | builds everything |
| `re` | `cmake --build build --target re` | cleans, then rebuilds `my_sniffer` |
| `run_tests` | `cmake --build build --target run_tests` | builds and runs the unit tests |
| `coverage` | `cmake --build build --target coverage` | runs the unit tests and writes a coverage report |
| install | `cmake --install build` | see [Install](#install) |

## Install

After a build, the CMake install target copies what is needed to run the tools into one directory:

```sh
cmake --install build                       # into release/ at the root of the project
cmake --install build --prefix /usr/local   # or into the directory of your choice (sudo if needed)
```

| Installed file | Purpose |
|---|---|
| `<prefix>/bin/my_sniffer` | the sniffer |
| `<prefix>/bin/analyse_log` | the log analyser |
| `<prefix>/etc/my_sniffer/whitelist.conf` | example whitelist for `analyse_log -w` |

- **Destination:** `<prefix>` is `release` unless `--prefix` is given. The `release/` directory is ignored by git.
- **Choosing the directory:** only `--prefix` works. `-DCMAKE_INSTALL_PREFIX` at configuration time is ignored.
- **Capture rights:** the installed `my_sniffer` is a copy, so it has none yet. On Linux, grant them with `scripts/linux-capture-access.sh release/bin/my_sniffer`.

```sh
release/bin/my_sniffer --log capture.log
release/bin/analyse_log -w release/etc/my_sniffer/whitelist.conf capture_<date>.log
```

## Privileges needed to capture

Reading raw packets is a privileged operation on both platforms. Only `my_sniffer` is concerned.

### Linux

`my_sniffer` opens an `AF_PACKET` raw socket, which requires the `CAP_NET_RAW` capability. Two ways to get it:

```sh
# 1. grant the capability to the binary once, then run as a normal user (what install-linux.sh does)
scripts/linux-capture-access.sh

# 2. or run as root every time
sudo build/my_sniffer
```

`scripts/linux-capture-access.sh` runs `sudo setcap cap_net_raw+ep` on `build/my_sniffer`, or on the path you give it:

```sh
scripts/linux-capture-access.sh release/bin/my_sniffer
```

Good to know:

- The capability is attached to the file. Rebuilding the binary removes it, and a copy does not inherit it: run the script again on the new file.
- It is ignored on filesystems mounted with `nosuid` (often `/tmp`, sometimes `/home`). Build elsewhere or use `sudo`.
- Check it with `getcap build/my_sniffer`.

### macOS

`my_sniffer` reads packets from the BPF devices `/dev/bpf*`, which only root can open by default. Two ways:

```sh
# 1. run as root
sudo build/my_sniffer

# 2. or give your user access to /dev/bpf*
scripts/macos-capture-access.sh
```

`scripts/macos-capture-access.sh` runs `sudo chown <you> /dev/bpf*`: your user becomes the owner of the BPF devices and can open them.
macOS recreates `/dev/bpf*` at every boot, so run the script again after a reboot.

The macOS backend captures on `en0`, the usual name of the first Wi-Fi or Ethernet interface.
To capture on another interface, change `DEFAULT_INTERFACE` in `src/capture/MacCapture.cpp` and rebuild.

## Run

The examples below call `my_sniffer` and `analyse_log` by name. From the project directory, write `build/my_sniffer` and `build/analyse_log`, or `release/bin/...` for an [installed copy](#install).

### Capture: `my_sniffer`

```sh
my_sniffer                                 # live display only
my_sniffer --log capture.log               # also write a log
my_sniffer -d --log capture.log            # detailed mode: every header and the payload
my_sniffer -f proto=tcp -f dport=443       # only TCP packets to port 443
my_sniffer -f contains="GET /"             # only packets whose payload contains this text
my_sniffer --help                          # every option and filter
```

| Option | Effect |
|---|---|
| `-d`, `--detailed` | detailed display and detailed log (default: minimum) |
| `--log`, `--log <path>`, `--log=<path>` | write a log; without a path, `my_sniffer.log` in the current directory |
| `-f`, `--filter <expr>` | only display and log the packets that match |
| `-h`, `--help` | help |

- **Log file name:** the start time is added, so `--log capture.log` writes `capture_<dd-mm-YYYY>_<HH-MM-SS>.log`.
- **Rotation:** a log file is closed at 50 MB and renamed `<name>.1.log`, `<name>.2.log`... Three older parts are kept.
- **Minimum or detailed:** the default log has one line per packet. `-d` logs every header and the payload in hexadecimal. `analyse_log` reads both, but needs a detailed log to check protocols.
- **Keys while capturing:** `p` pauses or resumes the display, `d` switches between minimum and detailed display, `Ctrl+C` stops and prints a summary.

Filters are `key=value`. Several values of one key are separated by `/` and mean "any of them"; different keys must all match.

| Filter | Matches |
|---|---|
| `proto=<type>` | `tcp`, `udp`, `arp`, `ipv6`, `unknown` |
| `sport=<port>`, `dport=<port>`, `port=<port>` | source port, destination port, either |
| `src=<ip>`, `dst=<ip>`, `ipv4=<ip>` | source address, destination address, either |
| `tcpflags=<flags>` | `NS`, `CWR`, `ECE`, `URG`, `ACK`, `PSH`, `RST`, `SYN`, `FIN` |
| `minsize=<bytes>`, `maxsize=<bytes>` | packet size |
| `contains=<text>` | text found in the TCP or UDP payload |

### Analyse: `analyse_log`

```sh
analyse_log capture_08-10-2026_14-30-00.log
analyse_log -w config/whitelist.conf capture_08-10-2026_14-30-00.log
analyse_log -f report.txt capture_08-10-2026_14-30-00.log
```

Give it the main log file: it finds the rotated parts by itself and reads them oldest first.

| Alert | Meaning | Needs |
|---|---|---|
| `[SERVICE-SPIKE]` | abnormal volume from one IP to one service (IP and port) | |
| `[NETWORK-SPIKE]` | whole network traffic at least 3 times its usual level | |
| `[BEACON]` | connections to one destination at a nearly constant interval | |
| `[FOREIGN-IP]` | traffic to or from an IP outside the whitelist, with its direction and LAN / WAN context | `-w <whitelist>` |
| `[PROTO-MISMATCH]` | payload that is not the protocol expected on a standard port (TCP 80 HTTP, 443 TLS, 22 SSH...) | a detailed log (`my_sniffer -d`) |

| Option | Effect |
|---|---|
| `-w`, `--whitelist <file>` | trusted IPs and ranges: turns `[FOREIGN-IP]` on |
| `-f`, `--file <file>` | also write the report to `<file>` (overwritten if it exists) |
| `-h`, `--help` | help |

## Configuration

The only configuration file is the whitelist of `analyse_log`: the IPv4 addresses and ranges you trust.
An example is provided in `config/whitelist.conf`. Copy it and edit the copy:

```sh
cp config/whitelist.conf ~/whitelist.conf
analyse_log -w ~/whitelist.conf capture_08-10-2026_14-30-00.log
```

Format: one entry per line, either a single IP or a CIDR range. Everything after `#` is a comment.

```
192.168.1.0/24     # my home network
8.8.8.8            # a DNS server I use
```

The example trusts the three private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), so only public IPs are reported.
Replace them with your own subnet to also catch unknown devices on your local network.
An invalid line stops `analyse_log` with the file name and the line number.

## Tests

Unit tests use [Criterion](https://github.com/Snaipe/Criterion). The `unit_tests` target only exists when CMake finds it.

```sh
build/unit_tests                           # run the tests built by scripts/install.sh
cmake --build build --target run_tests     # rebuild them if needed, then run them
cmake --build build --target coverage      # same, plus an HTML report in build/coverage/index.html (needs gcovr)
```

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `No capture backend implemented for this platform` (CMake) | The project only builds on Linux and macOS |
| CMake fails while downloading spdlog | spdlog is not installed and GitHub cannot be reached. Connect to the internet, or install spdlog (`libspdlog-dev`, `spdlog-devel`, `brew install spdlog`) and configure again |
| `Criterion not found, skipping unit_tests target` (CMake) | Only the tests are skipped. Install Criterion, then configure again |
| A warning stops the build | Warnings are errors (`-Werror`): fix the code the compiler points at |
| `Homebrew is required` (macOS) | Install Homebrew from https://brew.sh, then run the script again |
| `socket: Operation not permitted` (Linux) | `my_sniffer` has no `CAP_NET_RAW`: run `scripts/linux-capture-access.sh` again (rebuilding removes the capability) or use `sudo` |
| `sudo: setcap: command not found` (Linux) | Install libcap: `libcap2-bin` (apt) or `libcap` (dnf, pacman) |
| `Permission denied while opening /dev/bpf0` (macOS) | Use `sudo`, or run `scripts/macos-capture-access.sh` (again after each reboot) |
| `All BPF devices are in use` (macOS) | Another capture tool (Wireshark, tcpdump) holds them: close it |
| `ioctl(BIOCSETIF)` error (macOS) | Your interface is not `en0`: see [macOS](#macos) |
| `my_sniffer: command not found` | The binaries are in `build/` (or `release/bin/` once installed): call them with that path |
| `PROTO-MISMATCH  disabled` in the summary | The log has no payload: capture with `my_sniffer -d` |
| `FOREIGN-IP  disabled` in the summary | No whitelist given: add `-w <whitelist>` |

## Project layout

```
CMakeLists.txt        build and install rules
config/               example whitelist
include/, src/        sources
  capture/            capture backends: LinuxCapture (AF_PACKET), MacCapture (BPF)
  parsers/            Ethernet, IPv4, TCP, UDP
  cli/                live display, filters, keyboard input
  log/                log writer (spdlog)
  analysis/           log parser and detectors used by analyse_log
scripts/              set-up scripts: dependencies, build, capture rights
tests/                unit tests (Criterion)
build/                build directory (created by the build, ignored by git)
release/              default install directory (created by cmake --install, ignored by git)
```
