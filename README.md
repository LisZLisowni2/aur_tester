# AUR Tester

`AurTester` is a secure, reactive isolation environment and dynamic network intrusion prevention system (IPS) designed for safely compiling and testing Arch Linux (AUR) packages. 

It automatically clones a specified package, parses its `PKGBUILD` to dynamically build a domain whitelist, spins up a hardened Arch Linux Docker container, and sniffs its outbound network traffic via `libpcap` to instantly terminate the container if any unlisted domain or direct IP connection is detected.

## Features
- **Automated Root Validation**: Safely asserts required permissions before initiating raw network socket operations.
- **Dynamic Whitelisting**: Parses `PKGBUILD` sources in real-time to allow legitimate package downloads while blocking hidden telemetry or malware.
- **DNS-Parser Level Inspection**: Resolves raw IPv4 TCP connections back to their domain names by capturing port 53 UDP packets on the Docker bridge (`docker0`).
- **Asynchronous Kill Switch**: Instantly kills and destroys the container mid-build via `tokio::select!` the millisecond a network anomaly occurs.
  
## Prerequisites
- **Arch Linux** host (or any system running Docker with an Arch build toolchain available).
- **Docker** daemon running and configured.
- **Root Privileges** (required for `libpcap` packet capturing on the `docker0` network interface).
- **Git** installed on the host.

## Installation & Usage

Clone the repository and build the binary:

```bash
cargo build --release
```

Run the sandbox tester with root privileges (preserving environment variables for Docker socket access):
Bash

```bash
sudo ./target/release/aur_tester <package-name>
```

## Options

```
Usage: aur_tester [OPTIONS] <PACKAGE>

Arguments:
  <PACKAGE>  The name of the AUR package to test (e.g., yay, paru)

Options:
  -i, --interface <INTERFACE>  Custom Docker network interface [default: docker0]
  -h, --help                   Print help
  -V, --version                Print version
```

## Architecture Diagram

The orchestrator provisions an isolated container, while an asynchronous task sniffs the network bridge. If an unauthorized payload attempts an outbound HTTP connection to a non-declared domain, the mpsc channel triggers an emergency container destruction.
