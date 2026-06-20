# Contributing to AUR Tester 🤝

Thank you for your interest in improving the AUR Tester! We welcome contributions from the community, whether you are fixing bugs, improving documentation, or proposing new security features.

## How to Contribute

### 1. Reporting Bugs & Feature Requests
Before opening a new issue, please search the existing issues to ensure it hasn't been reported yet. When opening an issue, provide as much context as possible:
- Your system configuration (Kernel version, Docker version).
- Steps to reproduce the issue.
- Terminal logs (especially the output from the sniffer or Docker orchestrator).

### 2. Development Setup
To start hacking on the codebase:
1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Create a new branch for your feature or bug fix: `git checkout -b feature/my-awesome-feature`.

### 3. Running Tests
Because our integration tests utilize `libpcap` to capture raw network packets from the network interfaces, **you must run the test suite with root privileges**:

```bash
sudo -E cargo test
```
