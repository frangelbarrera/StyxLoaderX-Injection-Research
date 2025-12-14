# StyxLoaderX: Advanced EDR Evasion Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++](https://img.shields.io/badge/C%2B%2B-11-blue)](https://isocpp.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://www.microsoft.com/en-us/windows)
[![Evasion Rate](https://img.shields.io/badge/Evasion%20Rate-85%25-green)](https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion)
[![GitHub Stars](https://img.shields.io/github/stars/frangelbarrera/StyxLoaderX-EDR-Evasion?style=social)](https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion)

## Overview

**StyxLoaderX** is a sophisticated, modular framework designed for advanced Endpoint Detection and Response (EDR) evasion on Windows x64 systems. This project demonstrates cutting-edge techniques in cybersecurity research, including dynamic syscall mapping, AES-256 encryption, process hollowing, and sandbox detection. With an **85% evasion rate** against tools like Sysmon, it showcases expertise in low-level Windows internals and anti-forensic methods.

**Key Highlights:**
- **Modular Architecture:** Easily extensible with interchangeable evasion modules.
- **Dynamic Syscall Resolution:** Adapts to Windows updates without recompilation.
- **AES Encryption & UPX Packing:** Protects binaries and strings from static analysis.
- **Educational Focus:** Built for learning red team techniques; strictly for ethical, controlled environments.
- **Performance:** <5s execution time, minimal resource footprint.

This framework is ideal for penetration testers, security researchers, and students exploring EDR bypass. It executes arbitrary payloads (e.g., opening calc.exe) while evading modern security solutions.

**Repository URL:** [https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion](https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion)
**Documentation:** [Full Whitepaper](docs/Whitepaper.md) | [Test Report](docs/test_report.md)

**Disclaimer:** This project is for **educational and research purposes only**. Do not use in production systems or for malicious activities. Always comply with legal and ethical guidelines.

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features

### Core Capabilities
- **Direct Syscalls with Dynamic Mapping:** Bypasses userland hooks by calling NT functions directly, resolving syscall numbers at runtime for compatibility across Windows builds.
- **Process Hollowing:** Replaces legitimate process memory with malicious code, making injections appear as normal system activity.
- **String Obfuscation:** AES-256 encryption for sensitive data (e.g., DLL names), decrypted on-the-fly to evade signature-based detection.
- **Binary Packing:** UPX compression reduces file size by ~50% and adds obfuscation layers.
- **Sandbox Evasion:** Detects and aborts in virtualized or analysis environments (e.g., VMs, sandboxes).

### Advanced Metrics
- **Evasion Effectiveness:** 85% success rate in bypassing Sysmon logs (improved from 66% with enhancements).
- **Execution Speed:** Sub-5-second payload deployment.
- **Compatibility:** Windows 10/11 x64; supports multiple injection modes.
- **Modularity:** Plug-and-play modules for custom evasion strategies.

### Educational Value
- Learn Windows API internals, memory manipulation, and red team tactics.
- Includes comprehensive documentation, research notes, and test reports.
- Suitable for cybersecurity courses, CTFs, or portfolio projects.

## Architecture

```
StyxLoaderX/
├── src/                 # Main loaders (MainLoader.cpp, SimpleInjector.cpp)
├── modules/             # Evasion modules (DirectSyscall.cpp, HollowInjector.cpp, etc.)
├── shellcode/           # Assembly payloads (shellcode.asm)
├── docs/                # Documentation (Whitepaper.md, test_report.md, etc.)
├── run_project.bat      # Automated build and execution script
└── README.md            # This file
```

- **MainLoader.cpp:** Central orchestrator selecting evasion modes (simple, direct, hollow).
- **Modules:** Reusable components for specific techniques (e.g., syscalls, encryption).
- **Shellcode:** Customizable payloads compiled from Assembly.
- **Automation:** `run_project.bat` handles dependencies, compilation, and testing.

## Installation

### Prerequisites
- **Operating System:** Windows 10/11 x64.
- **Tools:** Visual Studio Community (with C++ Desktop Development), NASM Assembler.
- **Hardware:** At least 4GB RAM (8GB recommended for VMs).
- **Permissions:** Administrator rights for execution.

### Step-by-Step Setup
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion.git
   cd StyxLoaderX-EDR-Evasion
   ```

2. **Install Dependencies:**
   - Download and install [Visual Studio](https://visualstudio.microsoft.com/) with C++ workload.
   - Download and install [NASM](https://www.nasm.us/).
   - The `run_project.bat` script will automatically download OpenSSL and UPX if needed.

3. **Build the Project:**
   - Run `run_project.bat` as administrator.
   - It compiles shellcode, loaders, and applies obfuscation.

4. **Verify Installation:**
   - Check for generated files: `MainLoader.exe`, `SimpleInjector.exe`, `shellcode.bin`.
   - Test in a VM (see [Testing](#testing)).

For detailed lab setup, see [docs/config_lab.md](docs/config_lab.md).

## Usage

### Quick Start
1. Execute `run_project.bat` and select a mode (e.g., "direct" for advanced evasion).
2. Provide a target process PID or EXE (e.g., notepad.exe).
3. Monitor results: Payload executes stealthily.

### Command Examples
- **Simple Mode:** `MainLoader.exe simple 1234 shellcode\shellcode.bin` (Basic injection).
- **Direct Mode:** `MainLoader.exe direct 1234 shellcode\shellcode.bin` (Syscall-based, high evasion).
- **Hollow Mode:** `MainLoader.exe hollow explorer.exe shellcode\shellcode.bin` (Process hollowing).

### Modes Overview
| Mode      | Description                          | Evasion Level | Use Case                  |
|-----------|--------------------------------------|---------------|---------------------------|
| Simple    | Basic CreateRemoteThread injection   | Low (detectable) | Testing basics            |
| Direct    | Dynamic syscalls                     | High (~80%)    | Bypassing hooks           |
| Hollow    | Process hollowing + AES              | Very High (~90%)| Advanced persistence      |

### Customization
- Modify `shellcode/shellcode.asm` for custom payloads.
- Extend modules in `modules/` for new techniques.
- Adjust obfuscation keys in `StringObfuscator.h`.

## Testing

Test in a controlled VM environment to avoid risks.

### Setup Test Environment
- Install Sysmon with high-telemetry config (see [docs/config_lab.md](docs/config_lab.md)).
- Run `run_project.bat` and select modes.
- Check Event Viewer > Windows Logs > Application for Sysmon events (ID 8 for injections).

### Expected Results
- **Success:** No logs in advanced modes; calc.exe opens without alerts.
- **Metrics:** 85% evasion rate; <5s execution.
- **Debugging:** Use x64dbg for process inspection.

Full test report: [docs/test_report.md](docs/test_report.md).

## Contributing

Contributions are welcome! This is an educational project.

1. Fork the repo: [https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion/fork](https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion/fork).
2. Create a feature branch: `git checkout -b feature/new-evasion-technique`.
3. Commit changes and submit a PR.
4. Report issues: [Issues Page](https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion/issues).

Guidelines:
- Follow C++ best practices.
- Add tests for new modules.
- Update documentation.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by open-source projects like [klezVirus/inceptor](https://github.com/klezVirus/inceptor).
- Research based on Windows internals and EDR bypass techniques.
- Thanks to the cybersecurity community for shared knowledge.

---

**Built with passion for ethical cybersecurity education. Star this repo if you find it useful!** 🚀

