⚠️ ACADEMIC RESEARCH ONLY
This code is published for educational purposes to help defenders 
understand evasion techniques. Do not use for malicious purposes.
Author is a defensive security engineer.

# StyxLoaderX: Advanced EDR Evasion Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++](https://img.shields.io/badge/C%2B%2B-11-blue)](https://isocpp.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://www.microsoft.com/en-us/windows)
[![GitHub Stars](https://img.shields.io/github/stars/frangelbarrera/StyxLoaderX-EDR-Evasion?style=social)](https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion)

## Overview

**StyxLoaderX** is a modular research framework for studying Endpoint Detection and Response (EDR) evasion techniques on Windows x64 systems. This project documents techniques relevant to defensive analysis, including dynamic syscall mapping, AES-256 encryption, process hollowing, and sandbox detection. The goal is to help defenders understand attacker methodologies in order to build better detections.

**Key Highlights:**
- **Modular Architecture:** Easily extensible with interchangeable evasion modules.
- **Dynamic Syscall Resolution:** Adapts to Windows updates without recompilation.
- **AES Encryption & UPX Packing:** Protects binaries and strings from static analysis.
- **Educational Focus:** Built for learning red team techniques; strictly for ethical, controlled environments.
- **Performance:** <5s execution time, minimal resource footprint.

This framework is ideal for penetration testers, security researchers, and students exploring EDR bypass. It executes arbitrary payloads (e.g., opening calc.exe) while evading modern security solutions.

**Repository URL:** [https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion](https://github.com/frangelbarrera/StyxLoaderX-EDR-Evasion)
**Documentation:** [Full Whitepaper](docs/Whitepaper.md) | [Test Report](docs/test_report.md)

---

## ⚖️ Ethical Use Policy

This framework documents offensive techniques that have legitimate defensive applications. Security professionals must understand attacker methodologies to build effective detections and protections.

**Authorized use cases:**
- Red team assessments with signed Rules of Engagement
- EDR product testing and detection engineering
- Academic research in Windows internals and malware analysis
- Cybersecurity training in controlled lab environments

**All testing must occur in isolated lab VMs.** See [docs/config_lab.md](docs/config_lab.md) for safe setup instructions.

---

> **⚠️ LEGAL NOTICE:** This project is provided strictly for **educational and authorized security research purposes only**. Unauthorized access to computer systems is a criminal offense in most jurisdictions.

**By using this software you agree that you:**
- ✅ Have explicit, written authorization before testing any system
- ✅ Are conducting legitimate red team assessments or academic research
- ✅ Will comply with all applicable laws (CFAA, Computer Misuse Act, Budapest Convention, etc.)
- ❌ Will NOT use these techniques against systems without authorization
- ❌ Will NOT use this for any illegal or malicious purpose

**The authors assume no liability for misuse.** If you are unsure whether your use is authorized, it is not.

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

### Research Metrics
- **Tested Against:** Sysmon with high-telemetry configuration (see docs/test_report.md for methodology).
- **Execution Speed:** Sub-5-second payload deployment.
- **Compatibility:** Windows 10/11 x64; supports multiple injection modes.
- **Modularity:** Plug-and-play modules for testing different evasion strategies.

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
| Hollow    | Process hollowing + AES              | High            | Detection engineering     |

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
- **Simple mode:** Sysmon Event ID 8 (CreateRemoteThread) should be logged.
- **Direct/Hollow modes:** Test which telemetry gaps appear in your Sysmon config.
- **Execution time:** <5s for payload deployment.
- **Debugging:** Use x64dbg for process inspection.
- **Detection engineering:** Use the gaps you find to build Sigma rules or tune Sysmon configs.

Full test report: [docs/test_report.md](docs/test_report.md).

## Contributing

Contributions are welcome! This is an educational project.

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/new-technique`
3. Ensure all new modules include documentation
4. Submit a PR with a clear description of the technique and its defensive implications

**Contribution guidelines:**
- Follow C++ best practices
- Document the defensive countermeasure for every offensive technique added
- Test in isolated VMs only — never test against production systems
- Update the relevant docs (Whitepaper, test_report) with your findings

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by open-source projects like [klezVirus/inceptor](https://github.com/klezVirus/inceptor).
- Research based on Windows internals and EDR bypass techniques.
- Thanks to the cybersecurity community for shared knowledge.

---

**Built for defensive cybersecurity research. See CONTRIBUTING.md for guidelines on adding detection artifacts alongside new techniques.**

