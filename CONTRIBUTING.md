# Contributing to StyxLoaderX

## Ethical Scope (Enforced)

StyxLoaderX is a **research framework** for studying Windows x64
process injection techniques. It is NOT an operational tool. To keep
it that way, contributions are bounded by the following ethical scope.

### What IS accepted

- **Bug fixes** for existing techniques (compilation errors, logic
  bugs, handle leaks, missing error checks).
- **Documentation improvements** (better explanations, more references,
  honest updates to `test_report.md` and `Whitepaper.md`).
- **Defensive detection improvements** (new Sigma rules, Sysmon config
  deltas, YARA rules — see `docs/detections/`).
- **Refactoring** that improves code quality without changing behavior
  (e.g. RAII for handles, smart pointers, splitting large functions).
- **Build system improvements** (CMake updates, CI workflow updates).
- **Test scaffolding** (compilation tests, lab test protocols).
- **Implementation of "legitimate future work"** items from
  `docs/Whitepaper.md`:
  - Compile-time string obfuscation (skCrypter-style `constexpr`)
  - OpenSSL EVP API migration (replace deprecated `AES_cbc_encrypt`)
  - Full PE payload support in ProcessHollowing (compute
    `AddressOfEntryPoint` from the PE header)

### What is NOT accepted (will be rejected)

- **Operational evasion techniques** that cross from "research
  demonstration" into "operational tooling":
  - SSN randomization (Hell's Gate / Halo's Gate / Tartarus' Gate)
  - ETW patching
  - AMSI bypass
  - Sleep obfuscation (Ekko, Foliage)
  - Callback-based injection (EnumWindows, CreateTimerQueueTimer,
    EnumChildWindows, etc.)
  - Custom syscall stub generation at runtime
  - AV/EDR fingerprinting and dynamic adaptation
  - Process doppelgänging / ghosting / herpaderping
  - Indirect syscalls (correctly implemented — see `Whitepaper.md`
    "Future Work (Conceptual)" for context)

- **Operational malware features**:
  - Persistence (Run keys, scheduled tasks, services, WMI event
    subscriptions, etc.)
  - Command & control (C2) channels
  - Data exfiltration
  - Lateral movement
  - Credential dumping (LSASS access beyond what's needed for
    research injection)
  - Kerberos ticket manipulation

- **Payloads beyond the calc.exe canary**:
  - The `shellcode/shellcode.asm` file is a TEST CANARY. Do not
    propose PRs that replace it with a "more useful" payload. The
    canary exists specifically to keep the framework non-operational.

- **Removal or weakening of ethical safeguards**:
  - Do not remove or weaken the disclaimer in `README.md`.
  - Do not remove or weaken the ethical preamble in `LICENSE`.
  - Do not remove or weaken the scope rules in this file.
  - Do not remove or weaken the security policy in `SECURITY.md`.
  - Do not remove the `CheckAndAbortIfSandbox()` call from
    `tools/main_loader.cpp`.

## PR Checklist

Before opening a PR, verify:

- [ ] Code compiles cleanly with `/WX` (MSVC) or `-Werror` (GCC/Clang).
- [ ] No new `__asm` blocks (use MASM `.asm` files instead — see
      `modules/asm/styx_syscalls.asm` for the pattern).
- [ ] No `#include "../modules/X.cpp"` (use `#include "styxloader/X.hpp"`
      instead — public headers live in `include/styxloader/`).
- [ ] No `int main()` in `src/*.cpp` (main() lives only in `tools/*.cpp`).
- [ ] No handle leaks (`CloseHandle` on every error path, or use RAII).
- [ ] No `new`/`delete` without smart pointers (`std::unique_ptr`,
      `std::shared_ptr`).
- [ ] All API return values checked (especially `OpenProcess`,
      `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory`).
- [ ] If adding a new offensive technique: a corresponding defensive
      detection (Sigma rule or Sysmon delta) is added in
      `docs/detections/`.
- [ ] If adding a new offensive technique: it is within the ethical
      scope above (if unclear, open an issue to discuss BEFORE writing
      code).
- [ ] Documentation updated: relevant sections of `README.md`,
      `Whitepaper.md`, `test_report.md` reflect the new behavior.
- [ ] `test_report.md` is NOT updated to claim tests were run if they
      were not. Honesty over marketing.
- [ ] CRLF line endings preserved on all modified files (the repo
      uses CRLF throughout).

## Code Style

- **C++ standard**: C++17 (enforced by CMake).
- **Namespaces**: all public symbols in `namespace styxloader`.
- **Headers**: public API in `include/styxloader/*.hpp`; implementations
  in `src/*.cpp`. No header/impl mixing.
- **Includes**: use `#include "styxloader/X.hpp"` for project headers,
  `#include <windows.h>` for system headers. Project headers first,
  then system headers, then third-party (OpenSSL).
- **Error handling**: check return values of all Win32 API calls. Use
  `GetLastError()` in error messages. Prefer `try`/`catch` for
  `std::stoi`/`std::stoul`.
- **Memory**: use `std::vector`, `std::string`, `std::unique_ptr` for
  ownership. Raw `new`/`malloc` only when interfacing with C APIs that
  require it, and always wrap in RAII.
- **Comments**: explain WHY, not WHAT. Reference authoritative sources
  (MalwareTech, hasherezade, j00ru, Russinovich, NIST, etc.) where
  relevant.
- **Honesty**: if a technique has known weaknesses (e.g. runtime string
  obfuscation), document them in the header file. A research tool
  should show its own limitations.

## Test Protocol (Lab Verification)

Before claiming any technique works in `test_report.md`, you MUST
follow the test protocol documented there. Do NOT add claims like
"X% evasion rate" without lab evidence. If you ran tests in a lab,
record:

- Windows version and build number
- Sysmon version and config (link to the config file)
- EDR product (if any) and version
- Exact commands executed
- Sysmon Event IDs observed (with timestamps)
- Calc.exe canary result (opened / did not open)

Vague claims like "tested against modern EDRs" will be rejected.

## CI

The GitHub Actions workflow (`.github/workflows/build.yml`) verifies
compilation on every push and PR. A green CI means the code compiles;
it does NOT mean the code works functionally. Functional testing
requires a lab VM with Sysmon (see `docs/test_report.md` for the
manual protocol).

## License

By contributing, you agree that your contributions will be licensed
under the GNU General Public License v3.0 or later (see `LICENSE`).
The ethical preamble in `LICENSE` applies to all contributions.
