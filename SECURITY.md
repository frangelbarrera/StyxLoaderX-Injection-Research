# Security Policy

## StyxLoaderX — Windows x64 Injection Research Framework

This document describes how to responsibly report security issues found
in the StyxLoaderX framework itself. It does NOT describe how to use
the framework's offensive techniques — for that, see `README.md` and
`docs/Whitepaper.md`.

## Scope

StyxLoaderX is research code that demonstrates Windows x64 injection
techniques (direct syscalls, process hollowing, CreateRemoteThread,
string obfuscation, sandbox evasion). The framework's *purpose* is to
demonstrate these techniques in a controlled lab. Reporting that "the
framework can inject code" is not a security issue — it is the intended
behavior.

What IS in scope for security reports:

- **Bugs in the framework that crash the build machine or compromise
  the lab environment.** Examples:
  - Buffer overflows in the framework's own argument parsing
  - Handle leaks that exhaust lab resources
  - Supply-chain vulnerabilities in `run_project.bat` (e.g., a
    compromised download URL, missing checksum verification)
  - Path traversal in shellcode file reading
  - DLL hijacking in the built .exe

- **Defensive detection gaps.** If you find that the Sigma rules or
  Sysmon config delta in `docs/detections/` fail to detect the
  techniques the framework implements, please report it so the
  detections can be improved.

- **Ethical scope violations.** If you find code in the framework that
  crosses the ethical scope (persistence, C2, exfil, AMSI/ETW bypass,
  SSN randomization, etc. — see `CONTRIBUTING.md`), please report it
  immediately. Such code should not be in this repo.

What is NOT in scope:

- **"The framework can be used offensively."** Yes — that is its
  stated purpose. We will not respond to reports that the framework
  performs the techniques it documents.
- **"The framework bypasses my EDR."** The framework is research code
  for studying evasion techniques. If your EDR detects it, that is
  good — please contribute a Sigma rule. If your EDR does not detect
  it, that is a limitation of your EDR, not a bug in this framework.
- **"The framework's shellcode opens calc.exe."** Yes — that is the
  test canary. Replacing it with anything else is out of scope (see
  `CONTRIBUTING.md`).

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security reports.**

Instead, email the maintainer at: `201400231+frangelbarrera@users.noreply.github.com`
(GitHub's noreply address — forwards to the maintainer's real address).

Please include:

1. **Description** of the issue and its impact.
2. **Reproduction steps** (commands, environment, expected vs actual
   behavior).
3. **Affected version** (git commit hash).
4. **Suggested fix** (if you have one — optional but appreciated).

You should receive a response within 7 days. If the issue is confirmed,
a fix will be developed and released as soon as practical. You will be
credited in the commit message unless you request otherwise.

## Responsible Disclosure Timeline

- **Day 0**: You report the issue privately.
- **Day 1-7**: Maintainer acknowledges and triages.
- **Day 7-30**: Fix developed (timeline depends on severity and
  complexity).
- **Day 30**: Fix released in a public commit. Public disclosure after
  the fix is released, coordinated with you.

For critical issues (e.g., supply-chain vulnerability in
`run_project.bat` that compromises the build machine), the timeline
will be expedited.

## Security Measures in This Repository

The following security measures have been applied (refactor series,
commits 1-13):

- **Supply-chain hardening** in `run_project.bat`:
  - Authenticode signature verification on the OpenSSL installer
    (commit 7).
  - SHA256 verification framework for UPX zip (commit 7; user must
    fill in the expected hash from the official UPX release page).
  - Recommended alternative: use CMake + vcpkg (commit 10) which
    verifies package hashes and avoids third-party downloads.
- **Build system hardening**:
  - CMake treats warnings as errors (`/WX` on MSVC, `-Werror` on
    GCC/Clang) — commit 10.
  - C++17 strict conformance (`/permissive-` on MSVC) — commit 10.
- **Architecture review**:
  - Library/tools separation enforced (no `#include "../modules/X.cpp"`
    possible) — commit 2.
  - No `main()` in library code — commit 2.
- **CI verification**:
  - GitHub Actions workflow verifies compilation on every push/PR
    (commit 11).
  - vcpkg used for OpenSSL (supply-chain safe, no slproweb download
    in CI) — commit 11.

## Known Security Limitations (Deliberate)

The following are deliberate non-features (see `CONTRIBUTING.md` for
the ethical scope):

- No AMSI bypass
- No ETW bypass
- No SSN randomization (Hell's Gate / Halo's Gate / Tartarus' Gate)
- No anti-debugging beyond the basic sandbox check
- No callback-based injection (EnumWindows, CreateTimerQueueTimer)
- No sleep obfuscation (Ekko)
- No process doppelgänging / ghosting
- No persistence, C2, or exfiltration
- No payload beyond the calc.exe canary

These omissions are deliberate. They are the line between "research
demonstration" and "operational tooling". Do not propose PRs that add
them — they will be rejected.

## Contact

- Maintainer: Frangel Raúl Crespo Barrera
- Email: `201400231+frangelbarrera@users.noreply.github.com`
- GitHub: [frangelbarrera](https://github.com/frangelbarrera)
