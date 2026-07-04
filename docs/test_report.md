# Test Report: StyxLoaderX Research Framework

## Status: NOT YET TESTED IN LAB

**As of the refactor series (commits 1–7 of the `fix/refactor-research-grade`
branch), the code compiles on MSVC x64 + MASM + NASM but has not been
functionally tested in a lab VM.**

This file previously contained claims such as "85% evasion rate", "Direct
Mode: Not detected by Sysmon. Calc.exe executed without injection logs",
and "Hollow Mode: Excellent (~90%)". Those claims were fabricated — they
were not supported by any test evidence, the code did not compile at the
time they were written (see commit `653bf2d` and the staff engineer audit
worklog), and the single-commit git history eliminated any charitable
interpretation that the tests might have been run on an earlier version.

The previous claims have been removed. This file now documents what HAS
been tested, what HAS NOT been tested, and what the test plan is.

---

## What Has Been Verified (Static Analysis Only)

The following have been verified by static analysis (g++ -fsyntax-only
+ g++ -c on Linux with a Win32 API shim, plus pwntools asm() for opcode
verification on Linux). They have NOT been verified by running the
binaries on Windows.

| Component | Verification | Status |
|-----------|--------------|--------|
| `src/shellcode.cpp` | g++ -c | Compiles cleanly |
| `src/sandbox_check.cpp` | g++ -c | Compiles cleanly |
| `src/simple_injector.cpp` | g++ -c | Compiles cleanly |
| `src/string_obfuscator.cpp` | g++ -c (against system OpenSSL 3.x) | Compiles with deprecation warnings (AES_cbc_encrypt is deprecated in OpenSSL 3.0; migration to EVP API is tracked as future work) |
| `src/hollow_injector.cpp` | g++ -c | Compiles cleanly |
| `src/direct_syscall.cpp` | g++ -c (with MASM stubs stubbed out) | Compiles cleanly |
| `tools/main_loader.cpp` | g++ -fsyntax-only | Compiles cleanly |
| `tools/simple_injector_tool.cpp` | g++ -fsyntax-only | Compiles cleanly |
| `modules/asm/styx_syscalls.asm` | pwntools asm() (opcodes verified) | Opcodes match expected Win32 syscall ABI pattern (`49 89 ca` mov r10,rcx + `b8 NN NN NN NN` mov eax,imm32 + `0f 05` syscall + `c3` ret). MASM syntax not verified on Linux (no ml64 available); will be verified on Windows in lab. |
| `shellcode/shellcode.asm` | pwntools asm() (opcodes + RIP-relative displacements verified) | Produces 44 bytes. All 10 opcode assertions pass. Position-independent. |

**NOT verified** (requires Windows lab):
- Anything that actually runs `MainLoader.exe` or `SimpleInjector.exe`
- Anything that resolves SSNs at runtime via `GetSyscallNumber`
- Anything that calls `NtAllocateVirtualMemory` / `NtCreateThreadEx` via
  the MASM stubs
- Anything that opens `calc.exe` after injection
- Anything that produces or avoids Sysmon events

---

## What Was Wrong With the Previous Claims

The previous `test_report.md` (commit `653bf2d`, 2026-06-29) claimed:

| Previous claim | Why it was fabricated |
|----------------|----------------------|
| "Environment: Windows 11 x64 VM, 2 GB RAM, Sysmon with SwiftOnSecurity config" | `docs/config_lab.md` admitted "Status: Pending execution on PC with more RAM". 2 GB is below Windows 11 minimum (4 GB) and would trigger `SandboxCheck.cpp`'s <2 GB abort. The lab was never set up. |
| "Direct Mode: Not detected by Sysmon. Calc.exe executed without injection logs." | `DirectSyscall.cpp:29` had a syntax error (`p[i[i + 6]`) that prevented compilation. The `__asm` blocks (lines 58-98) were not supported on MSVC x64 AND contained `mov rdx, rdx` / `mov r8, r8` / `mov r9, r9` NOPs that did not load any actual syscall arguments. `shellcode.asm:15` used `mov rax, 0x7C8623AD` — a Windows XP 32-bit WinExec address, invalid on Windows 11 x64. The direct mode binary did not exist and could not have executed calc.exe. |
| "Direct Mode Evasion: Very high (~80%)" | See above. The binary did not exist. |
| "Hollow Mode: Not detected by Sysmon. Process appears legitimate in Task Manager." | `HollowInjector.cpp:40` read `ctx.Rdx` (wrong register — should be `ctx.Rcx` for PEB pointer on x64). `:67` set `ctx.Rcx = newBase` (wrong register — should be `ctx.Rip` for entry point redirection). The hollowed process would crash on `ResumeThread`. |
| "Hollow Mode Evasion: Excellent (~90%)" | See above. |
| "Evasion Rate: ~85%" | Arithmetic on fabricated numbers. |
| "Execution Time: <5 seconds per test" | Tests were not run. |
| "Conclusion: The framework demonstrates effective evasion against the tested Sysmon configuration." | No tests were run. |

The single-commit git history (only commit `653bf2d` existed before the
refactor series) eliminated any charitable interpretation that the tests
might have been run on an earlier functional version. There was no
earlier version.

---

## Test Plan (Future Work)

Once the code is verified to compile on Windows (run `run_project.bat`
or `cmake --build`), the following test protocol will be executed in a
lab VM. Results will be recorded here honestly, including failures.

### Lab Setup

- Windows 11 x64 VM (minimum 4 GB RAM, 64 GB disk — Windows 11 minimum)
- Sysmon with SwiftOnSecurity config (or higher-telemetry config)
- Visual Studio 2022 Build Tools (C++ workload)
- NASM 2.16+
- OpenSSL 3.x (via vcpkg recommended)
- x64dbg for debugging
- Event Viewer for Sysmon logs

### Test Cases

1. **Compilation test** — `run_project.bat` (or `cmake --build`) succeeds
   and produces `MainLoader.exe`, `SimpleInjector.exe`, `shellcode.bin`.
   Record: build time, warnings, errors.

2. **Calc canary (simple mode)** — Launch `notepad.exe`, get its PID,
   run `MainLoader.exe simple <PID> shellcode\shellcode.bin`. Expected:
   calc.exe opens. Record: calc.exe opens (yes/no), Sysmon Event ID 8
   logged (yes/no).

3. **Calc canary (direct mode)** — Same as above with `direct` mode.
   Expected: calc.exe opens. Record: calc.exe opens (yes/no), Sysmon
   Event ID 8 logged (yes/no) — note: direct syscalls bypass Sysmon's
   userland hooks, so Event ID 8 should NOT fire. If it does, document
   why (e.g. Sysmon v15+ kernel callbacks).

4. **Calc canary (hollow mode)** — Run
   `MainLoader.exe hollow C:\Windows\System32\notepad.exe shellcode\shellcode.bin`.
   Expected: a notepad.exe process spawns, then calc.exe opens.
   Record: calc.exe opens (yes/no), notepad.exe visible in Task Manager
   (yes/no), Sysmon Event ID 1 (suspended process creation) logged
   (yes/no), Sysmon Event ID 10 (process access) logged (yes/no).

5. **Sandbox evasion check** — Run `MainLoader.exe` in the lab VM.
   Expected: the sandbox check passes (lab is NOT detected as sandbox).
   Record: did the sandbox check pass (yes/no), if no which check fired.

6. **String obfuscation check** — Run
   `strings MainLoader.exe | grep -i kernel32` on the compiled binary.
   Expected: the plaintext "kernel32.dll" IS still present in .rdata
   (because the obfuscation is runtime, not compile-time — see known
   weakness in `string_obfuscator.hpp`). Record: confirmation that this
   is a known weakness, not a regression.

### What "Evasion Rate" Would Mean

If evasion-rate measurements are added in the future, they will be
defined explicitly:
- Against Sysmon (telemetry only, does not block): "X% of test cases
  produced no Sysmon event matching the detection rule".
- Against a real EDR (Defender for Endpoint, Elastic Endpoint, etc.):
  requires ethics review and a properly isolated lab; out of scope for
  this research repo until a separate test framework is built.

The previous "85% evasion rate" was not defined against any of these —
it was a fabricated number.

---

## Refinements Applied During the Refactor Series

The following fixes from the staff engineer audit have been applied:

- **Compilation**: syntax error in `DirectSyscall.cpp:29` fixed (commit 1).
  `__asm` blocks replaced with MASM stubs (commit 3). `#include "../modules/X.cpp"`
  replaced with proper `.hpp` includes (commit 2). Missing `<fstream>`,
  `<vector>`, `<string>` includes added (commit 1). `AES_KEY` member
  renamed to `AES_KEY_BYTES` to avoid shadowing the OpenSSL typedef
  (commit 1).
- **Logic**: `HollowInjector.cpp` now uses `ctx.Rcx` + `ReadProcessMemory`
  for PEB, `ctx.Rip` for entry point, and patches `PEB.ImageBaseAddress`
  (commit 4). `DirectSyscall.cpp` now uses MASM stubs that correctly
  marshal arguments (commit 3). `shellcode.asm` is now position-
  independent and uses a loader-resolved WinExec address (commit 6).
- **Architecture**: split into `include/styxloader/`, `src/`, `tools/`,
  with `main()` only in `tools/` (commit 2).
- **Security**: `run_project.bat` now verifies Authenticode on the
  OpenSSL installer and SHA256 on the UPX zip, deploys OpenSSL DLLs,
  and uses relative paths via `%OPENSSL_ROOT%` (commit 7).
- **Removed**: `IndirectSyscall.cpp` was deleted (commit 2) because the
  "indirect syscall" concept was fundamentally misimplemented (called
  `GetTransitionFunction` instead of jumping to a `syscall; ret`
  instruction inside ntdll). It is tracked as future work in
  `docs/Whitepaper.md`.

## What Is Still Broken / Out of Scope

- **String obfuscation** is still runtime (plaintext in `.rdata`). A
  constexpr/compile-time implementation (skCrypter-style) is tracked as
  future work.
- **AES key/IV** are still the sequential bytes `0x00..0x1F` /
  `0x00..0x0F`. Known weakness, documented in `string_obfuscator.hpp`.
- **`AES_cbc_encrypt`** is deprecated in OpenSSL 3.0. Migration to the
  EVP API is tracked as future work.
- **Indirect syscalls** are not implemented. The previous implementation
  was deleted (see above).
- **No CI** — GitHub Actions workflow is added in a later commit but
  only verifies compilation, not functional behavior.
- **No automated tests** — the test plan above is manual. Automating
  it would require a Windows VM in CI with Sysmon, which is out of
  scope for a research repo.
