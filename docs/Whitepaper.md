# Whitepaper: StyxLoaderX — Windows x64 Injection Research Framework

> **Honesty note (refactor series):** This whitepaper was previously
> titled "Endpoint Detection and Response (EDR) Evasion Framework" and
> claimed an "85% evasion rate". Those claims were fabricated — see
> `docs/test_report.md` for the full accounting. The whitepaper has been
> rewritten to describe what the framework actually does, what it does
> not do, and what its known limitations are. The framework has been
> renamed to "Windows x64 Injection Research Framework" to better
> reflect its scope and avoid the pretense of being an operational EDR
> evasion tool.

## Executive Summary

StyxLoaderX is a research framework for studying Windows x64 process
injection techniques. It implements three injection modes (simple
CreateRemoteThread, direct syscalls, process hollowing), a basic sandbox
evasion check, AES-256 string obfuscation (with documented weaknesses),
and a test shellcode that opens `calc.exe` as a canary.

The framework is **NOT** an operational EDR evasion tool. It does not
implement Hell's Gate / Halo's Gate / Tartarus' Gate (SSN randomization),
ETW/AMSI patching, sleep obfuscation (Ekko), callback-based injection,
process doppelgänging/ghosting, or any persistence/C2/exfil mechanism.
These omissions are deliberate — see `CONTRIBUTING.md` for the ethical
scope.

The framework is intended for:
- Academic study of Windows x64 injection techniques
- Detection engineering (defenders building Sigma/Sysmon rules against
  the techniques demonstrated here)
- Cybersecurity training in controlled lab VMs

## Implemented Techniques

### 1. Direct Syscalls

**Goal**: bypass userland API hooks installed by EDR products in
`ntdll.dll` by invoking the kernel via the `syscall` instruction
directly, rather than calling the `ntdll.dll` exported function
pointers (where the hooks live).

**Implementation** (`src/direct_syscall.cpp` + `modules/asm/styx_syscalls.asm`):

1. **SSN resolution** (`GetSyscallNumber`): parses the first 50 bytes
   of the ntdll stub for the pattern `B8 ?? ?? ?? ?? 0F 05`
   (`mov eax, imm32; syscall`) and extracts the imm32 as the syscall
   service number. The SSN is stored in a C-set global
   (`g_ssn_NtAllocateVirtualMemory`, etc.).

2. **Syscall invocation** (MASM stubs): for each syscall, a MASM stub
   reads the SSN from the global, marshals the Win64 calling-convention
   arguments into the Win32 syscall ABI (arg1 moves from `rcx` to
   `r10`; args 2-4 stay in `rdx`/`r8`/`r9`; args 5+ stay on the stack
   at `[rsp+28h]+`), and executes `syscall`.

**Honest limitations**:
- SSNs are resolved once at startup; no randomization. Hell's Gate /
  Halo's Gate / Tartarus' Gate would randomize SSN selection to defeat
  EDR hook detection — out of scope (crosses into operational evasion).
- No hook detection on the parsed ntdll stubs. If an EDR hooks the
  `NtAllocateVirtualMemory` export, `GetSyscallNumber` may scan past
  the hook and find a different pattern or fail. Documented as a known
  weakness.
- SSNs are stored in globals (not thread-local). Not thread-safe for
  concurrent `DirectInject` calls; acceptable for research use.

**References**:
- j00ru's syscall table: https://j00ru.vexillium.org/syscalls/nt/64/
- MalwareTech "Syscalls in Windows" series
- SysWhispers / SysWhispers2 / SysWhispers3 (klezVirus) for the pattern

### 2. Process Hollowing

**Goal**: create a legitimate process in suspended state, unmap its
original image, write a payload in its place, redirect the entry point,
and resume — the process appears legitimate in Task Manager but
executes the attacker's code.

**Implementation** (`src/hollow_injector.cpp`):

1. `CreateProcessA(targetExe, ..., CREATE_SUSPENDED, ...)` — spawns the
   legitimate process suspended.
2. `GetThreadContext(pi.hThread, &ctx)` — reads the suspended thread's
   register state. On x64, `ctx.Rcx` holds the PEB pointer (passed to
   `ntdll!LdrInitializeThunk`).
3. `ReadProcessMemory(hProc, ctx.Rcx + 0x10, &imageBase, 8, NULL)` —
   reads `PEB.ImageBaseAddress` (offset 0x10 in x64 PEB) to find the
   original image base.
4. `ZwUnmapViewOfSection(hProc, imageBase)` — unmaps the original
   image.
5. `VirtualAllocEx(hProc, imageBase, ..., PAGE_EXECUTE_READWRITE)` —
   allocates a new region at the same address (preferring the original
   base; falls back to NULL if unavailable).
6. `WriteProcessMemory(hProc, newBase, shellcode, ...)` — writes the
   payload.
7. `WriteProcessMemory(hProc, ctx.Rcx + 0x10, &newBase, 8, NULL)` —
   patches `PEB.ImageBaseAddress` for full-PE payloads (no-op for raw
   shellcode, but correct behavior).
8. `ctx.Rip = (DWORD64)newBase` — redirects execution to the new
   payload.
9. `SetThreadContext` + `ResumeThread` — resumes the thread, which now
   executes the payload.

**Honest limitations**:
- No EPA (Entry Point Obscuration)
- No phantom DLL hollowing
- No transacted hollowing
- For raw shellcode payloads, `newBase` IS the entry point (no PE
  header to compute `AddressOfEntryPoint` from). For full PE payloads
  (future work), `ctx.Rip = newBase + AddressOfEntryPoint`.

**References**:
- Stephen Haunts "Process Hollowing" (2011)
- hasherezade `hollowing_experiments`
- MalwareTech "Process Hollowing" tutorial
- Russinovich *Windows Internals* 7th ed. Part 1, PEB layout

### 3. Simple CreateRemoteThread Injection

**Goal**: the most basic injection technique. Documented for
educational comparison against the more advanced modes. Will be detected
by any EDR via `CreateRemoteThread` monitoring (Sysmon Event ID 8).

**Implementation** (`src/simple_injector.cpp`): the classic
`OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` →
`CreateRemoteThread` sequence.

### 4. String Obfuscation (with documented weaknesses)

**Goal**: hide sensitive strings (DLL names, function names) from
static analysis tools like `strings` and YARA.

**Implementation** (`src/string_obfuscator.cpp` + `include/styxloader/string_obfuscator.hpp`):
AES-256-CBC encryption via OpenSSL, with the encrypted bytes stored
in a global vector initialized at runtime by a constructor.

**Honest weaknesses** (tracked as future work):
- **NOT compile-time**: the `OBFUSCATE_STR` macro evaluates `Encrypt()`
  at runtime via a global constructor. The plaintext literal
  (`"kernel32.dll"`, `"ntdll.dll"`, `"calc.exe"`) is present in the
  `.rdata` section of the binary and is trivially findable with
  `strings`. This is security theater, not real obfuscation.
- **Static key/IV**: `AES_KEY_BYTES = {0x00, 0x01, ..., 0x1F}` and
  `AES_IV_BYTES = {0x00, 0x01, ..., 0x0F}` — the most predictable
  key/IV possible. The sequential bytes pattern is identifiable by
  any reverse engineer in seconds.
- **IV reuse**: the same IV is used for every string, breaking CBC
  semantics (same plaintext → same ciphertext, leaks patterns).
- **Deprecated API**: uses `AES_cbc_encrypt` which is deprecated in
  OpenSSL 3.0. Migration to the EVP API is tracked as future work.

A proper implementation would be `constexpr` compile-time (skCrypter-
style) with a key derived from `__TIME__` / `__COUNTER__` and never
present in the binary. This is documented as a known weakness for
transparency — a research tool should show its own limitations.

### 5. Sandbox Evasion

**Goal**: detect if the binary is running in a sandbox/analysis VM and
abort if so.

**Implementation** (`src/sandbox_check.cpp`): five checks:
1. CPU count < 2 (sandboxes often simulate few cores)
2. Total RAM < 2 GB (sandboxes limit RAM)
3. Sleep-skipping detection (sleep 1s, check if `GetTickCount` advanced
   by less than 500ms — sandboxes often accelerate sleep calls)
4. BIOS vendor contains "VMware" or "VirtualBox"
5. `Program Manager` window not found (no explorer.exe desktop)

**Honest limitations** (deliberately out of scope):
- No MAC OUI checks
- No hostname/username pattern checks (`SANDBOX`, `CUCKOO`, `MALWARE`)
- No debugger detection (`IsDebuggerPresent`,
  `NtQueryInformationProcess(ProcessDebugPort)`)
- No mouse movement sampling
- No VMware Tools / VirtualBox Guest Additions registry checks
- The `> 30000` branch (long-running check) is a no-op (dead code
  preserved from the original)

These omissions are deliberate — they cross from "research
demonstration" into "operational anti-analysis". See `CONTRIBUTING.md`.

### 6. Test Shellcode (calc.exe canary)

**Goal**: a minimal position-independent shellcode that opens `calc.exe`
as a canary to prove injection worked.

**Implementation** (`shellcode/shellcode.asm`): loader-resolved
addressing. The first 8 bytes are a placeholder patched by the loader
at runtime with the address of `WinExec` (resolved via
`GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec")`). The
code at offset 8+ uses RIP-relative addressing to load the placeholder
and call `WinExec("calc.exe", SW_SHOW)`.

**Honest limitations**:
- A more "complete" approach (PEB walking + hash lookup for WinExec,
  like Metasploit `windows/x64/exec`) would cross from "research
  demonstration" into "operational shellcode" — out of scope. The
  loader-resolved pattern keeps the shellcode simple and pushes API
  resolution to the loader.

## Framework Architecture

```
include/styxloader/    public headers (one .hpp per module)
  shellcode.hpp          ReadShellcode(), PatchShellcodeWinExec()
  sandbox_check.hpp      IsRunningInSandbox(), CheckAndAbortIfSandbox()
  direct_syscall.hpp     GetSyscallNumber(), DirectInject()
  hollow_injector.hpp    ProcessHollowing()
  simple_injector.hpp    SimpleInject()
  string_obfuscator.hpp  StringObfuscator class, OBFUSCATE_STR macro
src/                  library implementations (no main() here)
  shellcode.cpp
  sandbox_check.cpp
  direct_syscall.cpp
  hollow_injector.cpp
  simple_injector.cpp
  string_obfuscator.cpp
tools/                executables (main() lives here)
  main_loader.cpp         full orchestrator with mode dispatch
  simple_injector_tool.cpp  standalone baseline injector
modules/asm/          MASM source
  styx_syscalls.asm       direct syscall stubs
shellcode/            NASM source
  shellcode.asm           test canary (calc.exe)
docs/                 documentation
  Whitepaper.md
  test_report.md
  config_lab.md
  research_hooks.md
  detections/             Sigma rules + Sysmon delta
run_project.bat       legacy build script (CMake is recommended)
CMakeLists.txt        modern build system
```

## Test Results

**Not yet tested in lab.** See `docs/test_report.md` for the test plan
and the accounting of why previous "85% evasion rate" claims were
fabricated.

## Future Work (Conceptual)

The following techniques were considered and deliberately not
implemented because they would cross from "research demonstration"
into "operational evasion". They are documented here for completeness
and as conceptual references for future research, NOT as a roadmap:

- **Indirect syscalls** (was previously misimplemented, deleted in
  commit 2): the correct implementation would jump to a `syscall; ret`
  instruction inside `ntdll.dll` (not to an exported function),
  preserving the SSN set in `eax`. The previous implementation called
  `GetTransitionFunction` (a C++ function returning the address of
  `NtDelayExecution`) instead of jumping to the syscall instruction,
  which did not perform the desired syscall. A correct implementation
  would also need to handle the case where the `syscall; ret` gadget
  is hooked by an EDR. **Status: removed; conceptual future work
  only.**
- **SSN randomization** (Hell's Gate / Halo's Gate / Tartarus' Gate):
  randomize SSN selection to defeat EDR hook detection. Out of scope.
- **ETW/AMSI patching**: out of scope.
- **Sleep obfuscation** (Ekko): out of scope.
- **Callback-based injection** (EnumWindows, CreateTimerQueueTimer):
  out of scope.
- **Process doppelgänging / ghosting**: out of scope.
- **Compile-time string obfuscation** (skCrypter): tracked as
  legitimate future work (does not cross the line).
- **OpenSSL EVP API migration**: tracked as legitimate future work.
- **PE payload support in ProcessHollowing**: tracked as legitimate
  future work.

## Conclusion

StyxLoaderX is a research framework for studying Windows x64 process
injection. It is NOT an operational tool. It demonstrates direct
syscalls, process hollowing, simple injection, basic sandbox evasion,
and (weak) string obfuscation. Its honest limitations are documented
above. The defensive detections in `docs/detections/` are the
counterpart to the offensive techniques demonstrated here.

## References

- MalwareTech blog (syscalls, process hollowing)
- hasherezade `hollowing_experiments`
- j00ru's syscall table
- SysWhispers / SysWhispers2 / SysWhispers3 (klezVirus)
- Stephen Haunts "Process Hollowing" (2011)
- Russinovich *Windows Internals* 7th ed.
- Skape "Understanding Windows Shellcode"
- NIST SP 800-38A (CBC mode requirements)
- skCrypter (compile-time string obfuscation)
