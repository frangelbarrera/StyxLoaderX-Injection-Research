#pragma once

// Direct syscall module. Resolves syscall service numbers (SSNs) at runtime
// by parsing the ntdll stubs, then invokes the kernel via the 'syscall'
// instruction directly, bypassing the ntdll exported function pointers
// (which are the typical EDR hook points).
//
// Audit note: the original DirectSyscall.cpp used MSVC inline __asm blocks
// which (a) are not supported on MSVC x64 and (b) contained 'mov rdx, rdx'
// / 'mov r8, r8' / 'mov r9, r9' NOPs that failed to load any actual
// arguments into the syscall-ABI registers. This header declares the
// intended public API; the implementation in src/direct_syscall.cpp uses
// a separate MASM stub (modules/asm/styx_syscalls.asm) to perform the
// actual syscall with correct argument marshalling.
//
// Limitations (intentional, scope-bounded for research):
//   - No SSN randomization (Hell's Gate / Halo's Gate / Tartarus' Gate)
//   - No hook detection on the parsed ntdll stubs
//   - No ETW/AMSI patching
// These omissions are deliberate: they cross from "research demonstration"
// into "operational EDR evasion". See CONTRIBUTING.md.

#include <windows.h>

namespace styxloader {

// Resolves the syscall service number for the given ntdll export name
// (e.g. "NtAllocateVirtualMemory"). Parses the first 50 bytes of the
// stub looking for the pattern 'mov eax, imm32; syscall' (B8 ?? ?? ?? ??
// 0F 05). Returns 0 if the pattern is not found (caller must treat 0 as
// failure — SSN 0 is NtAccessCheck, which is not what we want).
//
// Note: 0 as failure is a known design wart (a real SSN could be 0 in
// theory). For research code this is acceptable; production code should
// return std::optional<DWORD> or use an out-param.
ULONG GetSyscallNumber(const char* syscallName);

// Injects shellcode into a target process using direct syscalls
// (NtAllocateVirtualMemory + NtWriteVirtualMemory + NtCreateThreadEx).
//
// hProcess  - open handle to the target process with PROCESS_VM_OPERATION
//             | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD rights.
// shellcode - pointer to the shellcode bytes.
// size      - number of bytes.
//
// Returns true on success, false on any NTSTATUS != 0 from any of the
// three syscalls. The remote thread is waited on (INFINITE) before
// returning.
//
// Audit note: the previous version had undefined behavior in the syscall
// path (uninitialized hThread, no argument marshalling). The current
// version uses a MASM stub that correctly sets up r10/rcx, rdx, r8, r9
// and the stack for args 5+.
bool DirectInject(HANDLE hProcess, PVOID shellcode, SIZE_T size);

}  // namespace styxloader
