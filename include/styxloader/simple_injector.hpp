#pragma once

// Simple CreateRemoteThread injection. The most basic and most-detected
// injection technique — kept for educational comparison against the
// direct-syscall and hollowing modes. Will be detected by any EDR via
// CreateRemoteThread monitoring (Sysmon Event ID 8).
//
// Audit note: no behavioral bugs in the original SimpleInjector.cpp.
// Only missing #include <vector> (fixed in commit 1).

#include <windows.h>

namespace styxloader {

// Injects shellcode into a target process via the classic
// OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
// sequence.
//
// hProcess  - open handle to target with PROCESS_VM_OPERATION |
//             PROCESS_VM_WRITE | PROCESS_CREATE_THREAD rights.
// shellcode - pointer to shellcode bytes.
// size      - number of bytes.
//
// Returns true on success. The remote thread is waited on (INFINITE)
// before returning. On failure, any allocated remote memory is freed
// and the process handle is left to the caller to close.
bool SimpleInject(HANDLE hProcess, PVOID shellcode, SIZE_T size);

}  // namespace styxloader
