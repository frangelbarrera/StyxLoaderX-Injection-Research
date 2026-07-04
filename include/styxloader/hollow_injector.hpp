#pragma once

// Process hollowing module. Creates a legitimate process in suspended
// state, unmaps its original image, allocates a new region, writes the
// payload, patches the thread context to redirect entry, and resumes.
//
// Audit note: the original HollowInjector.cpp had two critical bugs:
//   1. Read the image base from ctx.Rdx instead of PEB.ImageBaseAddress
//      (which must be obtained via ReadProcessMemory from ctx.Rcx + 0x10).
//   2. Set ctx.Rcx to redirect the entry point instead of ctx.Rip.
// Both are fixed in src/hollow_injector.cpp. The PEB.ImageBaseAddress
// patch (WriteProcessMemory to ctx.Rcx + 0x10 with the new base) is
// also added for correctness, though for raw shellcode payloads it is
// a no-op (only relevant for full PE payloads).
//
// Limitations (intentional, scope-bounded for research):
//   - No EPA (Entry Point Obscuration)
//   - No phantom DLL hollowing
//   - No transacted hollowing
// These omissions are deliberate: they cross from "research demonstration"
// into "operational injection". See CONTRIBUTING.md.

#include <windows.h>

namespace styxloader {

// Performs process hollowing of targetExe with the shellcode read from
// shellcodePath.
//
// targetExe    - path to a legitimate executable to hollow (e.g.
//                "C:\\Windows\\System32\\notepad.exe").
// shellcodePath - path to a .bin file containing raw shellcode bytes.
//
// Returns true on success, false on any failure. On failure, the spawned
// suspended process is terminated and its handles are closed.
bool ProcessHollowing(const char* targetExe, const char* shellcodePath);

}  // namespace styxloader
