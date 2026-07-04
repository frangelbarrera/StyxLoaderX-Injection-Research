#pragma once

// Sandbox evasion module. Performs basic anti-analysis checks at startup
// and aborts the process if a sandbox/VM environment is detected.
//
// Audit note: the original SandboxCheck.cpp had 5 checks (CPU count,
// RAM size, sleep-skipping detection, BIOS vendor VM strings, Program
// Manager window). Those checks are preserved. The dead branch in Check 3
// (empty 'if' body when execution time > 30s) is fixed in a separate commit.
//
// Limitations (intentional, scope-bounded for research):
//   - No MAC OUI checks
//   - No hostname/username pattern checks
//   - No debugger detection (IsDebuggerPresent, NtQueryInformationProcess)
//   - No mouse movement sampling
// These omissions are deliberate: they cross from "research demonstration"
// into "operational anti-analysis". See CONTRIBUTING.md.

namespace styxloader {

// Returns true if the current process appears to be running in a sandbox
// or analysis VM. Implements the checks described above.
bool IsRunningInSandbox();

// Calls IsRunningInSandbox(); if true, prints a message and calls
// ExitProcess(0). This is the main entry point used by MainLoader at startup.
void CheckAndAbortIfSandbox();

}  // namespace styxloader
