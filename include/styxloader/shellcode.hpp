#pragma once

// Shared shellcode-reading and patching utilities. Used by all injection
// modules to avoid the previous duplication (ReadShellcode was copy-pasted
// in 3 places in the old repo).
//
// Audit note: this header centralizes:
//   - ReadShellcode(): reads a .bin file into a byte vector.
//   - PatchShellcodeWinExec(): patches the first 8 bytes of the shellcode
//     with the runtime-resolved address of WinExec. Required by the new
//     shellcode.asm (commit 6) which uses loader-resolved addressing
//     instead of a hardcoded WinExec address (audit fix F13).

#include <string>
#include <vector>

namespace styxloader {

// Reads a file as raw bytes. Returns an empty vector on any error
// (file not found, read error, empty file). Callers should check .empty()
// before using the result.
std::vector<unsigned char> ReadShellcode(const char* filename);

// Patches the first 8 bytes of `shellcode` with the runtime address of
// WinExec, resolved via GetProcAddress(GetModuleHandleA("kernel32.dll"),
// "WinExec"). This is the loader-side half of the loader-resolved
// shellcode pattern (see shellcode/shellcode.asm).
//
// Returns true on success. On failure (kernel32 not loaded, WinExec not
// found, or shellcode buffer smaller than 8 bytes), returns false and
// leaves the shellcode unchanged.
//
// After this call, the shellcode is ready to be injected — the first 8
// bytes are the WinExec address, and the code at offset 8+ reads those
// bytes via RIP-relative addressing and calls WinExec("calc.exe", SW_SHOW).
bool PatchShellcodeWinExec(std::vector<unsigned char>& shellcode);

}  // namespace styxloader
