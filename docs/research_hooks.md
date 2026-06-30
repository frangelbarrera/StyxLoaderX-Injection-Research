# Userland Hooking Research

This document summarizes research on how EDRs implement userland hooks on Windows, based on documentation and examples from GitHub repositories such as klezVirus/inceptor and references to "Bypassing Userland EDR Hooks".

## What is Userland Hooking?
EDRs (Endpoint Detection and Response) inject a DLL into target processes (using techniques such as APC or thread hijacking). This DLL modifies the first instructions of key functions in ntdll.dll and kernel32.dll (e.g., NtWriteVirtualMemory, CreateRemoteThread) to insert a "jump" (JMP) to its own monitoring code. This allows intercepting calls to Windows APIs and detecting malicious behaviors such as code injection.

- **Mechanism:** The hooked DLL replaces functions by patching the first bytes with a JMP to a trampoline function that logs the call and then executes the original code.
- **Detection limitation:** Hooks live in the userland API layer, not in the kernel, which makes them vulnerable to evasion.

## How to Evade It
- **Direct Syscalls:** Call the kernel directly (ntoskrnl.exe) using syscalls (e.g., NtAllocateVirtualMemory) instead of going through hooked APIs. Hooks only affect ntdll.dll exported functions.
- **Indirect Syscalls:** Use the stack for legitimate transitions, complicating call analysis.
- **Research Tools:** x64dbg for memory inspection and disassembly; Process Explorer to view injected DLLs.

## Initial Findings
- On Windows 10/11 x64, syscalls use a syscall number (e.g., 0x18 for NtAllocateVirtualMemory) obtained dynamically.
- GitHub examples show how to map syscalls and call them with inline ASM.
- Risk: Syscalls vary by Windows build; use dynamic tables.

Next: Implement DirectSyscall.cpp module based on this research.
