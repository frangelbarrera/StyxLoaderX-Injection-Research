# Sysmon Configuration Delta

Additions to improve detection of StyxLoaderX techniques in SwiftOnSecurity's Sysmon config.

> **Honesty note (refactor series):** The previous version of this file
> had three errors:
> 1. Used `<Rule name="..." condition="is">` wrapper inside `<RuleGroup>`,
>    which is NOT valid Sysmon schema. Sysmon uses `<RuleGroup>` with
>    direct child conditions (e.g. `<ProcessCreate onmatch="include">`
>    with `<TargetImage condition="end with">...`), not a nested `<Rule>`
>    element.
> 2. Referenced `FileBlockShashing` which does not exist in Sysmon. The
>    real features are `FileBlockExecutable`, `FileDelete`, and
>    `HashAlgorithms`.
> 3. The YARA rule for detecting direct syscall stubs had `$stub1 = { 4C 8B
>    D1 B8 ?? ?? ?? 00 F3 04 }` — the last two bytes `F3 04` are wrong.
>    The correct syscall opcode is `0F 05` (not `F3 04`). This meant
>    the YARA rule never matched anything.
>
> All three errors are fixed below.

## Process Hollowing Detection

The default SwiftOnSecurity config logs process creation (Event ID 1)
but does not specifically detect process hollowing. Add these rules to
your Sysmon config:

### Rule 1: Log process access with PROCESS_VM_WRITE

This rule fires on Sysmon Event ID 10 (ProcessAccess) when a process
requests `PROCESS_VM_WRITE` (0x20) or broader access rights on another
process. This is the access right needed for `WriteProcessMemory`,
which is used by all injection techniques.

```xml
<RuleGroup name="SuspiciousProcessAccess" groupRelation="or">
  <ProcessAccess onmatch="include">
    <!-- PROCESS_VM_WRITE (0x20) — required for WriteProcessMemory -->
    <GrantedAccess condition="is">0x20</GrantedAccess>
    <!-- PROCESS_ALL_ACCESS (0x1f0fff) — over-broad, common in research code -->
    <GrantedAccess condition="is">0x1f0fff</GrantedAccess>
    <!-- CREATE_THREAD | VM_OPERATION | VM_WRITE (0x1028) — minimum for hollowing -->
    <GrantedAccess condition="is">0x1028</GrantedAccess>
  </ProcessAccess>
</RuleGroup>
```

Note: Sysmon `<GrantedAccess>` matching is exact-equals by default. For
bitmask matching (e.g. "any access that includes PROCESS_VM_WRITE"), you
need to enumerate the specific access masks you want to alert on, OR use
a SIEM-side correlation rule. The values above cover the most common
research-code patterns.

### Rule 2: Log remote thread creation in suspicious targets

This rule fires on Sysmon Event ID 8 (CreateRemoteThread) when a remote
thread is created in a process commonly abused for injection.

```xml
<RuleGroup name="RemoteThreadSuspicious" groupRelation="or">
  <CreateRemoteThread onmatch="include">
    <TargetImage condition="end with">notepad.exe</TargetImage>
    <TargetImage condition="end with">explorer.exe</TargetImage>
    <TargetImage condition="end with">svchost.exe</TargetImage>
    <TargetImage condition="end with">calc.exe</TargetImage>
    <TargetImage condition="end with">mshta.exe</TargetImage>
    <TargetImage condition="end with">rundll32.exe</TargetImage>
    <TargetImage condition="end with">regsvr32.exe</TargetImage>
  </CreateRemoteThread>
</RuleGroup>
```

Note: this catches the Simple mode of StyxLoaderX but NOT the Direct or
Hollow modes (Direct uses `NtCreateThreadEx` via direct syscall which
does not trigger Event ID 8 in userland-hooked Sysmon; Hollow uses
`ResumeThread` on an existing suspended thread).

## Detecting Direct Syscalls

Direct syscalls bypass Sysmon's userland hooks because they do not call
the ntdll.dll exported functions that Sysmon instruments. To detect
direct syscalls:

1. **ETW (Event Tracing for Windows)** — Use the
   `Microsoft-Windows-Kernel-Process` ETW provider, which logs at the
   kernel level and is not bypassable via userland syscalls. This is
   the most reliable detection.

2. **Sysmon v15+ `FileBlockExecutable`** (NOT `FileBlockShashing` which
   does not exist) — Can flag binaries with suspicious characteristics.
   However, this is name-based, not content-based, so it is not useful
   for detecting direct syscall stubs specifically.

3. **Custom EDR with kernel callbacks** —
   `PsSetCreateProcessNotifyRoutine` (process creation),
   `PsSetCreateThreadNotifyRoutine` (thread creation),
   `ObRegisterCallbacks` (handle creation) are kernel-level and cannot
   be bypassed by userland direct syscalls. This is what commercial
   EDRs use.

4. **Static analysis — YARA rules** to flag binaries containing direct
   syscall stub patterns. The rule below is CORRECTED (the previous
   version had `F3 04` instead of `0F 05` for the syscall opcode):

```yara
rule Direct_Syscall_Stub {
    meta:
        description = "Detects direct syscall stub pattern in PE files"
        author = "Frangel Barrera"
        date = "2026-07-04"
        note = "Matches the standard Win10/11 ntdll syscall stub: mov r10, rcx; mov eax, SSN; syscall; ret"
    strings:
        // mov r10, rcx (49 8B D1) + mov eax, imm32 (B8 ?? ?? ?? ??) + syscall (0F 05)
        $stub = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }
    condition:
        $stub
}
```

The pattern `4C 8B D1 B8 ?? ?? ?? ?? 0F 05` is what the StyxLoaderX MASM
stubs in `modules/asm/styx_syscalls.asm` produce (modulo the SSN being
loaded from a global instead of an immediate — the actual stub uses
`mov eax, [rip+disp32]` instead of `mov eax, imm32`, so the YARA rule
will NOT match StyxLoaderX's own stubs). The rule matches the STANDARD
ntdll syscall stub pattern, which is what StyxLoaderX parses via
`GetSyscallNumber()`.

To match StyxLoaderX's own stubs (which load SSN from a global), the
pattern would be:
`49 8B D1` (mov r10, rcx) + `8B 05 ?? ?? ?? ??` (mov eax, [rip+disp32])
+ `0F 05` (syscall) + `C3` (ret). Adding this as a second string would
catch StyxLoaderX-derived binaries specifically:

```yara
rule StyxLoaderX_Syscall_Stub {
    meta:
        description = "Detects StyxLoaderX-specific MASM syscall stub pattern"
        author = "Frangel Barrera"
        date = "2026-07-04"
    strings:
        // mov r10, rcx + mov eax, [rip+disp32] + syscall + ret
        $styx_stub = { 4C 8B D1 8B 05 ?? ?? ?? ?? 0F 05 C3 }
    condition:
        $styx_stub
}
```

## Verification

After applying these rules, run StyxLoaderX in your lab VM:

- **Simple mode** → should trigger Event ID 8 (CreateRemoteThread)
  + Event ID 10 (ProcessAccess with GrantedAccess 0x20 or broader).
- **Direct mode** → may NOT trigger Event ID 8 (direct syscalls bypass
  the userland hook on `NtCreateThreadEx`). Use ETW or kernel EDR.
  Event ID 10 MAY still fire on the `OpenProcess` call (which uses the
  Win32 export, not a direct syscall, in the current implementation).
- **Hollow mode** → should trigger Event ID 1 (process creation, with
  the spawned process in suspended state) + Event ID 10 (ProcessAccess
  on the suspended process).

Tune the rules based on your environment's false positive rate.
