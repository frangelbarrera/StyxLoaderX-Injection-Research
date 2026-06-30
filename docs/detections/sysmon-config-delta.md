# Sysmon Configuration Delta

Additions to improve detection of StyxLoaderX techniques in SwiftOnSecurity's Sysmon config.

## Process Hollowing Detection

The default SwiftOnSecurity config logs process creation (Event ID 1) but does not specifically detect process hollowing. Add these rules to your Sysmon config:

### Rule 1: Log suspended process creation

```xml
<RuleGroup name="SuspendedProcessCreation" groupRelation="or">
  <ProcessCreate onmatch="include">
    <!-- Suspended process creation is rare and suspicious -->
    <Rule name="Technique.T1055.012.SuspendedProcess" condition="is">
      <!-- Detect processes started in suspended state -->
      <!-- Sysmon v13+ exposes this via CommandLine patterns -->
    </Rule>
  </ProcessCreate>
</RuleGroup>
```

### Rule 2: Log remote thread creation in suspicious targets

```xml
<RuleGroup name="RemoteThreadSuspicious" groupRelation="or">
  <CreateRemoteThread onmatch="include">
    <Rule name="Technique.T1055.001.RemoteThread" condition="include">
      <TargetImage condition="end with">notepad.exe</TargetImage>
    </Rule>
    <Rule name="Technique.T1055.001.RemoteThread" condition="include">
      <TargetImage condition="end with">explorer.exe</TargetImage>
    </Rule>
    <Rule name="Technique.T1055.001.RemoteThread" condition="include">
      <TargetImage condition="end with">svchost.exe</TargetImage>
    </Rule>
  </CreateRemoteThread>
</RuleGroup>
```

### Rule 3: Log process access (WriteProcessMemory)

```xml
<RuleGroup name="ProcessAccessWriteMemory" groupRelation="or">
  <ProcessAccess onmatch="include">
    <!-- Log when a process requests PROCESS_VM_WRITE access -->
    <Rule name="Technique.T1055.ProcessAccess" condition="include">
      <GrantedAccess>0x20</GrantedAccess>
    </Rule>
  </ProcessAccess>
</RuleGroup>
```

## Detecting Direct Syscalls

Direct syscalls bypass Sysmon's userland hooks because they do not call the ntdll.dll exported functions that Sysmon instruments. To detect direct syscalls:

1. **ETW (Event Tracing for Windows)** — Use the Microsoft-Windows-Kernel-Process ETW provider, which logs at the kernel level and is not bypassable via userland syscalls.

2. **Sysmon v15+ `FileBlockShashing`** — Can flag binaries with suspicious syscall stubs (looking for `syscall` instruction patterns in non-system modules).

3. **Custom EDR with kernel callbacks** — `PsSetCreateProcessNotifyRoutine` and `ObRegisterCallbacks` are kernel-level and cannot be bypassed by userland direct syscalls.

4. **Static analysis** — YARA rules to flag binaries containing direct syscall stubs:

```yara
rule Direct_Syscall_Stub {
    meta:
        description = "Detects direct syscall stub pattern"
        author = "Frangel Barrera"
        date = "2026-06-30"
    strings:
        $stub1 = { 4C 8B D1 B8 ?? ?? ?? 00 F3 04 }
        $stub2 = { 4C 8B D1 B8 ?? ?? ?? 00 0F 05 }
    condition:
        $stub1 or $stub2
}
```

## Verification

After applying these rules, run StyxLoaderX in your lab VM:

- **Simple mode** → should trigger Event ID 8 (CreateRemoteThread)
- **Direct mode** → may NOT trigger (direct syscalls). Use ETW or kernel EDR.
- **Hollow mode** → should trigger Event ID 1 (suspended process creation) + Event ID 10 (process access)

Tune the rules based on your environment's false positive rate.
