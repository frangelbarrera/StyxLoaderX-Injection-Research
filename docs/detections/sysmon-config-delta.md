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
