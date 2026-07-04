# Defensive Detections

This directory contains Sigma rules and Sysmon configuration guidance to detect the evasion techniques demonstrated in this repository.

## Purpose

Every offensive technique in this repo has a corresponding defensive detection. This is the core principle of the project: **understanding evasion to build better detection**.

## Files

| File | Detects | MITRE ATT&CK |
|------|---------|--------------|
| `sigma-process-hollowing.yml` | Process Hollowing via CreateProcessA(CREATE_SUSPENDED) + ZwUnmapViewOfSection | T1055.012 |
| `sigma-remote-thread-injection.yml` | CreateRemoteThread injection (Simple mode) | T1055.001 |
| `sysmon-config-delta.md` | Sysmon configuration additions to improve detection coverage | — |

## How to Use

### Sigma Rules

Sigma is a generic signature format for log events. These rules can be converted to:

- **Splunk SPL** — via [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools)
- **Elastic Lucene/KQL** — via sigmac
- **Microsoft Sentinel KQL** — via sigmac
- **QRadar AQL** — via sigmac

Quick start:
```bash
# Install sigmac
pip install pysigma

# Convert to Splunk SPL
sigmac -t splunk -c tools/config/splunk-windows.yml sigma-process-hollowing.yml

# Convert to Elastic KQL
sigmac -t kibana -c tools/config/kibana-windows.yml sigma-process-hollowing.yml
```

### Sysmon Config Delta

See `sysmon-config-delta.md` for additions to your Sysmon configuration that improve detection of the techniques in this repo.

## Limitations

- **Direct syscalls** (used in Direct mode) bypass Sysmon's userland hooks. These rules detect behavioral patterns, not the syscalls themselves. For deeper visibility, use ETW (Event Tracing for Windows) or an EDR with kernel-level telemetry.
- **Process Hollowing** detection relies on sequence analysis (process creation → memory write → thread resume). Tune the timeframe based on your environment.
- **False positives** are possible with legitimate process hollowing (e.g., some antivirus engines, .NET CLR). Test in your environment before production deployment.

## Contributing

When adding a new evasion technique to the modules, also add a corresponding Sigma rule here. See CONTRIBUTING.md in the repo root.
