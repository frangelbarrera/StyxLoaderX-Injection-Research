# Laboratory Configuration

This document details the lab environment setup for the EDR Evasion Framework project.

## Prerequisites
- Windows 11 ISO (already downloaded).
- VirtualBox (already downloaded).
- VS Code (already downloaded).
- Internet connection for minor downloads (~100 MB total).

## Setup Steps
1. **Create VM in VirtualBox:**
   - Name: Win11Lab
   - Type: Microsoft Windows, Version: Windows 11 (64-bit)
   - RAM: 2048 MB
   - Disk: 20 GB, VDI, Dynamically allocated
   - Enable VT-x/AMD-V if available.

2. **Install Windows 11:**
   - Mount ISO and start VM.
   - Configure language, keyboard.
   - Create user: labuser (no password for simplicity in lab).
   - Disable automatic updates: Settings > Windows Update > Pause updates.

3. **Install Tools:**
   - **Sysmon:** Download from https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon. Run with high-telemetry config (search "SwiftOnSecurity sysmon config").
   - **NASM:** Download from https://www.nasm.us/. Install.
   - **x64dbg:** Download from https://x64dbg.com/. Install.

4. **Configure VS Code:**
   - Install extensions: C/C++ (ms-vscode.cpptools), Python (ms-python.python).

## Verification
- Start VM and verify Sysmon registers basic events.
- Compile a "Hello World" in C++ to confirm toolchain.

Status: Pending execution on PC with more RAM.
