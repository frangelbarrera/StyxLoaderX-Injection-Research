#include "styxloader/shellcode.hpp"

#include <fstream>

namespace styxloader {

std::vector<unsigned char> ReadShellcode(const char* filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<unsigned char>(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
}

}  // namespace styxloader
