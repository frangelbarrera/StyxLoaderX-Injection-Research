#pragma once

// Shared shellcode-reading utility. Used by all injection modules to avoid
// the previous duplication (ReadShellcode was copy-pasted in 3 places).
//
// Audit note: the old repo had three identical copies of this function
// (HollowInjector.cpp, SimpleInjector.cpp, and inline in MainLoader.cpp).
// This header centralizes it.

#include <string>
#include <vector>

namespace styxloader {

// Reads a file as raw bytes. Returns an empty vector on any error
// (file not found, read error, empty file). Callers should check .empty()
// before using the result.
std::vector<unsigned char> ReadShellcode(const char* filename);

}  // namespace styxloader
