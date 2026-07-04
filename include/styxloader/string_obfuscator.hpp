#pragma once

// String obfuscation module. Provides AES-256-CBC encryption of sensitive
// strings at rest (in the binary) and decryption on demand at runtime.
//
// Audit note: the original StringObfuscator.h had two honest weaknesses:
//   1. OBFUSCATE_STR macro evaluated Encrypt() at runtime via a global
//      constructor, leaving the plaintext literal in the .rdata section
//      of the binary (trivially findable with 'strings'). This is
//      security theater — the current version still has this issue.
//      A constexpr/compile-time implementation (skCrypter-style) is
//      tracked as future work.
//   2. AES_KEY and AES_IV were the sequential bytes 0x00..0x1F and
//      0x00..0x0F — the most predictable key/IV possible. The current
//      version retains this for research transparency, but documents
//      it as a known weakness.
//
// Limitations (intentional, scope-bounded for research):
//   - Not compile-time (plaintext appears in .rdata)
//   - Static key/IV (sequential bytes)
//   - Uses deprecated AES_cbc_encrypt (OpenSSL 3.0 EVP API migration
//     is tracked as future work)
// These are deliberate: a "honest" research tool shows its own
// limitations. A production implante would use skCrypter or equivalent.
// See CONTRIBUTING.md.

#include <openssl/aes.h>
#include <string>
#include <vector>

namespace styxloader {

class StringObfuscator {
private:
    // Renamed from AES_KEY/AES_IV to AES_KEY_BYTES/AES_IV_BYTES to avoid
    // shadowing the OpenSSL typedef AES_KEY (audit fix F7).
    static constexpr unsigned char AES_KEY_BYTES[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };  // Clave AES fija (miembro renombrado AES_KEY_BYTES para evitar
        // shadow del typedef AES_KEY de OpenSSL); en producción generar
        // dinámicamente. Sequential bytes 0x00..0x1F — known weakness.
    static constexpr unsigned char AES_IV_BYTES[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };  // IV fijo. Sequential bytes 0x00..0x0F — known weakness.

public:
    static std::vector<unsigned char> Encrypt(const std::string& input);
    static std::string Decrypt(const std::vector<unsigned char>& encrypted);
    static std::string GetDecryptedString(const std::vector<unsigned char>& encrypted);
};

// Macros for obfuscating sensitive strings (e.g. DLL/function names).
//
// WARNING: as documented above, OBFUSCATE_STR runs Encrypt() at runtime
// via a global constructor. The plaintext literal IS present in the
// binary's .rdata section. This is honest weakness — not real
// obfuscation. Use compile-time alternatives (skCrypter) for production.
#define OBFUSCATE_STR(str) styxloader::StringObfuscator::Encrypt(str)
#define DEOBFUSCATE_STR(vec) styxloader::StringObfuscator::Decrypt(vec)

// Pre-obfuscated constants (plaintext in .rdata — see warning above).
const auto OBF_KERNEL32 = OBFUSCATE_STR("kernel32.dll");
const auto OBF_NTDLL = OBFUSCATE_STR("ntdll.dll");
const auto OBF_CALC = OBFUSCATE_STR("calc.exe");

inline std::string GetKernel32() { return DEOBFUSCATE_STR(OBF_KERNEL32); }
inline std::string GetNtdll()    { return DEOBFUSCATE_STR(OBF_NTDLL); }
inline std::string GetCalc()     { return DEOBFUSCATE_STR(OBF_CALC); }

}  // namespace styxloader
