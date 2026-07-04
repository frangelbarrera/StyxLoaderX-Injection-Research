#include "styxloader/string_obfuscator.hpp"

#include <cstring>

namespace styxloader {

// Out-of-line definitions for the static constexpr members.
// Required by the One Definition Rule when they're ODR-used (e.g. passed
// to AES_set_encrypt_key). MSVC is permissive here, but g++/clang in
// pedantic mode require these.
constexpr unsigned char StringObfuscator::AES_KEY_BYTES[32];
constexpr unsigned char StringObfuscator::AES_IV_BYTES[16];

std::vector<unsigned char> StringObfuscator::Encrypt(const std::string& input) {
    AES_KEY key;
    AES_set_encrypt_key(AES_KEY_BYTES, 256, &key);

    std::vector<unsigned char> plaintext(input.begin(), input.end());
    size_t paddedSize = ((plaintext.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    plaintext.resize(paddedSize, 0);  // Padding simple (null bytes — known weakness)

    std::vector<unsigned char> ciphertext(paddedSize);
    unsigned char iv[16];
    memcpy(iv, AES_IV_BYTES, 16);

    AES_cbc_encrypt(plaintext.data(), ciphertext.data(), paddedSize, &key, iv, AES_ENCRYPT);
    return ciphertext;
}

std::string StringObfuscator::Decrypt(const std::vector<unsigned char>& encrypted) {
    AES_KEY key;
    AES_set_decrypt_key(AES_KEY_BYTES, 256, &key);

    std::vector<unsigned char> plaintext(encrypted.size());
    unsigned char iv[16];
    memcpy(iv, AES_IV_BYTES, 16);

    AES_cbc_encrypt(encrypted.data(), plaintext.data(), encrypted.size(), &key, iv, AES_DECRYPT);
    return std::string(plaintext.begin(), plaintext.end());
}

std::string StringObfuscator::GetDecryptedString(const std::vector<unsigned char>& encrypted) {
    return Decrypt(encrypted);
}

}  // namespace styxloader
