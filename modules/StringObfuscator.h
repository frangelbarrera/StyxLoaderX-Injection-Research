#pragma once
#include <string>
#include <vector>
#include <openssl/aes.h>  // Requiere OpenSSL para AES
#include <openssl/rand.h>

// Clase para ofuscación de cadenas con AES-256 (más fuerte que XOR)
class StringObfuscator {
private:
    static constexpr unsigned char AES_KEY_BYTES[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    }; // Clave AES fija (miembro renombrado AES_KEY_BYTES para evitar shadow del typedef AES_KEY de OpenSSL); en producción generar dinámicamente
    static constexpr unsigned char AES_IV_BYTES[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    }; // IV fijo

public:
    // Cifrar cadena con AES
    static std::vector<unsigned char> Encrypt(const std::string& input) {
        AES_KEY key;
        AES_set_encrypt_key(AES_KEY_BYTES, 256, &key);

        std::vector<unsigned char> plaintext(input.begin(), input.end());
        size_t paddedSize = ((plaintext.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        plaintext.resize(paddedSize, 0);  // Padding simple

        std::vector<unsigned char> ciphertext(paddedSize);
        unsigned char iv[16];
        memcpy(iv, AES_IV_BYTES, 16);

        AES_cbc_encrypt(plaintext.data(), ciphertext.data(), paddedSize, &key, iv, AES_ENCRYPT);
        return ciphertext;
    }

    // Descifrar cadena con AES
    static std::string Decrypt(const std::vector<unsigned char>& encrypted) {
        AES_KEY key;
        AES_set_decrypt_key(AES_KEY_BYTES, 256, &key);

        std::vector<unsigned char> plaintext(encrypted.size());
        unsigned char iv[16];
        memcpy(iv, AES_IV_BYTES, 16);

        AES_cbc_encrypt(encrypted.data(), plaintext.data(), encrypted.size(), &key, iv, AES_DECRYPT);
        return std::string(plaintext.begin(), plaintext.end());
    }

    // Ejemplo de uso: Obtener función descifrada
    static std::string GetDecryptedString(const std::vector<unsigned char>& encrypted) {
        return Decrypt(encrypted);
    }
};

// Macros para ofuscar cadenas sensibles (ej. nombres de DLLs/funciones)
#define OBFUSCATE_STR(str) StringObfuscator::Encrypt(str)
#define DEOBFUSCATE_STR(vec) StringObfuscator::Decrypt(vec)

// Ejemplos de cadenas ofuscadas (cifrar en compile-time si posible)
const auto OBF_KERNEL32 = OBFUSCATE_STR("kernel32.dll");
const auto OBF_NTDLL = OBFUSCATE_STR("ntdll.dll");
const auto OBF_CALC = OBFUSCATE_STR("calc.exe");

// Función para obtener cadena descifrada
inline std::string GetKernel32() { return DEOBFUSCATE_STR(OBF_KERNEL32); }
inline std::string GetNtdll() { return DEOBFUSCATE_STR(OBF_NTDLL); }
inline std::string GetCalc() { return DEOBFUSCATE_STR(OBF_CALC); }