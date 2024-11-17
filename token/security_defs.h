#ifndef SECURITY_DEFS_H
#define SECURITY_DEFS_H

#include "types.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sodium.h>
#include <sodium/crypto_kdf.h>
#include <sodium/crypto_auth.h>

// Encryption Definitions
#define BUFFER_SIZE 4096
#define IV_SIZE 16
#define KEY_SIZE 32
#define TOKEN_SIZE 37
#define HASH_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)

// Storage Definitions
#define STORAGE_PATH "./secure_storage/"
#define KEY_FILE_PATH "./secure_storage/master.key"
#define MAX_PATH_LEN 4096
#define MIN_TOKEN_LEN 32

// Chunking Definitions
#define MIN_CHUNK_SIZE (5 * 1024 * 1024)  // 5MB
#define MAX_CHUNK_SIZE (10 * 1024 * 1024) // 10MB
#define MAX_CHUNKS 1500                    // Maximum number of chunks per file

#define METADATA_MAGIC 0x4D455441  // "META" in hex
#define SECURE_WIPE(ptr, len) sodium_memzero(ptr, len)

// Complete SecureMetadata definition
struct SecureMetadata {
    char token[TOKEN_SIZE];
    size_t data_size;
    unsigned char iv[IV_SIZE];
    char original_filename[256];
    size_t chunk_count;
    char chunk_hashes[MAX_CHUNKS][HASH_SIZE];
    size_t chunk_sizes[MAX_CHUNKS];
    unsigned char key_salt[crypto_kdf_KEYBYTES];
    uint32_t version;
    unsigned char hmac[crypto_auth_BYTES];
};

// Help text definition
#define HELP_TEXT \
    "Usage:\n" \
    "To store with auto-generated key:\n" \
    "  %s store <filepath>\n" \
    "To store with existing key:\n" \
    "  %s store <filepath> --key <keypath>\n" \
    "To retrieve:\n" \
    "  %s retrieve <token> <output_path> [--key <keypath>]\n" \
    "To generate a new master key:\n" \
    "  %s generate-key <output_keypath>\n"

// Function declaration
void secure_wipe(void* ptr, size_t len);

#endif // SECURITY_DEFS_H