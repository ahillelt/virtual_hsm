// security_defs.h
#ifndef SECURITY_DEFS_H
#define SECURITY_DEFS_H

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

typedef struct {
    int code;
    char message[256];
} SecurityError;

// Function declaration
void secure_wipe(void* ptr, size_t len);

#endif // SECURITY_DEFS_H