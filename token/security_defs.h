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
#define TOKEN_SIZE 37
#define BUFFER_SIZE 8192
#define SUCCESS 0

#define KEY_SIZE 32
#define IV_SIZE 12  // For GCM mode
#define TAG_SIZE 16
#define MAX_ERROR_MSG 256
#define HASH_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)

// Security settings
#define SECURE_PERMISSIONS 0600  // Owner read/write only
#define MAX_KEY_ATTEMPTS 3
#define KEY_ITERATION_COUNT 100000  // For key derivation
#define SALT_SIZE 32

// Storage Definitions
#define STORAGE_PATH "./secure_storage/"
#define KEY_FILE_PATH "./secure_storage/master.key"
#define MAX_PATH_LEN 4096
#define MIN_TOKEN_LEN 32
#define MAX_FILENAME_LENGTH 256

// Chunking Definitions
#define MIN_CHUNK_SIZE (1 * 1024 * 1024)   // 1MB min chunk size
#define MAX_CHUNK_SIZE (50 * 1024 * 1024)  // 5MB max chunk size
#define MAX_CHUNKS 2048                    // Maximum number of chunks per file

#define METADATA_MAGIC 0x4D455441  // "META" in hex
#define SECURE_WIPE(ptr, len) sodium_memzero(ptr, len)

#define CONTEXT_INFO "FILE_ENCRYPTION_2024_V1"

// Configuration constants
#define MAX_FAILED_ATTEMPTS 3
#define OPERATION_TIMEOUT_SECONDS 300
#define LOG_BUFFER_SIZE 1024

// Rate limiting
#define RATE_LIMIT_INTERVAL 60  // seconds
#define MAX_OPERATIONS_PER_INTERVAL 10

// Complete SecureMetadata definition
typedef struct SecureMetadata {
    char token[TOKEN_SIZE];
    size_t data_size;        //  just data
    size_t file_size;         // total
    size_t chunk_count;
    char original_filename[MAX_FILENAME_LENGTH];
    char chunk_hashes[MAX_CHUNKS][HASH_SIZE];
    size_t chunk_sizes[MAX_CHUNKS];
    unsigned char iv[IV_SIZE];
    unsigned char key_salt[SALT_SIZE];
    uint32_t version;
    unsigned char hmac[crypto_auth_BYTES];
} SecureMetadata;


// Help text definition
#define HELP_TEXT \
    "Usage:\n" \
    "  %s [store|retrieve|generate-key] [options]\n\n" \
    "Options:\n" \
    "  store <filepath>            Store a file\n" \
    "    --key <keypath>           Optional: specify a key file\n" \
    "  retrieve <token> <output>   Retrieve a stored file\n" \
    "    --key <keypath>           Optional: specify a key file\n" \
    "  generate-key <output_path>  Generate a new master key\n" \
    "  --debug                     Enable debug output\n" \
    "  --silent                    Suppress output messages\n"

// Function declaration
void secure_wipe(void* ptr, size_t len);

#endif // SECURITY_DEFS_H