#ifndef HSM_SECURITY_H
#define HSM_SECURITY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Security Configuration
#define AUDIT_LOG_FILE "hsm_audit.log"
#define KEY_ROTATION_DAYS 90
#define MAX_KEY_AGE_DAYS 365
#define MAX_FAILED_AUTH_ATTEMPTS 3
#define SESSION_TIMEOUT_SECONDS 3600

// Audit log encryption constants
#define AUDIT_IV_SIZE 12
#define AUDIT_TAG_SIZE 16
#define AUDIT_MAGIC "VHSMAUD1"
#define AUDIT_MAGIC_SIZE 8

// Metadata encryption constants
#define METADATA_IV_SIZE 12
#define METADATA_TAG_SIZE 16
#define METADATA_MAGIC "VHSMMETA"
#define METADATA_MAGIC_SIZE 8

// Key Lifecycle States
typedef enum {
    KEY_STATE_ACTIVE = 0,
    KEY_STATE_DEPRECATED = 1,
    KEY_STATE_COMPROMISED = 2,
    KEY_STATE_DESTROYED = 3,
    KEY_STATE_PRE_ACTIVE = 4
} KeyState;

// Audit Event Types
typedef enum {
    AUDIT_KEY_CREATED = 0,
    AUDIT_KEY_ACCESSED = 1,
    AUDIT_KEY_MODIFIED = 2,
    AUDIT_KEY_DELETED = 3,
    AUDIT_KEY_ROTATED = 4,
    AUDIT_AUTH_SUCCESS = 5,
    AUDIT_AUTH_FAILURE = 6,
    AUDIT_SIGN_OPERATION = 7,
    AUDIT_VERIFY_OPERATION = 8,
    AUDIT_ENCRYPTION = 9,
    AUDIT_DECRYPTION = 10,
    AUDIT_CONFIG_CHANGE = 11,
    AUDIT_SECURITY_VIOLATION = 12
} AuditEventType;

// Key Metadata for Lifecycle Management
typedef struct {
    char key_name[50];
    time_t created_at;
    time_t last_used;
    time_t last_rotated;
    KeyState state;
    int use_count;
    int rotation_version;
    unsigned char checksum[SHA256_DIGEST_LENGTH];
} KeyMetadata;

// Audit Log Entry
typedef struct {
    time_t timestamp;
    AuditEventType event_type;
    char key_name[50];
    char user_id[64];
    char details[256];
    int success;
} AuditLogEntry;

// Access Control Entry
typedef struct {
    char user_id[64];
    char key_pattern[50];
    int can_read;
    int can_write;
    int can_delete;
    int can_sign;
} AccessControlEntry;

// Function Prototypes

// Audit Logging
int init_audit_log(void);
int write_audit_log(AuditEventType event_type, const char *key_name,
                    const char *user_id, const char *details, int success);
int get_audit_logs(AuditLogEntry *entries, int max_entries, time_t start_time, time_t end_time);

// Key Lifecycle Management
int init_key_metadata(const char *key_name, KeyMetadata *metadata);
int save_key_metadata(const KeyMetadata *metadata);
int load_key_metadata(const char *key_name, KeyMetadata *metadata);
int update_key_usage(const char *key_name);
int check_key_rotation_needed(const char *key_name);
int rotate_key(const char *key_name, const char *user_id);
int deprecate_key(const char *key_name, const char *user_id);
int destroy_key(const char *key_name, const char *user_id);

// Access Control
int check_access(const char *user_id, const char *key_name, const char *operation);
int add_access_control(const AccessControlEntry *ace);
int remove_access_control(const char *user_id, const char *key_pattern);

// Secure Memory Management
void* secure_malloc(size_t size);
void secure_free(void *ptr, size_t size);
void secure_memzero(void *ptr, size_t size);
int lock_memory_pages(void);

// Key Protection
int encrypt_key_in_memory(unsigned char *key, size_t key_len);
int decrypt_key_in_memory(unsigned char *encrypted_key, size_t key_len);

// Implementation

// Audit encryption key (exported for audit log decryption)
unsigned char audit_enc_key[32] = {0};
int audit_enc_key_initialized = 0;

// Initialize audit encryption key (exported for audit log decryption)
void init_audit_encryption_key(void) {
    if (audit_enc_key_initialized) {
        return;
    }

    // Derive key using PBKDF2 with proper random salt
    // Read salt from secure location or generate if not exists
    unsigned char salt[32];
    const char *salt_file = ".vhsm_audit_salt";
    FILE *sf = fopen(salt_file, "rb");

    if (sf) {
        if (fread(salt, 1, sizeof(salt), sf) != sizeof(salt)) {
            fprintf(stderr, "Warning: Failed to read audit salt, generating new\n");
            if (RAND_bytes(salt, sizeof(salt)) != 1) {
                fprintf(stderr, "FATAL: Cannot generate random salt\n");
                exit(1);
            }
        }
        fclose(sf);
    } else {
        // Generate new random salt
        if (RAND_bytes(salt, sizeof(salt)) != 1) {
            fprintf(stderr, "FATAL: Cannot generate random salt\n");
            exit(1);
        }

        // Save salt for future use
        sf = fopen(salt_file, "wb");
        if (sf) {
            fwrite(salt, 1, sizeof(salt), sf);
            fclose(sf);
            chmod(salt_file, 0600);
        }
    }

    // Use PBKDF2 with high iteration count
    const char *password = "VHSM_AUDIT_KEY_V2";
    PKCS5_PBKDF2_HMAC(password, strlen(password),
                      salt, sizeof(salt),
                      100000,  // 100k iterations
                      EVP_sha256(),
                      32, audit_enc_key);

    audit_enc_key_initialized = 1;
}

// Encrypt audit entry
static int encrypt_audit_entry(const unsigned char *plaintext, size_t plaintext_len,
                               unsigned char *ciphertext, size_t *ciphertext_len,
                               unsigned char *iv, unsigned char *tag) {
    init_audit_encryption_key();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (RAND_bytes(iv, AUDIT_IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, audit_enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    size_t total_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AUDIT_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Static metadata encryption key
static unsigned char metadata_enc_key[32] = {0};
static int metadata_enc_key_initialized = 0;

// Initialize metadata encryption key
static void init_metadata_encryption_key(void) {
    if (metadata_enc_key_initialized) {
        return;
    }

    // Derive key using PBKDF2 with proper random salt
    unsigned char salt[32];
    const char *salt_file = ".vhsm_metadata_salt";
    FILE *sf = fopen(salt_file, "rb");

    if (sf) {
        if (fread(salt, 1, sizeof(salt), sf) != sizeof(salt)) {
            fprintf(stderr, "Warning: Failed to read metadata salt, generating new\n");
            if (RAND_bytes(salt, sizeof(salt)) != 1) {
                fprintf(stderr, "FATAL: Cannot generate random salt\n");
                exit(1);
            }
        }
        fclose(sf);
    } else {
        // Generate new random salt
        if (RAND_bytes(salt, sizeof(salt)) != 1) {
            fprintf(stderr, "FATAL: Cannot generate random salt\n");
            exit(1);
        }

        // Save salt for future use
        sf = fopen(salt_file, "wb");
        if (sf) {
            fwrite(salt, 1, sizeof(salt), sf);
            fclose(sf);
            chmod(salt_file, 0600);
        }
    }

    // Use PBKDF2 with high iteration count
    const char *password = "VHSM_METADATA_KEY_V2";
    PKCS5_PBKDF2_HMAC(password, strlen(password),
                      salt, sizeof(salt),
                      100000,  // 100k iterations
                      EVP_sha256(),
                      32, metadata_enc_key);

    metadata_enc_key_initialized = 1;
}

// Encrypt metadata
static int encrypt_metadata(const unsigned char *plaintext, size_t plaintext_len,
                            unsigned char *ciphertext, size_t *ciphertext_len,
                            unsigned char *iv, unsigned char *tag) {
    init_metadata_encryption_key();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (RAND_bytes(iv, METADATA_IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, metadata_enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    size_t total_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, METADATA_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Decrypt metadata
static int decrypt_metadata(const unsigned char *ciphertext, size_t ciphertext_len,
                            unsigned char *plaintext, size_t *plaintext_len,
                            const unsigned char *iv, const unsigned char *tag) {
    init_metadata_encryption_key();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, metadata_enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    size_t total_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, METADATA_TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Error: Metadata authentication failed (tampered or corrupted)\n");
        return -1;
    }
    total_len += len;

    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Initialize audit log
int init_audit_log(void) {
    FILE *log = fopen(AUDIT_LOG_FILE, "ab");
    if (!log) {
        fprintf(stderr, "Error: Cannot initialize audit log\n");
        return 0;
    }

    // Write magic header if file is empty
    fseek(log, 0, SEEK_END);
    if (ftell(log) == 0) {
        fwrite(AUDIT_MAGIC, 1, AUDIT_MAGIC_SIZE, log);
    }
    fclose(log);

    // Set secure permissions
    chmod(AUDIT_LOG_FILE, 0600);
    return 1;
}

// Write audit log entry
int write_audit_log(AuditEventType event_type, const char *key_name,
                    const char *user_id, const char *details, int success) {
    // Create audit entry struct
    AuditLogEntry entry;
    entry.timestamp = time(NULL);
    entry.event_type = event_type;
    entry.success = success;

    // Copy strings safely
    if (key_name) {
        strncpy(entry.key_name, key_name, sizeof(entry.key_name) - 1);
        entry.key_name[sizeof(entry.key_name) - 1] = '\0';
    } else {
        strncpy(entry.key_name, "N/A", sizeof(entry.key_name) - 1);
        entry.key_name[sizeof(entry.key_name) - 1] = '\0';
    }

    if (user_id) {
        strncpy(entry.user_id, user_id, sizeof(entry.user_id) - 1);
        entry.user_id[sizeof(entry.user_id) - 1] = '\0';
    } else {
        strncpy(entry.user_id, "system", sizeof(entry.user_id) - 1);
        entry.user_id[sizeof(entry.user_id) - 1] = '\0';
    }

    if (details) {
        strncpy(entry.details, details, sizeof(entry.details) - 1);
        entry.details[sizeof(entry.details) - 1] = '\0';
    } else {
        entry.details[0] = '\0';
    }

    // Encrypt audit entry
    unsigned char ciphertext[sizeof(AuditLogEntry) + 32];
    size_t ciphertext_len = 0;
    unsigned char iv[AUDIT_IV_SIZE];
    unsigned char tag[AUDIT_TAG_SIZE];

    if (encrypt_audit_entry((const unsigned char*)&entry, sizeof(AuditLogEntry),
                            ciphertext, &ciphertext_len, iv, tag) != 0) {
        fprintf(stderr, "Error: Failed to encrypt audit entry\n");
        return 0;
    }

    // Append to encrypted audit log
    FILE *log = fopen(AUDIT_LOG_FILE, "ab");
    if (!log) {
        return 0;
    }

    // Write IV, tag, and encrypted data
    fwrite(iv, 1, AUDIT_IV_SIZE, log);
    fwrite(tag, 1, AUDIT_TAG_SIZE, log);
    fwrite(ciphertext, 1, ciphertext_len, log);

    fclose(log);

    // Zero sensitive data
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(iv, 0, sizeof(iv));
    memset(tag, 0, sizeof(tag));

    return 1;
}

// Initialize key metadata
int init_key_metadata(const char *key_name, KeyMetadata *metadata) {
    if (!key_name || !metadata) return 0;

    strncpy(metadata->key_name, key_name, sizeof(metadata->key_name) - 1);
    metadata->key_name[sizeof(metadata->key_name) - 1] = '\0';
    metadata->created_at = time(NULL);
    metadata->last_used = metadata->created_at;
    metadata->last_rotated = metadata->created_at;
    metadata->state = KEY_STATE_ACTIVE;
    metadata->use_count = 0;
    metadata->rotation_version = 1;
    memset(metadata->checksum, 0, sizeof(metadata->checksum));

    return 1;
}

// Save key metadata
int save_key_metadata(const KeyMetadata *metadata) {
    if (!metadata) return 0;

    char filename[128];
    snprintf(filename, sizeof(filename), ".%s.metadata", metadata->key_name);

    // Encrypt metadata
    unsigned char ciphertext[sizeof(KeyMetadata) + 32];
    size_t ciphertext_len = 0;
    unsigned char iv[METADATA_IV_SIZE];
    unsigned char tag[METADATA_TAG_SIZE];

    if (encrypt_metadata((const unsigned char*)metadata, sizeof(KeyMetadata),
                        ciphertext, &ciphertext_len, iv, tag) != 0) {
        fprintf(stderr, "Error: Failed to encrypt metadata\n");
        return 0;
    }

    // Write encrypted metadata file
    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Cannot save key metadata\n");
        return 0;
    }

    // Write magic, IV, tag, and encrypted data
    fwrite(METADATA_MAGIC, 1, METADATA_MAGIC_SIZE, file);
    fwrite(iv, 1, METADATA_IV_SIZE, file);
    fwrite(tag, 1, METADATA_TAG_SIZE, file);
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);

    // Set secure permissions
    chmod(filename, 0600);

    // Zero sensitive data
    memset(ciphertext, 0, sizeof(ciphertext));

    return 1;
}

// Load key metadata
int load_key_metadata(const char *key_name, KeyMetadata *metadata) {
    if (!key_name || !metadata) return 0;

    char filename[128];
    snprintf(filename, sizeof(filename), ".%s.metadata", key_name);

    FILE *file = fopen(filename, "rb");
    if (!file) {
        // Metadata doesn't exist, initialize new
        return init_key_metadata(key_name, metadata);
    }

    // Read magic number
    char magic[METADATA_MAGIC_SIZE];
    if (fread(magic, 1, METADATA_MAGIC_SIZE, file) != METADATA_MAGIC_SIZE) {
        // Old format or corrupted, try to initialize new
        fclose(file);
        return init_key_metadata(key_name, metadata);
    }

    // Check if it's encrypted format
    if (memcmp(magic, METADATA_MAGIC, METADATA_MAGIC_SIZE) != 0) {
        // Old unencrypted format or corrupted, initialize new
        fclose(file);
        return init_key_metadata(key_name, metadata);
    }

    // Read IV and tag
    unsigned char iv[METADATA_IV_SIZE];
    unsigned char tag[METADATA_TAG_SIZE];

    if (fread(iv, 1, METADATA_IV_SIZE, file) != METADATA_IV_SIZE ||
        fread(tag, 1, METADATA_TAG_SIZE, file) != METADATA_TAG_SIZE) {
        fprintf(stderr, "Error: Failed to read metadata IV/tag\n");
        fclose(file);
        return 0;
    }

    // Read encrypted data
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    long ciphertext_len = file_size - METADATA_MAGIC_SIZE - METADATA_IV_SIZE - METADATA_TAG_SIZE;
    fseek(file, METADATA_MAGIC_SIZE + METADATA_IV_SIZE + METADATA_TAG_SIZE, SEEK_SET);

    if (ciphertext_len <= 0 || ciphertext_len > 1024) {
        fprintf(stderr, "Error: Invalid metadata file size\n");
        fclose(file);
        return 0;
    }

    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fclose(file);
        return 0;
    }

    if (fread(ciphertext, 1, ciphertext_len, file) != (size_t)ciphertext_len) {
        free(ciphertext);
        fclose(file);
        return 0;
    }
    fclose(file);

    // Decrypt metadata
    unsigned char plaintext[sizeof(KeyMetadata) + 16];
    size_t plaintext_len = 0;

    if (decrypt_metadata(ciphertext, ciphertext_len, plaintext, &plaintext_len,
                        iv, tag) != 0) {
        fprintf(stderr, "Error: Failed to decrypt metadata\n");
        free(ciphertext);
        return 0;
    }

    free(ciphertext);

    if (plaintext_len != sizeof(KeyMetadata)) {
        fprintf(stderr, "Error: Metadata size mismatch\n");
        return 0;
    }

    // Copy decrypted metadata
    memcpy(metadata, plaintext, sizeof(KeyMetadata));
    memset(plaintext, 0, sizeof(plaintext));

    return 1;
}

// Update key usage statistics
int update_key_usage(const char *key_name) {
    KeyMetadata metadata;
    if (!load_key_metadata(key_name, &metadata)) {
        return 0;
    }

    metadata.last_used = time(NULL);
    metadata.use_count++;

    return save_key_metadata(&metadata);
}

// Check if key rotation is needed
int check_key_rotation_needed(const char *key_name) {
    KeyMetadata metadata;
    if (!load_key_metadata(key_name, &metadata)) {
        return 0;
    }

    time_t now = time(NULL);
    double days_since_rotation = difftime(now, metadata.last_rotated) / (60 * 60 * 24);

    if (days_since_rotation > KEY_ROTATION_DAYS) {
        fprintf(stderr, "Warning: Key '%s' needs rotation (%.0f days old)\n",
                key_name, days_since_rotation);
        return 1;
    }

    return 0;
}

// Secure memory allocation
void* secure_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
        // Note: mlock() would be called here on systems that support it
    }
    return ptr;
}

// Secure memory deallocation
void secure_free(void *ptr, size_t size) {
    if (ptr) {
        secure_memzero(ptr, size);
        free(ptr);
    }
}

// Secure memory zeroing (resistant to compiler optimization)
void secure_memzero(void *ptr, size_t size) {
    if (ptr) {
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}

// Lock memory pages to prevent swapping
int lock_memory_pages(void) {
#ifdef __linux__
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        fprintf(stderr, "Warning: Could not lock memory pages\n");
        return 0;
    }
    return 1;
#else
    fprintf(stderr, "Warning: Memory locking not supported on this platform\n");
    return 0;
#endif
}

#endif // HSM_SECURITY_H
