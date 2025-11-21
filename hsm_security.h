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

// Initialize audit log
int init_audit_log(void) {
    FILE *log = fopen(AUDIT_LOG_FILE, "a");
    if (!log) {
        fprintf(stderr, "Error: Cannot initialize audit log\n");
        return 0;
    }

    // Write header if file is empty
    fseek(log, 0, SEEK_END);
    if (ftell(log) == 0) {
        fprintf(log, "# Virtual HSM Audit Log\n");
        fprintf(log, "# Format: timestamp|event_type|key_name|user_id|details|success\n");
    }
    fclose(log);
    return 1;
}

// Write audit log entry
int write_audit_log(AuditEventType event_type, const char *key_name,
                    const char *user_id, const char *details, int success) {
    FILE *log = fopen(AUDIT_LOG_FILE, "a");
    if (!log) {
        return 0;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    const char *event_names[] = {
        "KEY_CREATED", "KEY_ACCESSED", "KEY_MODIFIED", "KEY_DELETED",
        "KEY_ROTATED", "AUTH_SUCCESS", "AUTH_FAILURE", "SIGN_OPERATION",
        "VERIFY_OPERATION", "ENCRYPTION", "DECRYPTION", "CONFIG_CHANGE",
        "SECURITY_VIOLATION"
    };

    fprintf(log, "%s|%s|%s|%s|%s|%s\n",
            timestamp,
            event_names[event_type],
            key_name ? key_name : "N/A",
            user_id ? user_id : "system",
            details ? details : "",
            success ? "SUCCESS" : "FAILURE");

    fclose(log);
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

    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Cannot save key metadata\n");
        return 0;
    }

    fwrite(metadata, sizeof(KeyMetadata), 1, file);
    fclose(file);

    // Set secure permissions
    chmod(filename, 0600);

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

    size_t read = fread(metadata, sizeof(KeyMetadata), 1, file);
    fclose(file);

    return (read == 1);
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
