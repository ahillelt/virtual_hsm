#ifndef VHSM_TYPES_H
#define VHSM_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* Version information */
#define VHSM_VERSION_MAJOR 2
#define VHSM_VERSION_MINOR 0
#define VHSM_VERSION_PATCH 0

/* Maximum lengths */
#define VHSM_MAX_KEY_NAME 128
#define VHSM_MAX_USERNAME 64
#define VHSM_MAX_PASSWORD 256
#define VHSM_MAX_PIN 32
#define VHSM_MAX_LABEL 256
#define VHSM_MAX_PATH 4096
#define VHSM_MAX_KEYS 10000

/* Cryptographic constants */
#define VHSM_AES_256_KEY_SIZE 32
#define VHSM_AES_128_KEY_SIZE 16
#define VHSM_GCM_IV_SIZE 12
#define VHSM_GCM_TAG_SIZE 16
#define VHSM_SHA256_SIZE 32
#define VHSM_SHA512_SIZE 64
#define VHSM_ED25519_KEY_SIZE 32
#define VHSM_ED25519_SIG_SIZE 64
#define VHSM_RSA_MIN_KEY_SIZE 2048
#define VHSM_RSA_MAX_KEY_SIZE 4096

/* Error codes */
typedef enum {
    VHSM_SUCCESS = 0,
    VHSM_ERROR_GENERIC = -1,
    VHSM_ERROR_INVALID_PARAM = -2,
    VHSM_ERROR_OUT_OF_MEMORY = -3,
    VHSM_ERROR_KEY_NOT_FOUND = -4,
    VHSM_ERROR_KEY_EXISTS = -5,
    VHSM_ERROR_CRYPTO_FAILED = -6,
    VHSM_ERROR_IO_FAILED = -7,
    VHSM_ERROR_AUTH_FAILED = -8,
    VHSM_ERROR_PERMISSION_DENIED = -9,
    VHSM_ERROR_INVALID_STATE = -10,
    VHSM_ERROR_BUFFER_TOO_SMALL = -11,
    VHSM_ERROR_NOT_IMPLEMENTED = -12,
    VHSM_ERROR_KEY_EXPIRED = -13,
    VHSM_ERROR_KEY_REVOKED = -14,
    VHSM_ERROR_SESSION_INVALID = -15,
    VHSM_ERROR_RATE_LIMIT = -16,
    VHSM_ERROR_AUDIT_FAILED = -17,
    VHSM_ERROR_COMPRESSION_FAILED = -18,
    VHSM_ERROR_DECOMPRESSION_FAILED = -19,
    VHSM_ERROR_INVALID_SIGNATURE = -20,
    VHSM_ERROR_INVALID_FORMAT = -21,
    VHSM_ERROR_NOT_INITIALIZED = -22,
    VHSM_ERROR_ALREADY_INITIALIZED = -23
} vhsm_error_t;

/* Key types */
typedef enum {
    VHSM_KEY_TYPE_INVALID = 0,
    VHSM_KEY_TYPE_AES_128,
    VHSM_KEY_TYPE_AES_256,
    VHSM_KEY_TYPE_ED25519,
    VHSM_KEY_TYPE_RSA_2048,
    VHSM_KEY_TYPE_RSA_3072,
    VHSM_KEY_TYPE_RSA_4096,
    VHSM_KEY_TYPE_ECDSA_P256,
    VHSM_KEY_TYPE_ECDSA_P384,
    VHSM_KEY_TYPE_ECDSA_P521,
    VHSM_KEY_TYPE_HMAC_SHA256,
    VHSM_KEY_TYPE_HMAC_SHA512
} vhsm_key_type_t;

/* Key usage flags */
typedef enum {
    VHSM_KEY_USAGE_NONE = 0,
    VHSM_KEY_USAGE_ENCRYPT = (1 << 0),
    VHSM_KEY_USAGE_DECRYPT = (1 << 1),
    VHSM_KEY_USAGE_SIGN = (1 << 2),
    VHSM_KEY_USAGE_VERIFY = (1 << 3),
    VHSM_KEY_USAGE_WRAP = (1 << 4),
    VHSM_KEY_USAGE_UNWRAP = (1 << 5),
    VHSM_KEY_USAGE_DERIVE = (1 << 6),
    VHSM_KEY_USAGE_ALL = 0xFF
} vhsm_key_usage_t;

/* Key states */
typedef enum {
    VHSM_KEY_STATE_INVALID = 0,
    VHSM_KEY_STATE_ACTIVE,
    VHSM_KEY_STATE_SUSPENDED,
    VHSM_KEY_STATE_REVOKED,
    VHSM_KEY_STATE_EXPIRED,
    VHSM_KEY_STATE_COMPROMISED
} vhsm_key_state_t;

/* User roles */
typedef enum {
    VHSM_ROLE_NONE = 0,
    VHSM_ROLE_USER = 1,
    VHSM_ROLE_OPERATOR = 2,
    VHSM_ROLE_ADMIN = 3,
    VHSM_ROLE_AUDITOR = 4
} vhsm_role_t;

/* Audit event types */
typedef enum {
    VHSM_AUDIT_NONE = 0,
    VHSM_AUDIT_LOGIN,
    VHSM_AUDIT_LOGOUT,
    VHSM_AUDIT_AUTH_FAILED,
    VHSM_AUDIT_KEY_GENERATED,
    VHSM_AUDIT_KEY_IMPORTED,
    VHSM_AUDIT_KEY_EXPORTED,
    VHSM_AUDIT_KEY_DELETED,
    VHSM_AUDIT_KEY_ROTATED,
    VHSM_AUDIT_KEY_REVOKED,
    VHSM_AUDIT_ENCRYPT,
    VHSM_AUDIT_DECRYPT,
    VHSM_AUDIT_SIGN,
    VHSM_AUDIT_VERIFY,
    VHSM_AUDIT_FILE_STORE,
    VHSM_AUDIT_FILE_RETRIEVE,
    VHSM_AUDIT_CONFIG_CHANGED,
    VHSM_AUDIT_ERROR
} vhsm_audit_event_t;

/* Compression types */
typedef enum {
    VHSM_COMPRESS_NONE = 0,
    VHSM_COMPRESS_ZLIB = 1,
    VHSM_COMPRESS_LZ4 = 2
} vhsm_compress_t;

/* Key metadata */
typedef struct {
    char name[VHSM_MAX_KEY_NAME];
    char label[VHSM_MAX_LABEL];
    vhsm_key_type_t type;
    vhsm_key_usage_t usage;
    vhsm_key_state_t state;
    time_t created;
    time_t expires;
    time_t last_used;
    uint64_t use_count;
    uint32_t version;
    uint8_t is_public;
    uint8_t exportable;
    uint8_t reserved[6];
} vhsm_key_metadata_t;

/* Session handle */
typedef void* vhsm_session_t;

/* Context handle */
typedef void* vhsm_ctx_t;

/* Key handle */
typedef uint64_t vhsm_key_handle_t;

#define VHSM_INVALID_HANDLE 0

/* Callback types */
typedef void (*vhsm_log_callback_t)(int level, const char* message, void* user_data);
typedef int (*vhsm_auth_callback_t)(const char* username, const char* prompt, char* response, size_t response_len, void* user_data);

#endif /* VHSM_TYPES_H */
