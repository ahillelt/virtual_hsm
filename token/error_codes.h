// error_codes.h
#ifndef ERROR_CODES_H
#define ERROR_CODES_H

#include <stdio.h>

// Error code definitions with categories
typedef enum {
    SUCCESS = 0,
    ERR_SYS_MALLOC_FAILED = 1001, // Memory allocation failed
    ERR_SYS_FILE_NOT_FOUND = 1002, // File not found
    ERR_SYS_FILE_ACCESS_DENIED = 1003, // File access denied
    ERR_SYS_DIR_CREATE_FAILED = 1004, // Directory creation failed
    ERR_SYS_PATH_TOO_LONG = 1005, // Path too long
    ERR_SEC_INVALID_KEY = 2001, // Invalid security key
    ERR_SEC_PATH_TRAVERSAL = 2002, // Path traversal attempt detected
    ERR_SEC_UNAUTHORIZED_ACCESS = 2003, // Unauthorized access attempt
    ERR_VAL_INVALID_PARAM = 3001, // Invalid parameter
    ERR_VAL_INVALID_PATH = 3002, // Invalid path
    ERR_VAL_INVALID_SIZE = 3003, // Invalid size
    ERR_VAL_INVALID_CHUNK = 3004, // Invalid chunk
    ERR_CRYPT_DECRYPT_FAILED = 4001, // Decryption failed
    ERR_CRYPT_INVALID_TOKEN = 4002, // Invalid token
    ERR_DATA_CHUNK_MISMATCH = 5001, // Chunk size mismatch
    ERR_DATA_CORRUPT_METADATA = 5002, // Corrupt metadata
    ERR_DATA_HASH_MISMATCH = 5003, // Hash mismatch
} ErrorCode;

// Error categories
typedef enum {
    ERR_NONE,
    ERR_SYSTEM,
    ERR_SECURITY,
    ERR_VALIDATION,
    ERR_CRYPTO,
    ERR_DATA_INTEGRITY
} ErrorCategory;

// Error result structure
typedef struct {
    ErrorCode code;
    ErrorCategory category;
    const char *file;
    int line;
    const char *func;
    char message[256]; // Optional additional details
} ErrorResult;

// Function to get error string
const char *get_error_string(ErrorCode code) {
    switch (code) {
        case SUCCESS: return "Success";
        case ERR_SYS_MALLOC_FAILED: return "Memory allocation failed";
        case ERR_SYS_FILE_NOT_FOUND: return "File not found";
        case ERR_SYS_FILE_ACCESS_DENIED: return "File access denied";
        case ERR_SYS_DIR_CREATE_FAILED: return "Directory creation failed";
        case ERR_SYS_PATH_TOO_LONG: return "Path too long";
        case ERR_SEC_INVALID_KEY: return "Invalid security key";
        case ERR_SEC_PATH_TRAVERSAL: return "Path traversal attempt detected";
        case ERR_SEC_UNAUTHORIZED_ACCESS: return "Unauthorized access attempt";
        case ERR_VAL_INVALID_PARAM: return "Invalid parameter";
        case ERR_VAL_INVALID_PATH: return "Invalid path";
        case ERR_VAL_INVALID_SIZE: return "Invalid size";
        case ERR_VAL_INVALID_CHUNK: return "Invalid chunk";
        case ERR_CRYPT_DECRYPT_FAILED: return "Decryption failed";
        case ERR_CRYPT_INVALID_TOKEN: return "Invalid token";
        case ERR_DATA_CHUNK_MISMATCH: return "Chunk size mismatch";
        case ERR_DATA_CORRUPT_METADATA: return "Corrupt metadata";
        case ERR_DATA_HASH_MISMATCH: return "Hash mismatch";
        default: return "Unknown error";
    }
}

// Function to log errors
void log_error(ErrorResult *error) {
    if (!error) return;

    // Determine the error category string
    const char* category_str;
    switch(error->category) {
        case ERR_SYSTEM: category_str = "SYSTEM"; break;
        case ERR_SECURITY: category_str = "SECURITY"; break;
        case ERR_VALIDATION: category_str = "VALIDATION"; break;
        case ERR_CRYPTO: category_str = "CRYPTO"; break;
        case ERR_DATA_INTEGRITY: category_str = "DATA_INTEGRITY"; break;
        default: category_str = "UNKNOWN"; break;
    }

    // Log the error
    fprintf(stderr, "[ERROR] %s (%d) - %s\n", category_str, error->code, get_error_string(error->code));
    if (error->message) {
        fprintf(stderr, "Details: %s\n", error->message);
    }
    fprintf(stderr, "Location: %s:%d in %s\n", error->file, error->line, error->func);
}

#endif // ERROR_CODES_H