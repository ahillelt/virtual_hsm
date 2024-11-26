#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>
#include <stdint.h>

// Forward declarations
struct SecureMetadata;
typedef struct SecureMetadata SecureMetadata;

// Operation function type definition
typedef int (*operation_func)(void*);

// Basic type definitions
typedef enum {
    SUCCESS = 0,
    ERROR_INVALID_INPUT = -1,
    ERROR_SYSTEM = -2,
    ERROR_CRYPTO = -3,
    ERROR_PERMISSION = -4,
    ERROR_TIMEOUT = -5,
    ERROR_RATE_LIMIT = -6
} ErrorCode;

typedef struct {
    int code;
    char message[256];
} SecurityError;

// Arguments structures
typedef struct {
    const char* filepath;
    char*** chunk_paths;
    size_t* chunk_count;
    char* token;
    size_t* file_size;
    SecureMetadata* metadata;
} StoreFileArgs;

typedef struct {
    const char* token;
    const char* output_path;
    unsigned char* key;
    SecureMetadata* metadata;
} RetrieveFileArgs;

#endif // TYPES_H

