#include "vhsm.h"
#include "../utils/secure_memory.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global library state */
static struct {
    int initialized;
    pthread_mutex_t lock;
    vhsm_log_callback_t log_callback;
    void* log_user_data;
} g_library_state = {
    .initialized = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/* Internal context structure */
struct vhsm_context {
    char storage_path[VHSM_MAX_PATH];
    uint8_t master_key[VHSM_AES_256_KEY_SIZE];
    int master_key_set;
    pthread_mutex_t lock;
    void* auth_ctx;
    void* storage_ctx;
    void* audit_ctx;
};

/* Library initialization */
vhsm_error_t vhsm_init(void) {
    pthread_mutex_lock(&g_library_state.lock);

    if (g_library_state.initialized) {
        pthread_mutex_unlock(&g_library_state.lock);
        return VHSM_ERROR_ALREADY_INITIALIZED;
    }

    /* Initialize OpenSSL */
    OpenSSL_add_all_algorithms();

    g_library_state.initialized = 1;
    pthread_mutex_unlock(&g_library_state.lock);

    return VHSM_SUCCESS;
}

void vhsm_cleanup(void) {
    pthread_mutex_lock(&g_library_state.lock);

    if (!g_library_state.initialized) {
        pthread_mutex_unlock(&g_library_state.lock);
        return;
    }

    /* Cleanup OpenSSL */
    EVP_cleanup();

    g_library_state.initialized = 0;
    g_library_state.log_callback = NULL;
    g_library_state.log_user_data = NULL;

    pthread_mutex_unlock(&g_library_state.lock);
}

const char* vhsm_version(void) {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d",
             VHSM_VERSION_MAJOR, VHSM_VERSION_MINOR, VHSM_VERSION_PATCH);
    return version;
}

const char* vhsm_error_string(vhsm_error_t error) {
    switch (error) {
        case VHSM_SUCCESS: return "Success";
        case VHSM_ERROR_GENERIC: return "Generic error";
        case VHSM_ERROR_INVALID_PARAM: return "Invalid parameter";
        case VHSM_ERROR_OUT_OF_MEMORY: return "Out of memory";
        case VHSM_ERROR_KEY_NOT_FOUND: return "Key not found";
        case VHSM_ERROR_KEY_EXISTS: return "Key already exists";
        case VHSM_ERROR_CRYPTO_FAILED: return "Cryptographic operation failed";
        case VHSM_ERROR_IO_FAILED: return "I/O operation failed";
        case VHSM_ERROR_AUTH_FAILED: return "Authentication failed";
        case VHSM_ERROR_PERMISSION_DENIED: return "Permission denied";
        case VHSM_ERROR_INVALID_STATE: return "Invalid state";
        case VHSM_ERROR_BUFFER_TOO_SMALL: return "Buffer too small";
        case VHSM_ERROR_NOT_IMPLEMENTED: return "Not implemented";
        case VHSM_ERROR_KEY_EXPIRED: return "Key expired";
        case VHSM_ERROR_KEY_REVOKED: return "Key revoked";
        case VHSM_ERROR_SESSION_INVALID: return "Session invalid";
        case VHSM_ERROR_RATE_LIMIT: return "Rate limit exceeded";
        case VHSM_ERROR_AUDIT_FAILED: return "Audit logging failed";
        case VHSM_ERROR_COMPRESSION_FAILED: return "Compression failed";
        case VHSM_ERROR_DECOMPRESSION_FAILED: return "Decompression failed";
        case VHSM_ERROR_INVALID_SIGNATURE: return "Invalid signature";
        case VHSM_ERROR_INVALID_FORMAT: return "Invalid format";
        case VHSM_ERROR_NOT_INITIALIZED: return "Library not initialized";
        case VHSM_ERROR_ALREADY_INITIALIZED: return "Library already initialized";
        default: return "Unknown error";
    }
}

void vhsm_set_log_callback(vhsm_log_callback_t callback, void* user_data) {
    pthread_mutex_lock(&g_library_state.lock);
    g_library_state.log_callback = callback;
    g_library_state.log_user_data = user_data;
    pthread_mutex_unlock(&g_library_state.lock);
}

/* Internal logging function */
void vhsm_log(int level, const char* fmt, ...) {
    pthread_mutex_lock(&g_library_state.lock);

    if (g_library_state.log_callback) {
        char buffer[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);

        g_library_state.log_callback(level, buffer, g_library_state.log_user_data);
    }

    pthread_mutex_unlock(&g_library_state.lock);
}

/* Context management */
vhsm_error_t vhsm_ctx_create(vhsm_ctx_t* ctx, const char* storage_path) {
    if (!ctx || !storage_path) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    if (!g_library_state.initialized) {
        return VHSM_ERROR_NOT_INITIALIZED;
    }

    struct vhsm_context* context = calloc(1, sizeof(struct vhsm_context));
    if (!context) {
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    strncpy(context->storage_path, storage_path, VHSM_MAX_PATH - 1);
    context->master_key_set = 0;
    pthread_mutex_init(&context->lock, NULL);

    /* Initialize subsystems (to be implemented) */
    context->auth_ctx = NULL;
    context->storage_ctx = NULL;
    context->audit_ctx = NULL;

    *ctx = context;
    return VHSM_SUCCESS;
}

void vhsm_ctx_destroy(vhsm_ctx_t ctx) {
    if (!ctx) {
        return;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;

    /* Securely wipe master key */
    secure_wipe(context->master_key, sizeof(context->master_key));

    /* Cleanup subsystems (to be implemented) */

    pthread_mutex_destroy(&context->lock);
    free(context);
}

vhsm_error_t vhsm_ctx_set_master_key(vhsm_ctx_t ctx, const uint8_t* master_key) {
    if (!ctx || !master_key) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;

    pthread_mutex_lock(&context->lock);
    memcpy(context->master_key, master_key, VHSM_AES_256_KEY_SIZE);
    context->master_key_set = 1;
    pthread_mutex_unlock(&context->lock);

    return VHSM_SUCCESS;
}

vhsm_error_t vhsm_ctx_generate_master_key(vhsm_ctx_t ctx, uint8_t* master_key) {
    if (!ctx || !master_key) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;

    /* Generate random master key */
    if (RAND_bytes(master_key, VHSM_AES_256_KEY_SIZE) != 1) {
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    pthread_mutex_lock(&context->lock);
    memcpy(context->master_key, master_key, VHSM_AES_256_KEY_SIZE);
    context->master_key_set = 1;
    pthread_mutex_unlock(&context->lock);

    return VHSM_SUCCESS;
}
