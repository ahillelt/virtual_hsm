/*
 * Virtual HSM - Basic Usage Example
 *
 * This example demonstrates how to use the Virtual HSM library API
 * programmatically for key management and cryptographic operations.
 */

#include "vhsm.h"
#include <stdio.h>
#include <string.h>

static void log_callback(int level, const char* message, void* user_data) {
    printf("[LOG %d] %s\n", level, message);
}

int main(void) {
    vhsm_error_t err;
    vhsm_ctx_t ctx = NULL;
    vhsm_session_t session = NULL;
    vhsm_key_handle_t key_handle = 0;

    printf("=== Virtual HSM Library API Example ===\n\n");

    /* Step 1: Initialize the library */
    printf("1. Initializing library...\n");
    err = vhsm_init();
    if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to initialize: %s\n", vhsm_error_string(err));
        return 1;
    }
    printf("   Version: %s\n", vhsm_version());

    /* Set log callback (optional) */
    vhsm_set_log_callback(log_callback, NULL);

    /* Step 2: Create HSM context */
    printf("\n2. Creating HSM context...\n");
    err = vhsm_ctx_create(&ctx, "./example_storage");
    if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to create context: %s\n", vhsm_error_string(err));
        vhsm_cleanup();
        return 1;
    }
    printf("   Context created\n");

    /* Step 3: Generate and set master key */
    printf("\n3. Generating master key...\n");
    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to generate master key: %s\n", vhsm_error_string(err));
        vhsm_ctx_destroy(ctx);
        vhsm_cleanup();
        return 1;
    }
    printf("   Master key generated\n");

    /* Step 4: Enable audit logging */
    printf("\n4. Enabling audit logging...\n");
    err = vhsm_audit_enable(ctx, "./example_audit.log");
    if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to enable audit: %s\n", vhsm_error_string(err));
    } else {
        printf("   Audit logging enabled\n");
    }

    /* Step 5: Create a user */
    printf("\n5. Creating user 'admin'...\n");
    err = vhsm_user_create(ctx, "admin", "SecurePassword123!", NULL, VHSM_ROLE_ADMIN);
    if (err != VHSM_SUCCESS && err != VHSM_ERROR_KEY_EXISTS) {
        fprintf(stderr, "Failed to create user: %s\n", vhsm_error_string(err));
    } else {
        printf("   User created\n");
    }

    /* Step 6: Login and create session */
    printf("\n6. Logging in as 'admin'...\n");
    err = vhsm_session_login(ctx, &session, "admin", "SecurePassword123!", NULL);
    if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to login: %s\n", vhsm_error_string(err));
        vhsm_ctx_destroy(ctx);
        vhsm_cleanup();
        return 1;
    }
    printf("   Session created\n");

    /* Step 7: Generate encryption key */
    printf("\n7. Generating AES-256 key...\n");
    err = vhsm_key_generate(session, "my_encryption_key", VHSM_KEY_TYPE_AES_256,
                             VHSM_KEY_USAGE_ENCRYPT | VHSM_KEY_USAGE_DECRYPT,
                             &key_handle);
    if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to generate key: %s\n", vhsm_error_string(err));
    } else {
        printf("   Key generated (handle: %lu)\n", key_handle);
    }

    /* Step 8: Generate signing key */
    printf("\n8. Generating ED25519 signing key...\n");
    vhsm_key_handle_t sign_key_handle = 0;
    err = vhsm_key_generate(session, "my_signing_key", VHSM_KEY_TYPE_ED25519,
                             VHSM_KEY_USAGE_SIGN | VHSM_KEY_USAGE_VERIFY,
                             &sign_key_handle);
    if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to generate signing key: %s\n", vhsm_error_string(err));
    } else {
        printf("   Signing key generated (handle: %lu)\n", sign_key_handle);
    }

    /* Step 9: List keys */
    printf("\n9. Listing all keys...\n");
    vhsm_key_metadata_t metadata[100];
    size_t count = 100;
    err = vhsm_key_list(session, metadata, &count);
    if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Failed to list keys: %s\n", vhsm_error_string(err));
    } else {
        printf("   Found %zu keys:\n", count);
        for (size_t i = 0; i < count; i++) {
            printf("   - %s (type=%d, state=%d)\n",
                   metadata[i].name, metadata[i].type, metadata[i].state);
        }
    }

    /* Step 10: Encrypt data (demonstrates API - may return NOT_IMPLEMENTED) */
    printf("\n10. Encrypting data...\n");
    const char* plaintext = "Hello, Virtual HSM!";
    uint8_t ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);
    uint8_t iv[VHSM_GCM_IV_SIZE];

    err = vhsm_encrypt(session, key_handle,
                       (const uint8_t*)plaintext, strlen(plaintext),
                       ciphertext, &ciphertext_len, iv, VHSM_GCM_IV_SIZE);
    if (err == VHSM_ERROR_NOT_IMPLEMENTED) {
        printf("   Encryption API available but not fully implemented yet\n");
    } else if (err != VHSM_SUCCESS) {
        fprintf(stderr, "Encryption failed: %s\n", vhsm_error_string(err));
    } else {
        printf("   Data encrypted (%zu bytes)\n", ciphertext_len);
    }

    /* Step 11: File storage (demonstrates API) */
    printf("\n11. Testing file storage API...\n");
    char token[64];
    err = vhsm_file_store(session, key_handle, "./examples/basic_usage.c",
                          VHSM_COMPRESS_ZLIB, 0, token, sizeof(token));
    if (err == VHSM_ERROR_NOT_IMPLEMENTED) {
        printf("   File storage API available but not fully implemented yet\n");
    } else if (err != VHSM_SUCCESS) {
        fprintf(stderr, "File storage failed: %s\n", vhsm_error_string(err));
    } else {
        printf("   File stored with token: %s\n", token);
    }

    /* Cleanup */
    printf("\n12. Cleaning up...\n");

    if (session) {
        vhsm_session_logout(session);
        printf("   Session logged out\n");
    }

    if (ctx) {
        vhsm_ctx_destroy(ctx);
        printf("   Context destroyed\n");
    }

    vhsm_cleanup();
    printf("   Library cleaned up\n");

    printf("\n=== Example Complete ===\n");
    return 0;
}
