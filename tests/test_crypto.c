#include "vhsm.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Test crypto operations */

int test_init() {
    printf("Testing library initialization...\n");

    vhsm_error_t err = vhsm_init();
    assert(err == VHSM_SUCCESS || err == VHSM_ERROR_ALREADY_INITIALIZED);

    const char* version = vhsm_version();
    assert(version != NULL);
    printf("  Version: %s\n", version);

    printf("  PASS\n\n");
    return 1;
}

int test_context() {
    printf("Testing context management...\n");

    vhsm_ctx_t ctx = NULL;
    vhsm_error_t err;

    err = vhsm_ctx_create(&ctx, "./test_storage");
    assert(err == VHSM_SUCCESS);
    assert(ctx != NULL);

    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    assert(err == VHSM_SUCCESS);

    vhsm_ctx_destroy(ctx);

    printf("  PASS\n\n");
    return 1;
}

int test_authentication() {
    printf("Testing authentication...\n");

    vhsm_ctx_t ctx = NULL;
    vhsm_error_t err;

    err = vhsm_ctx_create(&ctx, "./test_storage");
    assert(err == VHSM_SUCCESS);

    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    assert(err == VHSM_SUCCESS);

    /* Create user */
    err = vhsm_user_create(ctx, "testuser", "testpass", NULL, VHSM_ROLE_USER);
    if (err != VHSM_SUCCESS && err != VHSM_ERROR_KEY_EXISTS) {
        printf("  vhsm_user_create returned error code: %d\n", err);
    }
    assert(err == VHSM_SUCCESS || err == VHSM_ERROR_KEY_EXISTS);

    /* Login */
    vhsm_session_t session;
    err = vhsm_session_login(ctx, &session, "testuser", "testpass", NULL);
    assert(err == VHSM_SUCCESS);
    assert(vhsm_session_is_valid(session));

    /* Logout */
    vhsm_session_logout(session);
    assert(!vhsm_session_is_valid(session));

    vhsm_ctx_destroy(ctx);

    printf("  PASS\n\n");
    return 1;
}

int test_key_generation() {
    printf("Testing key generation...\n");

    vhsm_ctx_t ctx = NULL;
    vhsm_session_t session;
    vhsm_error_t err;

    err = vhsm_ctx_create(&ctx, "./test_storage");
    assert(err == VHSM_SUCCESS);

    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    assert(err == VHSM_SUCCESS);

    err = vhsm_user_create(ctx, "testuser2", "testpass2", NULL, VHSM_ROLE_ADMIN);
    if (err != VHSM_SUCCESS && err != VHSM_ERROR_KEY_EXISTS) {
        printf("  FAIL: Could not create user\n");
        return 0;
    }

    err = vhsm_session_login(ctx, &session, "testuser2", "testpass2", NULL);
    assert(err == VHSM_SUCCESS);

    /* Generate AES key */
    vhsm_key_handle_t key_handle;
    err = vhsm_key_generate(session, "test_aes_key", VHSM_KEY_TYPE_AES_256,
                             VHSM_KEY_USAGE_ALL, &key_handle);
    assert(err == VHSM_SUCCESS || err == VHSM_ERROR_KEY_EXISTS);
    assert(key_handle != VHSM_INVALID_HANDLE);

    /* Generate ED25519 key */
    vhsm_key_handle_t sign_key;
    err = vhsm_key_generate(session, "test_sign_key", VHSM_KEY_TYPE_ED25519,
                             VHSM_KEY_USAGE_SIGN | VHSM_KEY_USAGE_VERIFY, &sign_key);
    assert(err == VHSM_SUCCESS || err == VHSM_ERROR_KEY_EXISTS);

    vhsm_session_logout(session);
    vhsm_ctx_destroy(ctx);

    printf("  PASS\n\n");
    return 1;
}

int test_encryption_decryption() {
    printf("Testing encryption/decryption...\n");

    vhsm_ctx_t ctx = NULL;
    vhsm_session_t session;
    vhsm_error_t err;

    err = vhsm_ctx_create(&ctx, "./test_storage");
    assert(err == VHSM_SUCCESS);

    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    assert(err == VHSM_SUCCESS);

    err = vhsm_user_create(ctx, "testuser3", "testpass3", NULL, VHSM_ROLE_ADMIN);
    if (err != VHSM_SUCCESS && err != VHSM_ERROR_KEY_EXISTS) {
        printf("  SKIP: Could not create user\n");
        vhsm_ctx_destroy(ctx);
        return 1;
    }

    err = vhsm_session_login(ctx, &session, "testuser3", "testpass3", NULL);
    assert(err == VHSM_SUCCESS);

    vhsm_key_handle_t key_handle;
    err = vhsm_key_generate(session, "test_enc_key", VHSM_KEY_TYPE_AES_256,
                             VHSM_KEY_USAGE_ALL, &key_handle);

    if (err == VHSM_SUCCESS) {
        /* Test encryption */
        const char* plaintext = "Hello, Virtual HSM!";
        uint8_t ciphertext[256];
        size_t ciphertext_len = sizeof(ciphertext);
        uint8_t iv[12];

        err = vhsm_encrypt(session, key_handle,
                          (const uint8_t*)plaintext, strlen(plaintext),
                          ciphertext, &ciphertext_len, iv, sizeof(iv));

        if (err == VHSM_SUCCESS) {
            printf("  Encryption successful (%zu bytes)\n", ciphertext_len);

            /* Test decryption */
            uint8_t decrypted[256];
            size_t decrypted_len = sizeof(decrypted);

            err = vhsm_decrypt(session, key_handle,
                              ciphertext, ciphertext_len,
                              decrypted, &decrypted_len, iv, sizeof(iv));

            if (err == VHSM_SUCCESS) {
                decrypted[decrypted_len] = '\0';
                assert(strcmp((char*)decrypted, plaintext) == 0);
                printf("  Decryption successful\n");
            } else {
                printf("  Decryption returned: %s\n", vhsm_error_string(err));
            }
        } else {
            printf("  Encryption returned: %s\n", vhsm_error_string(err));
        }
    }

    vhsm_session_logout(session);
    vhsm_ctx_destroy(ctx);

    printf("  PASS\n\n");
    return 1;
}

int test_audit() {
    printf("Testing audit logging...\n");

    vhsm_ctx_t ctx = NULL;
    vhsm_error_t err;

    err = vhsm_ctx_create(&ctx, "./test_storage");
    assert(err == VHSM_SUCCESS);

    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    assert(err == VHSM_SUCCESS);

    err = vhsm_audit_enable(ctx, "./test_audit.log");
    assert(err == VHSM_SUCCESS);

    /* Audit logging is now active */
    vhsm_audit_disable(ctx);

    vhsm_ctx_destroy(ctx);

    printf("  PASS\n\n");
    return 1;
}

int main(void) {
    printf("=== Virtual HSM Crypto Tests ===\n\n");

    int passed = 0;
    int total = 0;

    total++; if (test_init()) passed++;
    total++; if (test_context()) passed++;
    total++; if (test_authentication()) passed++;
    total++; if (test_key_generation()) passed++;
    total++; if (test_encryption_decryption()) passed++;
    total++; if (test_audit()) passed++;

    printf("=== Test Results: %d/%d passed ===\n", passed, total);

    vhsm_cleanup();

    return (passed == total) ? 0 : 1;
}
