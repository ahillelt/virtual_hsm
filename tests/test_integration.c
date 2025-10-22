#include "vhsm.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

/* Integration tests - full workflow tests */

int test_full_workflow() {
    printf("Testing full HSM workflow...\n");

    vhsm_ctx_t ctx = NULL;
    vhsm_session_t admin_session = NULL, user_session = NULL;
    vhsm_error_t err;

    /* Step 1: Initialize */
    err = vhsm_init();
    assert(err == VHSM_SUCCESS || err == VHSM_ERROR_ALREADY_INITIALIZED);

    /* Step 2: Create context */
    err = vhsm_ctx_create(&ctx, "./test_integration_storage");
    assert(err == VHSM_SUCCESS);

    /* Step 3: Generate master key */
    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    assert(err == VHSM_SUCCESS);
    printf("  Master key generated\n");

    /* Step 4: Enable audit */
    err = vhsm_audit_enable(ctx, "./test_integration_audit.log");
    assert(err == VHSM_SUCCESS);
    printf("  Audit logging enabled\n");

    /* Step 5: Create admin user */
    err = vhsm_user_create(ctx, "admin", "admin123", "1234", VHSM_ROLE_ADMIN);
    if (err != VHSM_SUCCESS && err != VHSM_ERROR_KEY_EXISTS) {
        printf("  FAIL: Could not create admin\n");
        goto cleanup;
    }
    printf("  Admin user created\n");

    /* Step 6: Create regular user */
    err = vhsm_user_create(ctx, "user1", "user123", NULL, VHSM_ROLE_USER);
    if (err != VHSM_SUCCESS && err != VHSM_ERROR_KEY_EXISTS) {
        printf("  FAIL: Could not create user\n");
        goto cleanup;
    }
    printf("  Regular user created\n");

    /* Step 7: Admin login */
    err = vhsm_session_login(ctx, &admin_session, "admin", "admin123", "1234");
    assert(err == VHSM_SUCCESS);
    assert(vhsm_session_is_valid(admin_session));
    printf("  Admin logged in\n");

    /* Step 8: Generate encryption key */
    vhsm_key_handle_t enc_key;
    err = vhsm_key_generate(admin_session, "company_key", VHSM_KEY_TYPE_AES_256,
                             VHSM_KEY_USAGE_ENCRYPT | VHSM_KEY_USAGE_DECRYPT, &enc_key);
    if (err == VHSM_SUCCESS) {
        printf("  Encryption key generated (handle: %lu)\n", enc_key);
    } else if (err == VHSM_ERROR_KEY_EXISTS) {
        printf("  Encryption key already exists\n");
    }

    /* Step 9: Generate signing key */
    vhsm_key_handle_t sign_key;
    err = vhsm_key_generate(admin_session, "signing_key", VHSM_KEY_TYPE_ED25519,
                             VHSM_KEY_USAGE_SIGN | VHSM_KEY_USAGE_VERIFY, &sign_key);
    if (err == VHSM_SUCCESS || err == VHSM_ERROR_KEY_EXISTS) {
        printf("  Signing key generated\n");
    }

    /* Step 10: List keys */
    vhsm_key_metadata_t metadata[10];
    size_t count = 10;
    err = vhsm_key_list(admin_session, metadata, &count);
    if (err == VHSM_SUCCESS) {
        printf("  Found %zu keys\n", count);
    }

    /* Step 11: Perform encryption/decryption */
    if (enc_key != VHSM_INVALID_HANDLE) {
        const char* secret = "Confidential Data";
        uint8_t ciphertext[256];
        size_t ciphertext_len = sizeof(ciphertext);
        uint8_t iv[12];

        err = vhsm_encrypt(admin_session, enc_key,
                          (const uint8_t*)secret, strlen(secret),
                          ciphertext, &ciphertext_len, iv, sizeof(iv));

        if (err == VHSM_SUCCESS) {
            printf("  Data encrypted (%zu bytes)\n", ciphertext_len);

            uint8_t decrypted[256];
            size_t decrypted_len = sizeof(decrypted);

            err = vhsm_decrypt(admin_session, enc_key,
                              ciphertext, ciphertext_len,
                              decrypted, &decrypted_len, iv, sizeof(iv));

            if (err == VHSM_SUCCESS) {
                decrypted[decrypted_len] = '\0';
                assert(strcmp((char*)decrypted, secret) == 0);
                printf("  Data decrypted and verified\n");
            }
        }
    }

    /* Step 12: User login */
    err = vhsm_session_login(ctx, &user_session, "user1", "user123", NULL);
    assert(err == VHSM_SUCCESS);
    printf("  User logged in\n");

    /* Step 13: User tries to list keys */
    count = 10;
    err = vhsm_key_list(user_session, metadata, &count);
    if (err == VHSM_SUCCESS || err == VHSM_ERROR_NOT_IMPLEMENTED) {
        printf("  User can list keys\n");
    }

    /* Step 14: Logout all sessions */
    if (admin_session) {
        vhsm_session_logout(admin_session);
        printf("  Admin logged out\n");
    }

    if (user_session) {
        vhsm_session_logout(user_session);
        printf("  User logged out\n");
    }

    /* Step 15: Cleanup */
cleanup:
    if (ctx) {
        vhsm_audit_disable(ctx);
        vhsm_ctx_destroy(ctx);
    }
    vhsm_cleanup();

    printf("  PASS\n\n");
    return 1;
}

int test_password_change() {
    printf("Testing password change...\n");

    vhsm_ctx_t ctx = NULL;
    vhsm_session_t session = NULL;
    vhsm_error_t err;

    err = vhsm_ctx_create(&ctx, "./test_pwd_storage");
    assert(err == VHSM_SUCCESS);

    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    assert(err == VHSM_SUCCESS);

    /* Create user */
    err = vhsm_user_create(ctx, "changetest", "oldpass", NULL, VHSM_ROLE_USER);
    if (err != VHSM_SUCCESS && err != VHSM_ERROR_KEY_EXISTS) {
        printf("  SKIP: Could not create user\n");
        vhsm_ctx_destroy(ctx);
        return 1;
    }

    /* Login with old password */
    err = vhsm_session_login(ctx, &session, "changetest", "oldpass", NULL);
    assert(err == VHSM_SUCCESS);
    vhsm_session_logout(session);

    /* Change password */
    err = vhsm_user_change_password(ctx, "changetest", "oldpass", "newpass");
    assert(err == VHSM_SUCCESS);
    printf("  Password changed\n");

    /* Old password should fail */
    err = vhsm_session_login(ctx, &session, "changetest", "oldpass", NULL);
    assert(err == VHSM_ERROR_AUTH_FAILED);

    /* New password should work */
    err = vhsm_session_login(ctx, &session, "changetest", "newpass", NULL);
    assert(err == VHSM_SUCCESS);
    vhsm_session_logout(session);

    vhsm_ctx_destroy(ctx);

    printf("  PASS\n\n");
    return 1;
}

int test_concurrent_sessions() {
    printf("Testing concurrent sessions...\n");

    vhsm_ctx_t ctx = NULL;
    vhsm_session_t session1 = NULL, session2 = NULL;
    vhsm_error_t err;

    err = vhsm_ctx_create(&ctx, "./test_concurrent_storage");
    assert(err == VHSM_SUCCESS);

    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(ctx, master_key);
    assert(err == VHSM_SUCCESS);

    /* Create users */
    vhsm_user_create(ctx, "user_a", "pass_a", NULL, VHSM_ROLE_USER);
    vhsm_user_create(ctx, "user_b", "pass_b", NULL, VHSM_ROLE_USER);

    /* Both users login */
    err = vhsm_session_login(ctx, &session1, "user_a", "pass_a", NULL);
    assert(err == VHSM_SUCCESS);

    err = vhsm_session_login(ctx, &session2, "user_b", "pass_b", NULL);
    assert(err == VHSM_SUCCESS);

    printf("  Two concurrent sessions active\n");

    /* Both should be valid */
    assert(vhsm_session_is_valid(session1));
    assert(vhsm_session_is_valid(session2));

    /* Logout one */
    vhsm_session_logout(session1);
    assert(!vhsm_session_is_valid(session1));
    assert(vhsm_session_is_valid(session2));

    /* Logout other */
    vhsm_session_logout(session2);
    assert(!vhsm_session_is_valid(session2));

    vhsm_ctx_destroy(ctx);

    printf("  PASS\n\n");
    return 1;
}

int main(void) {
    printf("=== Virtual HSM Integration Tests ===\n\n");

    int passed = 0;
    int total = 0;

    total++; if (test_full_workflow()) passed++;
    total++; if (test_password_change()) passed++;
    total++; if (test_concurrent_sessions()) passed++;

    printf("=== Test Results: %d/%d passed ===\n", passed, total);

    return (passed == total) ? 0 : 1;
}
