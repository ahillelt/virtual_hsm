#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* External declarations for homomorphic encryption */
typedef struct vhsm_he_context_s vhsm_he_context_t;

extern vhsm_he_context_t* vhsm_he_init(void);
extern void vhsm_he_cleanup(vhsm_he_context_t* he_ctx);
extern int vhsm_he_encrypt_int(vhsm_he_context_t* he_ctx, int64_t plaintext,
                                uint8_t* ciphertext, size_t* ciphertext_len);
extern int vhsm_he_decrypt_int(vhsm_he_context_t* he_ctx,
                                const uint8_t* ciphertext, size_t ciphertext_len,
                                int64_t* plaintext);
extern int vhsm_he_add(vhsm_he_context_t* he_ctx,
                        const uint8_t* c1, size_t c1_len,
                        const uint8_t* c2, size_t c2_len,
                        uint8_t* result, size_t* result_len);

int test_homomorphic_encryption() {
    printf("Testing Paillier homomorphic encryption...\n");

    vhsm_he_context_t* he_ctx = vhsm_he_init();
    assert(he_ctx != NULL);
    printf("  Initialized Paillier context\n");

    /* Test values */
    int64_t m1 = 100;
    int64_t m2 = 200;

    /* Encrypt m1 */
    uint8_t c1[512];
    size_t c1_len = sizeof(c1);
    int ret = vhsm_he_encrypt_int(he_ctx, m1, c1, &c1_len);
    assert(ret == 0);
    printf("  Encrypted %ld (%zu bytes)\n", m1, c1_len);

    /* Encrypt m2 */
    uint8_t c2[512];
    size_t c2_len = sizeof(c2);
    ret = vhsm_he_encrypt_int(he_ctx, m2, c2, &c2_len);
    assert(ret == 0);
    printf("  Encrypted %ld (%zu bytes)\n", m2, c2_len);

    /* Homomorphic addition: E(m1) * E(m2) = E(m1 + m2) */
    uint8_t c_sum[512];
    size_t c_sum_len = sizeof(c_sum);
    ret = vhsm_he_add(he_ctx, c1, c1_len, c2, c2_len, c_sum, &c_sum_len);
    assert(ret == 0);
    printf("  Performed homomorphic addition\n");

    /* Decrypt sum */
    int64_t m_sum;
    ret = vhsm_he_decrypt_int(he_ctx, c_sum, c_sum_len, &m_sum);
    assert(ret == 0);
    printf("  Decrypted sum: %ld\n", m_sum);

    /* Verify: m_sum should equal m1 + m2 */
    assert(m_sum == m1 + m2);
    printf("  Verification: %ld + %ld = %ld ✓\n", m1, m2, m_sum);

    vhsm_he_cleanup(he_ctx);
    printf("  PASS\n\n");

    return 1;
}

int test_homomorphic_multiple_operations() {
    printf("Testing multiple homomorphic operations...\n");

    vhsm_he_context_t* he_ctx = vhsm_he_init();
    assert(he_ctx != NULL);

    /* Test: (10 + 20) + 30 = 60 */
    int64_t values[] = {10, 20, 30};
    uint8_t ciphertexts[3][512];
    size_t lengths[3];

    /* Encrypt all values */
    for (int i = 0; i < 3; i++) {
        lengths[i] = 512;
        int ret = vhsm_he_encrypt_int(he_ctx, values[i], ciphertexts[i], &lengths[i]);
        assert(ret == 0);
        printf("  Encrypted %ld\n", values[i]);
    }

    /* Add first two */
    uint8_t temp_sum[512];
    size_t temp_len = 512;
    int ret = vhsm_he_add(he_ctx, ciphertexts[0], lengths[0],
                          ciphertexts[1], lengths[1], temp_sum, &temp_len);
    assert(ret == 0);

    /* Add third */
    uint8_t final_sum[512];
    size_t final_len = 512;
    ret = vhsm_he_add(he_ctx, temp_sum, temp_len,
                      ciphertexts[2], lengths[2], final_sum, &final_len);
    assert(ret == 0);

    /* Decrypt and verify */
    int64_t result;
    ret = vhsm_he_decrypt_int(he_ctx, final_sum, final_len, &result);
    assert(ret == 0);

    int64_t expected = values[0] + values[1] + values[2];
    assert(result == expected);
    printf("  Result: %ld + %ld + %ld = %ld ✓\n",
           values[0], values[1], values[2], result);

    vhsm_he_cleanup(he_ctx);
    printf("  PASS\n\n");

    return 1;
}

int main(void) {
    printf("=== Virtual HSM Homomorphic Encryption Tests ===\n\n");

    int passed = 0;
    int total = 0;

    total++; if (test_homomorphic_encryption()) passed++;
    total++; if (test_homomorphic_multiple_operations()) passed++;

    printf("=== Test Results: %d/%d passed ===\n", passed, total);

    return (passed == total) ? 0 : 1;
}
