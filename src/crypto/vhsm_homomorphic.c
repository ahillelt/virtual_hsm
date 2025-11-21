#include "vhsm.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

/*
 * Paillier Homomorphic Encryption Implementation
 *
 * Provides homomorphic addition: E(m1) * E(m2) = E(m1 + m2)
 * This allows computations on encrypted data without decryption.
 */

#define PAILLIER_KEY_BITS 1024

/* Paillier public key */
typedef struct {
    BIGNUM* n;      /* n = p * q */
    BIGNUM* g;      /* g = n + 1 */
    BIGNUM* n2;     /* n^2 */
} paillier_public_key_t;

/* Paillier private key */
typedef struct {
    BIGNUM* lambda;  /* λ = lcm(p-1, q-1) */
    BIGNUM* mu;      /* μ = (L(g^λ mod n^2))^-1 mod n */
    BIGNUM* n;       /* n = p * q */
    BIGNUM* n2;      /* n^2 */
} paillier_private_key_t;

/* Generate Paillier key pair */
int paillier_generate_keypair(paillier_public_key_t* pub, paillier_private_key_t* priv) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return 0;

    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* p_minus_1 = BN_new();
    BIGNUM* q_minus_1 = BN_new();
    BIGNUM* lambda = BN_new();
    BIGNUM* gcd = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* g_lambda = BN_new();
    BIGNUM* l_result = BN_new();

    if (!p || !q || !p_minus_1 || !q_minus_1 || !lambda || !gcd || !temp || !g_lambda || !l_result) {
        goto cleanup;
    }

    /* Generate two large primes p and q */
    if (!BN_generate_prime_ex(p, PAILLIER_KEY_BITS / 2, 0, NULL, NULL, NULL) ||
        !BN_generate_prime_ex(q, PAILLIER_KEY_BITS / 2, 0, NULL, NULL, NULL)) {
        goto cleanup;
    }

    /* Calculate n = p * q */
    pub->n = BN_new();
    priv->n = BN_new();
    if (!BN_mul(pub->n, p, q, ctx)) goto cleanup;
    BN_copy(priv->n, pub->n);

    /* Calculate n^2 */
    pub->n2 = BN_new();
    priv->n2 = BN_new();
    if (!BN_sqr(pub->n2, pub->n, ctx)) goto cleanup;
    BN_copy(priv->n2, pub->n2);

    /* g = n + 1 (simplified version) */
    pub->g = BN_new();
    if (!BN_add(pub->g, pub->n, BN_value_one())) goto cleanup;

    /* Calculate λ = lcm(p-1, q-1) */
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());

    /* λ = (p-1)(q-1) / gcd(p-1, q-1) */
    if (!BN_gcd(gcd, p_minus_1, q_minus_1, ctx)) goto cleanup;
    if (!BN_mul(temp, p_minus_1, q_minus_1, ctx)) goto cleanup;

    priv->lambda = BN_new();
    if (!BN_div(priv->lambda, NULL, temp, gcd, ctx)) goto cleanup;

    /* Calculate μ = (L(g^λ mod n^2))^-1 mod n */
    /* L(x) = (x-1)/n */
    if (!BN_mod_exp(g_lambda, pub->g, priv->lambda, pub->n2, ctx)) goto cleanup;
    BN_sub(temp, g_lambda, BN_value_one());
    if (!BN_div(l_result, NULL, temp, pub->n, ctx)) goto cleanup;

    priv->mu = BN_new();
    if (!BN_mod_inverse(priv->mu, l_result, pub->n, ctx)) goto cleanup;

    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(q);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_free(lambda);
    BN_free(gcd);
    BN_free(temp);
    BN_free(g_lambda);
    BN_free(l_result);

    return 1;

cleanup:
    BN_CTX_free(ctx);
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (p_minus_1) BN_free(p_minus_1);
    if (q_minus_1) BN_free(q_minus_1);
    if (lambda) BN_free(lambda);
    if (gcd) BN_free(gcd);
    if (temp) BN_free(temp);
    if (g_lambda) BN_free(g_lambda);
    if (l_result) BN_free(l_result);

    return 0;
}

/* Paillier encryption */
int paillier_encrypt(const paillier_public_key_t* pub, const BIGNUM* plaintext,
                     BIGNUM* ciphertext) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return 0;

    BIGNUM* r = BN_new();
    BIGNUM* g_m = BN_new();
    BIGNUM* r_n = BN_new();

    if (!r || !g_m || !r_n) {
        goto cleanup;
    }

    /* Generate random r where 0 < r < n and gcd(r,n) = 1 */
    do {
        if (!BN_rand_range(r, pub->n)) goto cleanup;
    } while (BN_is_zero(r));

    /* c = g^m * r^n mod n^2 */
    /* g^m mod n^2 */
    if (!BN_mod_exp(g_m, pub->g, plaintext, pub->n2, ctx)) goto cleanup;

    /* r^n mod n^2 */
    if (!BN_mod_exp(r_n, r, pub->n, pub->n2, ctx)) goto cleanup;

    /* c = g^m * r^n mod n^2 */
    if (!BN_mod_mul(ciphertext, g_m, r_n, pub->n2, ctx)) goto cleanup;

    BN_CTX_free(ctx);
    BN_free(r);
    BN_free(g_m);
    BN_free(r_n);
    return 1;

cleanup:
    BN_CTX_free(ctx);
    if (r) BN_free(r);
    if (g_m) BN_free(g_m);
    if (r_n) BN_free(r_n);
    return 0;
}

/* Paillier decryption */
int paillier_decrypt(const paillier_private_key_t* priv, const BIGNUM* ciphertext,
                     BIGNUM* plaintext) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return 0;

    BIGNUM* c_lambda = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* l_result = BN_new();

    if (!c_lambda || !temp || !l_result) {
        goto cleanup;
    }

    /* m = L(c^λ mod n^2) * μ mod n */
    /* c^λ mod n^2 */
    if (!BN_mod_exp(c_lambda, ciphertext, priv->lambda, priv->n2, ctx)) goto cleanup;

    /* L(c^λ) = (c^λ - 1) / n */
    BN_sub(temp, c_lambda, BN_value_one());
    if (!BN_div(l_result, NULL, temp, priv->n, ctx)) goto cleanup;

    /* m = L * μ mod n */
    if (!BN_mod_mul(plaintext, l_result, priv->mu, priv->n, ctx)) goto cleanup;

    BN_CTX_free(ctx);
    BN_free(c_lambda);
    BN_free(temp);
    BN_free(l_result);
    return 1;

cleanup:
    BN_CTX_free(ctx);
    if (c_lambda) BN_free(c_lambda);
    if (temp) BN_free(temp);
    if (l_result) BN_free(l_result);
    return 0;
}

/* Homomorphic addition: E(m1) * E(m2) = E(m1 + m2) */
int paillier_add(const paillier_public_key_t* pub, const BIGNUM* c1, const BIGNUM* c2,
                 BIGNUM* result) {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return 0;

    /* result = c1 * c2 mod n^2 */
    int ret = BN_mod_mul(result, c1, c2, pub->n2, ctx);

    BN_CTX_free(ctx);
    return ret;
}

/* Free keys */
void paillier_free_public_key(paillier_public_key_t* pub) {
    if (!pub) return;
    if (pub->n) BN_free(pub->n);
    if (pub->g) BN_free(pub->g);
    if (pub->n2) BN_free(pub->n2);
}

void paillier_free_private_key(paillier_private_key_t* priv) {
    if (!priv) return;
    if (priv->lambda) BN_free(priv->lambda);
    if (priv->mu) BN_free(priv->mu);
    if (priv->n) BN_free(priv->n);
    if (priv->n2) BN_free(priv->n2);
}

/* High-level API for HSM integration */

typedef struct {
    paillier_public_key_t public_key;
    paillier_private_key_t private_key;
    int initialized;
} vhsm_he_context_t;

vhsm_he_context_t* vhsm_he_init(void) {
    vhsm_he_context_t* he_ctx = calloc(1, sizeof(vhsm_he_context_t));
    if (!he_ctx) return NULL;

    if (!paillier_generate_keypair(&he_ctx->public_key, &he_ctx->private_key)) {
        free(he_ctx);
        return NULL;
    }

    he_ctx->initialized = 1;
    return he_ctx;
}

void vhsm_he_cleanup(vhsm_he_context_t* he_ctx) {
    if (!he_ctx) return;

    paillier_free_public_key(&he_ctx->public_key);
    paillier_free_private_key(&he_ctx->private_key);
    free(he_ctx);
}

/* Encrypt integer */
vhsm_error_t vhsm_he_encrypt_int(vhsm_he_context_t* he_ctx, int64_t plaintext,
                                  uint8_t* ciphertext, size_t* ciphertext_len) {
    if (!he_ctx || !he_ctx->initialized || !ciphertext || !ciphertext_len) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    BIGNUM* m = BN_new();
    BIGNUM* c = BN_new();

    if (!m || !c) {
        if (m) BN_free(m);
        if (c) BN_free(c);
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    /* Convert plaintext to BIGNUM */
    if (plaintext < 0) {
        BN_set_word(m, (unsigned long)(-plaintext));
        BN_set_negative(m, 1);
    } else {
        BN_set_word(m, (unsigned long)plaintext);
    }

    /* Encrypt */
    if (!paillier_encrypt(&he_ctx->public_key, m, c)) {
        BN_free(m);
        BN_free(c);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    /* Convert to bytes */
    int c_len = BN_num_bytes(c);
    if ((size_t)c_len > *ciphertext_len) {
        BN_free(m);
        BN_free(c);
        return VHSM_ERROR_BUFFER_TOO_SMALL;
    }

    BN_bn2bin(c, ciphertext);
    *ciphertext_len = c_len;

    BN_free(m);
    BN_free(c);

    return VHSM_SUCCESS;
}

/* Decrypt integer */
vhsm_error_t vhsm_he_decrypt_int(vhsm_he_context_t* he_ctx,
                                  const uint8_t* ciphertext, size_t ciphertext_len,
                                  int64_t* plaintext) {
    if (!he_ctx || !he_ctx->initialized || !ciphertext || !plaintext) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    BIGNUM* c = BN_bin2bn(ciphertext, ciphertext_len, NULL);
    BIGNUM* m = BN_new();

    if (!c || !m) {
        if (c) BN_free(c);
        if (m) BN_free(m);
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    /* Decrypt */
    if (!paillier_decrypt(&he_ctx->private_key, c, m)) {
        BN_free(c);
        BN_free(m);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    /* Convert to int64_t */
    *plaintext = BN_get_word(m);
    if (BN_is_negative(m)) {
        *plaintext = -(*plaintext);
    }

    BN_free(c);
    BN_free(m);

    return VHSM_SUCCESS;
}

/* Homomorphic addition on encrypted values */
vhsm_error_t vhsm_he_add(vhsm_he_context_t* he_ctx,
                          const uint8_t* c1, size_t c1_len,
                          const uint8_t* c2, size_t c2_len,
                          uint8_t* result, size_t* result_len) {
    if (!he_ctx || !he_ctx->initialized || !c1 || !c2 || !result || !result_len) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    BIGNUM* cipher1 = BN_bin2bn(c1, c1_len, NULL);
    BIGNUM* cipher2 = BN_bin2bn(c2, c2_len, NULL);
    BIGNUM* sum = BN_new();

    if (!cipher1 || !cipher2 || !sum) {
        if (cipher1) BN_free(cipher1);
        if (cipher2) BN_free(cipher2);
        if (sum) BN_free(sum);
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    /* Homomorphic addition */
    if (!paillier_add(&he_ctx->public_key, cipher1, cipher2, sum)) {
        BN_free(cipher1);
        BN_free(cipher2);
        BN_free(sum);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    /* Convert to bytes */
    int sum_len = BN_num_bytes(sum);
    if ((size_t)sum_len > *result_len) {
        BN_free(cipher1);
        BN_free(cipher2);
        BN_free(sum);
        return VHSM_ERROR_BUFFER_TOO_SMALL;
    }

    BN_bn2bin(sum, result);
    *result_len = sum_len;

    BN_free(cipher1);
    BN_free(cipher2);
    BN_free(sum);

    return VHSM_SUCCESS;
}
