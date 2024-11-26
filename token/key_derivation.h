#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

// Constants for key derivation
#define KEY_DERIVATION_INFO CONTEXT_INFO
#define KEY_DERIVATION_DIGEST EVP_sha256()

/**
 * Derives an encryption/decryption key using HKDF
 * 
 * @param master_key The input key material
 * @param master_key_len Length of the input key material
 * @param salt Salt value for key derivation
 * @param salt_len Length of the salt
 * @param derived_key Buffer to store the derived key
 * @param derived_key_len Desired length of the derived key
 * @return 1 on success, 0 on failure
 */
int derive_encryption_key(const unsigned char* master_key, 
                         size_t master_key_len,
                         const unsigned char* salt, 
                         size_t salt_len,
                         unsigned char* derived_key,
                         size_t derived_key_len) {
    
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    int ret = 0;
    const unsigned char info[] = KEY_DERIVATION_INFO;
    
    // Parameter validation
    if (!master_key || !salt || !derived_key || 
        master_key_len == 0 || salt_len == 0 || derived_key_len == 0) {
        return 0;
    }
    
    // Create HKDF object
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        goto cleanup;
    }
    
    // Create KDF context
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        goto cleanup;
    }
    
    // Set up HKDF parameters
    OSSL_PARAM params[5], *p = params;
    
    // Set digest algorithm
    *p++ = OSSL_PARAM_construct_utf8_string("digest", 
                                          (char*)EVP_MD_get0_name(KEY_DERIVATION_DIGEST), 
                                          0);
    
    // Set key
    *p++ = OSSL_PARAM_construct_octet_string("key", 
                                           (unsigned char*)master_key, 
                                           master_key_len);
    
    // Set salt
    *p++ = OSSL_PARAM_construct_octet_string("salt", 
                                           (unsigned char*)salt, 
                                           salt_len);
    
    // Set info
    *p++ = OSSL_PARAM_construct_octet_string("info", 
                                           (unsigned char*)info, 
                                           sizeof(info) - 1);  // Exclude null terminator
    
    // End parameter list
    *p = OSSL_PARAM_construct_end();
    
    // Perform key derivation
    if (EVP_KDF_derive(kctx, derived_key, derived_key_len, params) != 1) {
        goto cleanup;
    }
    
    ret = 1;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

#endif // KEY_DERIVATION_H