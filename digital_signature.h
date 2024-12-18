#ifndef DIGITAL_SIGNATURE_H
#define DIGITAL_SIGNATURE_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

#include "hsm_shared.h" 

#define MAX_SIGNATURE_SIZE 256
#define SHA256_DIGEST_LENGTH 32

// Structure to hold a key pair
typedef struct {
    EVP_PKEY *pkey;
    char name[MAX_NAME_LENGTH + 1];
} KeyPair;

// Function prototype declarations
int generate_key_pair(const char *name);
int sign_data(const char *key_name, const unsigned char *data, size_t data_len, unsigned char *signature, size_t *sig_len);
int verify_signature(const char *key_name, const unsigned char *data, size_t data_len, const unsigned char *signature, size_t sig_len);
int export_public_key(const char *key_name, char **pem_key);
int import_public_key(const char *name, const char *pem_key);

// from virtual_hsm.c
void store_public_key(const char *name, const unsigned char *key, size_t key_len);

// Helper function to find a key pair by name
KeyPair *find_key_pair(const char *name) {
    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            KeyPair *pair = malloc(sizeof(KeyPair));
            if (!pair) {
                DEBUG_PRINT("Memory allocation failed for KeyPair");
                return NULL;
            }
            // ADD'L work needed
            //if (keystore[i].encrypted_len != KEY_SIZE || keystore[i].iv_len != IV_SIZE) {
            //    DEBUG_PRINT("Invalid key data for: %s", name);
            //    return NULL;
            //}
            
            strncpy(pair->name, name, MAX_NAME_LENGTH);
            pair->name[MAX_NAME_LENGTH] = '\0';

            if (keystore[i].is_public_key) {
                DEBUG_PRINT("Found public key: %s", name);
                pair->pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, keystore[i].key_data, KEY_SIZE);
            } else {
                DEBUG_PRINT("Found private key: %s", name);
                unsigned char decrypted_key[KEY_SIZE];
                int decrypted_len = decrypt_key(keystore[i].key_data, 
                                                keystore[i].encrypted_len,
                                                decrypted_key, 
                                                keystore[i].iv,
                                                keystore[i].tag);
                
                if (decrypted_len != KEY_SIZE) {
                    DEBUG_PRINT("Decryption failed for key: %s", name);
                    free(pair);
                    pair = NULL;
                    return NULL;
                }
                
                pair->pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, decrypted_key, KEY_SIZE);
            }
            
            if (!pair->pkey) {
                DEBUG_PRINT("Failed to create EVP_PKEY for key: %s", name);
                free(pair);
                pair = NULL;
                return NULL;
            }
            
            return pair;
        }
    }
    DEBUG_PRINT("Key not found: %s", name);
    return NULL;
}

// Generate a new Ed25519 key pair and store it in the HSM
int generate_key_pair(const char *name) {
	 // Check if a key with the same name already exists
    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            fprintf(stderr, "Duplicate Name, Cannot generate\n");
            return 0; // Indicate failure
        }
    }
	
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;
        return 0;
    }
    
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    
    size_t priv_len = KEY_SIZE;
    unsigned char priv_key[KEY_SIZE];
    
    if (EVP_PKEY_get_raw_private_key(pkey, priv_key, &priv_len) <= 0 || priv_len != KEY_SIZE) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        return 0;
    }
    
    store_key(name, priv_key, 0);  // 0 indicates it's a private key
    
    // Also store the public key
    size_t pub_len = KEY_SIZE;
    unsigned char pub_key[KEY_SIZE];
    
    if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &pub_len) <= 0 || pub_len != KEY_SIZE) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        return 0;
    }
    
    char pub_name[MAX_NAME_LENGTH + 1];
    snprintf(pub_name, sizeof(pub_name), "%s_public", name);
    store_public_key(pub_name, pub_key, pub_len);
    
    EVP_PKEY_free(pkey);
    pkey = NULL;
    return 1;
}

// Sign data using a key stored in the HSM
int sign_data(const char *key_name, const unsigned char *data, size_t data_len, unsigned char *signature, size_t *sig_len) {
    KeyPair *pair = find_key_pair(key_name);
    if (!pair) {
        DEBUG_PRINT("Key pair not found: %s", key_name);
        return 0;
    }
    
    unsigned char public_key_raw[KEY_SIZE];
    size_t public_key_len = KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(pair->pkey, public_key_raw, &public_key_len) > 0) {
        DEBUG_PRINT("Public key used for verification:");
        for (size_t i = 0; i < public_key_len; i++) {
            fprintf(stderr, "%02x", public_key_raw[i]);
        }
        fprintf(stderr, "\n");
    }
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        DEBUG_PRINT("Failed to create MD context");
        return 0;
    }
    
    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pair->pkey) <= 0) {
        DEBUG_PRINT("Failed to initialize signing");
        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
        return 0;
    }
    
    if (EVP_DigestSign(md_ctx, signature, sig_len, data, data_len) <= 0) {
        DEBUG_PRINT("Failed to sign data");
        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
        return 0;
    }
    
    DEBUG_PRINT("Data signed successfully, signature length: %zu", *sig_len);
    EVP_MD_CTX_free(md_ctx);
    md_ctx = NULL;
    return 1;
}

// Verify a signature using a key stored in the HSM
int verify_signature(const char *key_name, const unsigned char *data, size_t data_len, const unsigned char *signature, size_t sig_len) {
    KeyPair *pair = find_key_pair(key_name);
    if (!pair) {
        DEBUG_PRINT("Key pair not found: %s", key_name);
        return 0;
    }
    
    unsigned char public_key_raw[KEY_SIZE];
    size_t public_key_len = KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(pair->pkey, public_key_raw, &public_key_len) > 0) {
        DEBUG_PRINT("Public key used for verification:");
        for (size_t i = 0; i < public_key_len; i++) {
            fprintf(stderr, "%02x", public_key_raw[i]);
        }
        fprintf(stderr, "\n");
    }
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        DEBUG_PRINT("Failed to create MD context");
        return 0;
    }
    
    if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pair->pkey) <= 0) {
        DEBUG_PRINT("Failed to initialize verification");
        EVP_MD_CTX_free(md_ctx);
        md_ctx = NULL;
        return 0;
    }
    
    int ret = EVP_DigestVerify(md_ctx, signature, sig_len, data, data_len);
    
    if (ret == 1) {
        DEBUG_PRINT("Signature verified successfully");
    } else if (ret == 0) {
        DEBUG_PRINT("Signature verification failed - invalid signature");
    } else {
        DEBUG_PRINT("Signature verification failed - error occurred");
        ERR_print_errors_fp(stderr);
    }
    
    EVP_MD_CTX_free(md_ctx);
    md_ctx = NULL;
    return (ret == 1);
}

// Export the public key in PEM format
int export_public_key(const char *key_name, char **pem_key) {
    KeyPair *pair = find_key_pair(key_name);
    if (!pair) {
        return 0;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || PEM_write_bio_PUBKEY(bio, pair->pkey) <= 0) {
        BIO_free(bio);
        bio = NULL;
        return 0;
    }
    
    long pem_size = BIO_get_mem_data(bio, pem_key);
    *pem_key = malloc(pem_size + 1);
    BIO_read(bio, *pem_key, pem_size);
    (*pem_key)[pem_size] = '\0';
    
    BIO_free(bio);
    bio = NULL;
    return 1;
}

// Import a public key in PEM format
int import_public_key(const char *name, const char *pem_key) {
    BIO *bio = BIO_new_mem_buf(pem_key, -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    bio = NULL;
    
    if (!pkey) {
        return 0;
    }
    
    unsigned char key_data[KEY_SIZE];
    size_t key_len = sizeof(key_data);
    
    if (EVP_PKEY_get_raw_public_key(pkey, key_data, &key_len) <= 0 || key_len != KEY_SIZE) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        return 0;
    }
    
    // Store public key without encryption
    store_public_key(name, key_data, key_len);
    EVP_PKEY_free(pkey);
    pkey = NULL;
    return 1;
}

#endif // DIGITAL_SIGNATURE_H
