// metadata.h
#ifndef METADATA_H
#define METADATA_H

#include "security_defs.h"
#include "token_utils.h"    // Add for hash_token
#include "key_management.h" // Add for load_key
#include <openssl/evp.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    char token[TOKEN_SIZE];
    size_t data_size;
    unsigned char iv[IV_SIZE];
    char original_filename[256];
    size_t chunk_count;
    char chunk_hashes[MAX_CHUNKS][HASH_SIZE];
    size_t chunk_sizes[MAX_CHUNKS];
    unsigned char key_salt[crypto_kdf_KEYBYTES];  // Using KEYBYTES instead of SALTBYTES
    uint32_t version;
    unsigned char hmac[crypto_auth_BYTES];
} SecureMetadata;

typedef struct {
    uint32_t magic;
    size_t metadata_size;
    unsigned char iv[IV_SIZE];
} MetadataHeader;

// Function declarations
int save_metadata(const SecureMetadata* metadata);
int load_metadata(const char* token, SecureMetadata* metadata);
int validate_metadata(const SecureMetadata* metadata, const unsigned char* master_key);
int encrypt_metadata(const SecureMetadata* metadata, const unsigned char* key, const char* filepath);
int decrypt_metadata(const char* filepath, const unsigned char* key, SecureMetadata* metadata);


int save_metadata(const SecureMetadata* metadata) {
    char hashed_filename[HASH_SIZE];
    hash_token(metadata->token, hashed_filename);
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s.meta", STORAGE_PATH, hashed_filename);
    
    unsigned char key[KEY_SIZE];
    if (load_key(key) != 0) {
        printf("Error loading key for metadata encryption\n");
        return -1;
    }
    
    return encrypt_metadata(metadata, key, filepath);
}

int load_metadata(const char* token, SecureMetadata* metadata) {
    char hashed_filename[HASH_SIZE];
    hash_token(token, hashed_filename);
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s.meta", STORAGE_PATH, hashed_filename);
    
    unsigned char key[KEY_SIZE];
    if (load_key(key) != 0) {
        printf("Error loading key for metadata decryption\n");
        return -1;
    }
    
    return decrypt_metadata(filepath, key, metadata);
}

int validate_metadata(const SecureMetadata* metadata, 
                     const unsigned char* master_key) {
    unsigned char hmac[crypto_auth_BYTES];
    
    // Calculate HMAC of metadata fields
    crypto_auth(hmac, 
                (unsigned char*)metadata, 
                offsetof(SecureMetadata, hmac),
                master_key);
    
    // Constant time comparison
    return crypto_verify_32(hmac, metadata->hmac);
}

int encrypt_metadata(const SecureMetadata* metadata, const unsigned char* key, const char* filepath) {
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        printf("Error opening metadata file: %s\n", strerror(errno));
        return -1;
    }

    // Create and write header
    MetadataHeader header;
    header.magic = METADATA_MAGIC;
    header.metadata_size = sizeof(SecureMetadata);
    if (RAND_bytes(header.iv, IV_SIZE) != 1) {
        printf("Error generating IV for metadata\n");
        fclose(fp);
        return -1;
    }

    if (fwrite(&header, sizeof(MetadataHeader), 1, fp) != 1) {
        printf("Error writing metadata header\n");
        fclose(fp);
        return -1;
    }

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, header.iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    // Encrypt metadata
    int out_len;
    unsigned char* buffer_out = malloc(sizeof(SecureMetadata) + EVP_MAX_BLOCK_LENGTH);
    if (!buffer_out) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, buffer_out, &out_len, (unsigned char*)metadata, sizeof(SecureMetadata))) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    if (fwrite(buffer_out, 1, out_len, fp) != (size_t)out_len) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    int final_len;
    if (!EVP_EncryptFinal_ex(ctx, buffer_out + out_len, &final_len)) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    if (final_len > 0) {
        if (fwrite(buffer_out + out_len, 1, final_len, fp) != (size_t)final_len) {
            free(buffer_out);
            EVP_CIPHER_CTX_free(ctx);
            fclose(fp);
            return -1;
        }
    }

    // Write authentication tag
    unsigned char tag[16];
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    if (fwrite(tag, 1, 16, fp) != 16) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    free(buffer_out);
    EVP_CIPHER_CTX_free(ctx);
    fclose(fp);
    return 0;
}

int decrypt_metadata(const char* filepath, const unsigned char* key, SecureMetadata* metadata) {
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        printf("Error opening metadata file: %s\n", strerror(errno));
        return -1;
    }

    // Read and verify header
    MetadataHeader header;
    if (fread(&header, sizeof(MetadataHeader), 1, fp) != 1) {
        printf("Error reading metadata header\n");
        fclose(fp);
        return -1;
    }

    if (header.magic != METADATA_MAGIC) {
        printf("Invalid metadata file format\n");
        fclose(fp);
        return -1;
    }

    // Read encrypted data
    unsigned char* encrypted_data = malloc(header.metadata_size + 16);  // +16 for tag
    if (!encrypted_data) {
        fclose(fp);
        return -1;
    }

    size_t read_size = fread(encrypted_data, 1, header.metadata_size, fp);
    if (read_size != header.metadata_size) {
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Read authentication tag
    unsigned char tag[16];
    if (fread(tag, 1, 16, fp) != 16) {
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, header.iv)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Decrypt metadata
    int out_len;
    if (!EVP_DecryptUpdate(ctx, (unsigned char*)metadata, &out_len, encrypted_data, header.metadata_size)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Verify and finalize decryption
    int final_len;
    if (!EVP_DecryptFinal_ex(ctx, (unsigned char*)metadata + out_len, &final_len)) {
        printf("Error: Metadata authentication failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    free(encrypted_data);
    fclose(fp);
    return 0;
}













#endif // METADATA_H