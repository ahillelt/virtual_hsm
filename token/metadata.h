// metadata.h
#ifndef METADATA_H
#define METADATA_H

#include "security_defs.h"
#include "token_utils.h"
#include "key_management.h"
#include <openssl/evp.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

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
        printf(!DEBUG ? "" :"Error loading key for metadata encryption\n");
        return -1;
    }
    
    return encrypt_metadata(metadata, key, filepath);
}

int load_metadata(const char* token, SecureMetadata* metadata) {
    // Additional null and length checks
    if (!token || !metadata || strlen(token) == 0) {
        fprintf(stderr,!DEBUG ? "" : "Invalid token or metadata pointer\n");
        return -1;
    }

    char hashed_filename[HASH_SIZE];
    hash_token(token, hashed_filename);
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s.meta", STORAGE_PATH, hashed_filename);
    
    // Verify file exists
    FILE* test_file = fopen(filepath, "rb");
    if (!test_file) {
        fprintf(stderr,!DEBUG ? "" : "Metadata file not found: %s\n", filepath);
        return -1;
    }
    fclose(test_file);

    unsigned char key[KEY_SIZE];
    if (load_key(key) != 0) {
        fprintf(stderr,!DEBUG ? "" : "Error loading key for metadata decryption\n");
        return -1;
    }
    
    int decrypt_result = decrypt_metadata(filepath, key, metadata);
    
    // Additional validation after decryption
    if (decrypt_result == 0) {
        if (metadata->file_size == 0) {
            fprintf(stderr,!DEBUG ? "" : "Warning: Decrypted metadata has zero file size\n");
        }
        if (metadata->chunk_count == 0) {
            fprintf(stderr,!DEBUG ? "" : "Warning: Decrypted metadata has zero chunk count\n");
        }
    }
    
    return decrypt_result;
}


int validate_metadata_secure(const SecureMetadata* metadata, const unsigned char* master_key) {
	if (!metadata || !master_key) {
        fprintf(stderr,!DEBUG ? "" : "Invalid metadata or master key\n");
        return 0;
    }
	
	if (metadata->file_size == 0) {
        fprintf(stderr,!DEBUG ? "" : "Warning: Metadata file size is zero\n");
        return 0;
    }
    unsigned char expected_hmac[crypto_auth_BYTES];
	
    crypto_auth(expected_hmac, 
               (unsigned char*)metadata, 
               offsetof(SecureMetadata, hmac), 
               master_key);
               
    // Use constant-time comparison
    return CRYPTO_memcmp(expected_hmac, 
                        metadata->hmac, 
                        crypto_auth_BYTES) == 0;
}
int encrypt_metadata(const SecureMetadata* metadata, const unsigned char* key, const char* filepath) {
	printf(SILENT ? "" :"Encrypting metadata:\n");
    printf(SILENT ? "" :"Token: %s\n", metadata->token);
    printf(SILENT ? "" :"File Size: %zu\n", metadata->file_size);
    printf(SILENT ? "" :"Original Filename: %s\n", metadata->original_filename);
	
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        printf(!DEBUG ? "" :"Error opening metadata file: %s\n", strerror(errno));
        return -1;
    }

    // Create and write header
    MetadataHeader header;
    header.magic = METADATA_MAGIC;
    header.metadata_size = sizeof(SecureMetadata);
    if (RAND_bytes(header.iv, IV_SIZE) != 1) {
        printf(!DEBUG ? "" :"Error generating IV for metadata\n");
        fclose(fp);
        return -1;
    }

    if (fwrite(&header, sizeof(MetadataHeader), 1, fp) != 1) {
        printf(!DEBUG ? "" :"Error writing metadata header\n");
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
    if (filepath == NULL || key == NULL || metadata == NULL) {
        fprintf(stderr,!DEBUG ? "" : "Error: Null parameters in decrypt_metadata\n");
        return -1;
    }
	
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr,!DEBUG ? "" : "Error opening metadata file: %s (errno: %d)\n", 
                strerror(errno), errno);
        return -1;
    }

    // Read and verify header
    MetadataHeader header;
    if (fread(&header, sizeof(MetadataHeader), 1, fp) != 1) {
        fprintf(stderr,!DEBUG ? "" : "Error reading metadata header\n");
        fclose(fp);
        return -1;
    }

    if (header.magic != METADATA_MAGIC) {
        fprintf(stderr,!DEBUG ? "" : "Invalid metadata file format (magic number mismatch)\n");
        fclose(fp);
        return -1;
    }

    // Ensure metadata size is within expected bounds
    if (header.metadata_size > sizeof(SecureMetadata)) {
        fprintf(stderr,!DEBUG ? "" : "Metadata size exceeds maximum allowed size\n");
        fclose(fp);
        return -1;
    }

    // Read encrypted data
    unsigned char* encrypted_data = malloc(header.metadata_size + EVP_MAX_BLOCK_LENGTH);
    if (!encrypted_data) {
        fprintf(stderr,!DEBUG ? "" : "Memory allocation failed for metadata decryption\n");
        fclose(fp);
        return -1;
    }

    size_t read_size = fread(encrypted_data, 1, header.metadata_size, fp);
    if (read_size != header.metadata_size) {
        fprintf(stderr,!DEBUG ? "" : "Incomplete metadata read (expected %zu, got %zu)\n", 
                header.metadata_size, read_size);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Read authentication tag
    unsigned char tag[16];
    if (fread(tag, 1, 16, fp) != 16) {
        fprintf(stderr,!DEBUG ? "" : "Failed to read authentication tag\n");
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr,!DEBUG ? "" : "Failed to create cipher context\n");
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, header.iv)) {
        fprintf(stderr,!DEBUG ? "" : "Decryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Decrypt metadata
    unsigned char* decrypted_data = malloc(header.metadata_size + EVP_MAX_BLOCK_LENGTH);
    if (!decrypted_data) {
        fprintf(stderr, "Memory allocation failed for decrypted metadata\n");
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    int out_len = 0;
    if (!EVP_DecryptUpdate(ctx, decrypted_data, &out_len, encrypted_data, header.metadata_size)) {
        fprintf(stderr,!DEBUG ? "" : "Metadata decryption update failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        free(decrypted_data);
        fclose(fp);
        return -1;
    }

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        fprintf(stderr,!DEBUG ? "" : "Failed to set authentication tag\n");
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        free(decrypted_data);
        fclose(fp);
        return -1;
    }

    // Verify and finalize decryption
    int final_len = 0;
    if (!EVP_DecryptFinal_ex(ctx, decrypted_data + out_len, &final_len)) {
        fprintf(stderr,!DEBUG ? "" : "Metadata authentication failed (decryption final)\n");
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        free(decrypted_data);
        fclose(fp);
        return -1;
    }

    // Copy decrypted data to metadata
    memcpy(metadata, decrypted_data, header.metadata_size);

    EVP_CIPHER_CTX_free(ctx);
    free(encrypted_data);
    free(decrypted_data);
	encrypted_data = NULL;
	decrypted_data = NULL;
    fclose(fp);
    return 0;
}



#endif // METADATA_H