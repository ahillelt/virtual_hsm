// crypto_ops.h
#ifndef CRYPTO_OPS_H
#define CRYPTO_OPS_H 

#include "security_defs.h"
#include "metadata.h"
#include "file_ops.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>

// Function signatures
int encrypt_file_secure(const char* input_path, 
                       char** chunk_paths,
                       size_t chunk_count, 
                       unsigned char* master_key,
                       SecureMetadata* metadata,
                       SecurityError* error);
int decrypt_file_chunked(const char* output_dir, 
                        unsigned char* key, 
                        const SecureMetadata* metadata);
int decrypt_file_core(FILE* ifp, FILE* ofp, 
                     unsigned char* key, 
                     const unsigned char* iv,
                     size_t chunk_size);
                     
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex);

void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex) {
    if (!bytes || !hex) return;
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

int encrypt_file_secure(const char* input_path, 
                       char** chunk_paths,
                       size_t chunk_count, 
                       unsigned char* master_key,
                       SecureMetadata* metadata,
                       SecurityError* error) {
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *ifp = NULL;
    FILE *temp_fp = NULL;
    unsigned char *buffer_in = NULL;
    unsigned char *buffer_out = NULL;
    int ret = -1;
    size_t actual_chunk_count = 0;  // Track actual chunks created
    
    // Allocate buffers
    buffer_in = OPENSSL_malloc(BUFFER_SIZE);
    buffer_out = OPENSSL_malloc(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    if (!buffer_in || !buffer_out) {
        snprintf(error->message, sizeof(error->message),
                "Failed to allocate encryption buffers");
        goto cleanup;
    }
    
    // Open input file
    ifp = fopen(input_path, "rb");
    if (!ifp) {
        snprintf(error->message, sizeof(error->message),
                "Failed to open input file: %s", strerror(errno));
        goto cleanup;
    }
    
    // Get file size
    fseek(ifp, 0, SEEK_END);
    metadata->data_size = ftell(ifp);
    fseek(ifp, 0, SEEK_SET);
    
    // Initialize encryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        snprintf(error->message, sizeof(error->message),
                "Failed to create encryption context");
        goto cleanup;
    }
    
    // Generate unique salt for key derivation
    if (RAND_bytes(metadata->key_salt, sizeof(metadata->key_salt)) != 1) {
        snprintf(error->message, sizeof(error->message),
                "Failed to generate key salt");
        goto cleanup;
    }
    
    // Derive encryption key
    unsigned char derived_key[KEY_SIZE];
    if (derive_key(master_key, 
                   metadata->key_salt,
                   sizeof(metadata->key_salt),
                   derived_key) != 0) {
        snprintf(error->message, sizeof(error->message),
                "Failed to derive encryption key");
        goto cleanup;
    }
    
    size_t bytes_remaining = metadata->data_size;
    
    while (bytes_remaining > 0 && actual_chunk_count < chunk_count) {
        // Generate unique IV for each chunk
        if (RAND_bytes(metadata->iv, IV_SIZE) != 1) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to generate IV for chunk %zu", actual_chunk_count);
            goto cleanup;
        }
        
        // Calculate chunk size
        size_t chunk_size = (bytes_remaining < MAX_CHUNK_SIZE) ? 
                            bytes_remaining : MAX_CHUNK_SIZE;
        metadata->chunk_sizes[actual_chunk_count] = chunk_size;
        
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                               derived_key, metadata->iv)) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to initialize encryption for chunk %zu", actual_chunk_count);
            goto cleanup;
        }
        
        // Open output chunk file
        temp_fp = fopen(chunk_paths[actual_chunk_count], "wb");
        if (!temp_fp) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to create chunk file %zu: %s", 
                    actual_chunk_count, strerror(errno));
            goto cleanup;
        }
        
        // Write IV to chunk file
        if (fwrite(metadata->iv, 1, IV_SIZE, temp_fp) != IV_SIZE) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to write IV for chunk %zu", actual_chunk_count);
            goto cleanup;
        }
        
        // Encrypt chunk data
        size_t bytes_processed = 0;
        while (bytes_processed < chunk_size) {
            size_t to_read = (chunk_size - bytes_processed < BUFFER_SIZE) ?
                            (chunk_size - bytes_processed) : BUFFER_SIZE;
            
            size_t bytes_read = fread(buffer_in, 1, to_read, ifp);
            if (bytes_read == 0) {
                if (feof(ifp)) break;
                snprintf(error->message, sizeof(error->message),
                        "Failed to read input file for chunk %zu", actual_chunk_count);
                goto cleanup;
            }
            
            int out_len;
            if (!EVP_EncryptUpdate(ctx, buffer_out, &out_len,
                                 buffer_in, bytes_read)) {
                snprintf(error->message, sizeof(error->message),
                        "Encryption failed for chunk %zu", actual_chunk_count);
                goto cleanup;
            }
            
            if (fwrite(buffer_out, 1, out_len, temp_fp) != (size_t)out_len) {
                snprintf(error->message, sizeof(error->message),
                        "Failed to write encrypted data for chunk %zu", actual_chunk_count);
                goto cleanup;
            }
            
            bytes_processed += bytes_read;
        }
        
        // Finalize encryption for this chunk
        int final_len;
        if (!EVP_EncryptFinal_ex(ctx, buffer_out, &final_len)) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to finalize encryption for chunk %zu", actual_chunk_count);
            goto cleanup;
        }
        
        if (final_len > 0) {
            if (fwrite(buffer_out, 1, final_len, temp_fp) != (size_t)final_len) {
                snprintf(error->message, sizeof(error->message),
                        "Failed to write final block for chunk %zu", actual_chunk_count);
                goto cleanup;
            }
        }
        
        // Get and write authentication tag
        unsigned char tag[16];
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to get authentication tag for chunk %zu", actual_chunk_count);
            goto cleanup;
        }
        
        if (fwrite(tag, 1, 16, temp_fp) != 16) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to write authentication tag for chunk %zu", actual_chunk_count);
            goto cleanup;
        }
        
        // Update remaining bytes and close chunk file
        bytes_remaining -= chunk_size;
        fclose(temp_fp);
        temp_fp = NULL;
        EVP_CIPHER_CTX_reset(ctx);
        actual_chunk_count++;
    }
    
    // Update metadata with actual chunk count
    metadata->chunk_count = actual_chunk_count;
    
    // Calculate metadata HMAC
    crypto_auth(metadata->hmac,
               (unsigned char*)metadata,
               offsetof(SecureMetadata, hmac),
               master_key);
    
    ret = 0;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ifp) fclose(ifp);
    if (temp_fp) fclose(temp_fp);
    if (buffer_in) {
        secure_wipe(buffer_in, BUFFER_SIZE);
        OPENSSL_free(buffer_in);
    }
    if (buffer_out) {
        secure_wipe(buffer_out, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        OPENSSL_free(buffer_out);
    }
    return ret;
}


int decrypt_file_chunked(const char* output_dir, 
                        unsigned char* key, 
                        const SecureMetadata* metadata) {
    char* final_path;
    
    if (ensure_directory_exists(output_dir) != 0) {
        printf("Failed to create output directory\n");
        return -1;
    }
    
    final_path = handle_file_conflict(output_dir, metadata->original_filename);
    if (!final_path) {
        printf("Failed to get valid output path\n");
        return -1;
    }
    
    FILE* ofp = fopen(final_path, "wb");
    if (!ofp) {
        printf("Error opening output file: %s\n", strerror(errno));
        return -1;
    }
    
    unsigned char derived_key[KEY_SIZE];
    if (derive_key(key, metadata->key_salt, sizeof(metadata->key_salt), derived_key) != 0) {
        printf("Error deriving decryption key\n");
        fclose(ofp);
        return -1;
    }

    size_t total_written = 0;
    for (size_t i = 0; i < metadata->chunk_count; i++) {
        char chunk_path[512];
        snprintf(chunk_path, sizeof(chunk_path), "%s%s.chunk", 
                STORAGE_PATH, metadata->chunk_hashes[i]);
        
        printf("Processing chunk %zu/%zu\n", i + 1, metadata->chunk_count);
        
        FILE* chunk_fp = fopen(chunk_path, "rb");
        if (!chunk_fp) {
            printf("Error opening chunk file: %s\n", chunk_path);
            fclose(ofp);
            return -1;
        }

        // Important: chunk_sizes in metadata should be only the encrypted data size
        // without IV and tag, since those are handled in decrypt_file_core
        size_t actual_chunk_size = metadata->chunk_sizes[i] + IV_SIZE + 16;  // Add IV and tag size
        if (decrypt_file_core(chunk_fp, ofp, derived_key, metadata->iv, actual_chunk_size) != 0) {
            printf("Error decrypting chunk %zu\n", i);
            fclose(chunk_fp);
            fclose(ofp);
            return -1;
        }

        total_written += metadata->chunk_sizes[i];  // Only count actual data size
        fclose(chunk_fp);
    }

    fclose(ofp);
    
    struct stat st;
    if (stat(final_path, &st) == 0) {
        printf("\nFile successfully decrypted to: %s\n", final_path);
        printf("Expected size: %zu bytes\n", metadata->data_size);
        printf("Actual size: %zu bytes\n", (size_t)st.st_size);
        
        if ((size_t)st.st_size != metadata->data_size) {
            printf("WARNING: File size mismatch!\n");
            return -1;
        }
    }
    
    return 0;
}

// Core decryption function with size handling
int decrypt_file_core(FILE* ifp, FILE* ofp,
                     unsigned char* key,
                     size_t total_chunk_size) {  // Expects total size including IV and tag
    int ret = -1;
    unsigned char tag[16];
    unsigned char iv[IV_SIZE];
    unsigned char* buffer_in = NULL;
    unsigned char* buffer_out = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    
    if (fread(iv, 1, IV_SIZE, ifp) != IV_SIZE) {
        printf("Error reading IV from chunk file\n");
        goto cleanup;
    }
    
    // Calculate actual encrypted data size
    size_t encrypted_size = total_chunk_size - (IV_SIZE + 16);
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error creating cipher context\n");
        goto cleanup;
    }
    
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        printf("Error initializing decryption\n");
        goto cleanup;
    }
    
    // Read the authentication tag
    if (fseek(ifp, IV_SIZE + encrypted_size, SEEK_SET) != 0) {
        printf("Error seeking to authentication tag\n");
        goto cleanup;
    }
    
    if (fread(tag, 1, 16, ifp) != 16) {
        printf("Error reading authentication tag\n");
        goto cleanup;
    }
    
    if (fseek(ifp, IV_SIZE, SEEK_SET) != 0) {
        printf("Error seeking to encrypted data\n");
        goto cleanup;
    }
    
    buffer_in = malloc(BUFFER_SIZE);
    buffer_out = malloc(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    if (!buffer_in || !buffer_out) {
        printf("Error allocating buffers\n");
        goto cleanup;
    }
    
    size_t remaining = encrypted_size;
    int out_len;
    
    while (remaining > 0) {
        size_t curr_chunk = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;
        size_t bytes_read = fread(buffer_in, 1, curr_chunk, ifp);
        if (bytes_read != curr_chunk) {
            printf("Error reading encrypted data\n");
            goto cleanup;
        }
        
        if (!EVP_DecryptUpdate(ctx, buffer_out, &out_len, buffer_in, bytes_read)) {
            printf("Error during decryption\n");
            goto cleanup;
        }
        
        if (out_len > 0) {
            if (fwrite(buffer_out, 1, out_len, ofp) != (size_t)out_len) {
                printf("Error writing decrypted data\n");
                goto cleanup;
            }
        }
        
        remaining -= bytes_read;
    }
    
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        printf("Error setting authentication tag\n");
        goto cleanup;
    }
    
    int final_len;
    if (!EVP_DecryptFinal_ex(ctx, buffer_out, &final_len)) {
        printf("Error: Authentication failed - data may be corrupted or tampered with\n");
        goto cleanup;
    }
    
    if (final_len > 0) {
        if (fwrite(buffer_out, 1, final_len, ofp) != (size_t)final_len) {
            printf("Error writing final data block\n");
            goto cleanup;
        }
    }
    
    ret = 0;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (buffer_in) {
        secure_wipe(buffer_in, BUFFER_SIZE);
        free(buffer_in);
    }
    if (buffer_out) {
        secure_wipe(buffer_out, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        free(buffer_out);
    }
    
    return ret;
}

#endif // CRYPTO_OPS_H
