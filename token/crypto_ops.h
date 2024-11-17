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


// Updated function signatures
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
    
    // Initialize all pointers to NULL at the start
    if (!input_path || !chunk_paths || !master_key || !metadata || !error) {
        if (error) {
            snprintf(error->message, sizeof(error->message),
                    "Invalid NULL parameters provided");
        }
        return -1;
    }
    
    // Initialize progress bar variables
    const int progress_width = 50;
    size_t total_bytes_processed = 0;
    int last_progress = 0;
    
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
    
    metadata->chunk_count = chunk_count;
    size_t bytes_remaining = metadata->data_size;
    size_t chunk_index = 0;
    
    // Initialize progress bar
    printf("\nEncryption Progress:\n[");
    for (int i = 0; i < progress_width; i++) {
        printf(" ");
    }
    printf("]\r[");
    fflush(stdout);
    
    while (bytes_remaining > 0 && chunk_index < chunk_count) {
        // Generate unique IV for each chunk
        if (RAND_bytes(metadata->iv, IV_SIZE) != 1) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to generate IV for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        // Calculate chunk size
        size_t chunk_size = (bytes_remaining < MAX_CHUNK_SIZE) ? 
                            bytes_remaining : MAX_CHUNK_SIZE;
        metadata->chunk_sizes[chunk_index] = chunk_size;
        
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                               derived_key, metadata->iv)) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to initialize encryption for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        // Open output chunk file
        temp_fp = fopen(chunk_paths[chunk_index], "wb");
        if (!temp_fp) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to create chunk file %zu: %s", 
                    chunk_index, strerror(errno));
            goto cleanup;
        }
        
        // Write IV to chunk file
        if (fwrite(metadata->iv, 1, IV_SIZE, temp_fp) != IV_SIZE) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to write IV for chunk %zu", chunk_index);
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
                        "Failed to read input file for chunk %zu", chunk_index);
                goto cleanup;
            }
            
            int out_len;
            if (!EVP_EncryptUpdate(ctx, buffer_out, &out_len,
                                 buffer_in, bytes_read)) {
                snprintf(error->message, sizeof(error->message),
                        "Encryption failed for chunk %zu", chunk_index);
                goto cleanup;
            }
            
            if (fwrite(buffer_out, 1, out_len, temp_fp) != (size_t)out_len) {
                snprintf(error->message, sizeof(error->message),
                        "Failed to write encrypted data for chunk %zu", chunk_index);
                goto cleanup;
            }
            
            bytes_processed += bytes_read;
            total_bytes_processed += bytes_read;
            
            // Update progress bar
            float progress = (float)total_bytes_processed / metadata->data_size;
            int current_progress = (int)(progress * progress_width);
            
            for (int j = last_progress; j < current_progress; j++) {
                printf("=");
                fflush(stdout);
            }
            last_progress = current_progress;
        }
        
        // Finalize encryption for this chunk
        int final_len;
        if (!EVP_EncryptFinal_ex(ctx, buffer_out, &final_len)) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to finalize encryption for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        if (final_len > 0) {
            if (fwrite(buffer_out, 1, final_len, temp_fp) != (size_t)final_len) {
                snprintf(error->message, sizeof(error->message),
                        "Failed to write final block for chunk %zu", chunk_index);
                goto cleanup;
            }
        }
        
        // Get and write authentication tag
        unsigned char tag[16];
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to get authentication tag for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        if (fwrite(tag, 1, 16, temp_fp) != 16) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to write authentication tag for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        // Update remaining bytes and close chunk file
        bytes_remaining -= chunk_size;
        fclose(temp_fp);
        temp_fp = NULL;
        EVP_CIPHER_CTX_reset(ctx);
        chunk_index++;
    }
    
    // Complete progress bar
    while (last_progress < progress_width) {
        printf("=");
        last_progress++;
    }
    printf("] 100%%\n");
    
    // Calculate metadata HMAC
    crypto_auth(metadata->hmac,
               (unsigned char*)metadata,
               offsetof(SecureMetadata, hmac),
               master_key);
    
    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    
    if (ifp) {
        fclose(ifp);
        ifp = NULL;
    }
    
    if (temp_fp) {
        fclose(temp_fp);
        temp_fp = NULL;
    }
    
    if (buffer_in) {
        secure_wipe(buffer_in, BUFFER_SIZE);
        OPENSSL_free(buffer_in);
        buffer_in = NULL;
    }
    
    if (buffer_out) {
        secure_wipe(buffer_out, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        OPENSSL_free(buffer_out);
        buffer_out = NULL;
    }

    // Add memory fence to ensure all cleanup operations complete
    __sync_synchronize();
    
    return ret;
}


int decrypt_file_chunked(const char* output_dir, 
                        unsigned char* key, 
                        const SecureMetadata* metadata) {
    char* final_path;
    
    // First verify all chunks exist before starting decryption
    printf("\nVerifying chunks...\n");
    for (size_t i = 0; i < metadata->chunk_count; i++) {
        char chunk_path[512];
        snprintf(chunk_path, sizeof(chunk_path), "%s%s.chunk", 
                STORAGE_PATH, metadata->chunk_hashes[i]);
        
        // Check if chunk exists
        struct stat st;
        if (stat(chunk_path, &st) != 0) {
            printf("Error: Chunk file missing or inaccessible: %s\n", chunk_path);
            printf("System error: %s\n", strerror(errno));
            return -1;
        }

        // Account for IV and authentication tag in size
        size_t expected_size = metadata->chunk_sizes[i] + IV_SIZE + 16;
        if ((size_t)st.st_size != expected_size) {
            printf("Error: Chunk size mismatch for %s\n", chunk_path);
            printf("Expected: %zu bytes, Found: %zu bytes\n", 
                   expected_size, (size_t)st.st_size);
            return -1;
        }
    }
    
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
    const int progress_width = 50;
    float total_size = 0;
    
    // Calculate total size
    for (size_t i = 0; i < metadata->chunk_count; i++) {
        total_size += metadata->chunk_sizes[i];
    }

    // Initialize progress bar
    printf("\nDecryption Progress:\n[");
    for (int i = 0; i < progress_width; i++) {
        printf(" ");
    }
    printf("]\r[");
    fflush(stdout);

    int last_progress = 0;
    int decryption_failed = 0;

    for (size_t i = 0; i < metadata->chunk_count; i++) {
        char chunk_path[512];
        snprintf(chunk_path, sizeof(chunk_path), "%s%s.chunk", 
                STORAGE_PATH, metadata->chunk_hashes[i]);

        FILE* chunk_fp = fopen(chunk_path, "rb");
        if (!chunk_fp) {
            printf("\nError opening chunk file: %s (%s)\n", 
                   chunk_path, strerror(errno));
            decryption_failed = 1;
            break;
        }

        size_t chunk_size = metadata->chunk_sizes[i];
        if (decrypt_file_core(chunk_fp, ofp, derived_key, NULL, chunk_size) != 0) {
            printf("\nError decrypting chunk %zu\n", i);
            fclose(chunk_fp);
            decryption_failed = 1;
            break;
        }

        total_written += chunk_size;
        fclose(chunk_fp);

        // Update progress bar
        float progress = (total_written / total_size);
        int current_progress = (int)(progress * progress_width);
        
        for (int j = last_progress; j < current_progress; j++) {
            printf("=");
            fflush(stdout);
        }
        last_progress = current_progress;
    }

    // Complete progress bar only if successful
    if (!decryption_failed) {
        while (last_progress < progress_width) {
            printf("=");
            last_progress++;
        }
        printf("] 100%%\n");
    }

    fclose(ofp);
    
    if (decryption_failed) {
        // Cleanup partial file
        unlink(final_path);
        return -1;
    }
    
    // Verify file size
    struct stat st;
    if (stat(final_path, &st) == 0) {
        printf("\nFile successfully decrypted to: %s\n", final_path);
        printf("Expected size: %zu bytes\n", metadata->data_size);
        printf("Actual size: %zu bytes\n", (size_t)st.st_size);
        
        if ((size_t)st.st_size == metadata->data_size) {
            return 0;  // Success
        }
        printf("WARNING: File size mismatch!\n");
    }
    
    return -1;
}

// Core decryption function
int decrypt_file_core(FILE* ifp, FILE* ofp,
                     unsigned char* key,
                     const unsigned char* iv_unused,
                     size_t chunk_size) {
    EVP_CIPHER_CTX* ctx = NULL;
    unsigned char iv[IV_SIZE];
    unsigned char tag[16];
    unsigned char* buffer_in = NULL;
    unsigned char* buffer_out = NULL;
    (void)iv_unused; // Compatibility var
    int ret = -1;
    
    // Validate input parameters
    if (!ifp || !ofp || !key) {
        printf("Error: Invalid parameters provided to decrypt_file_core\n");
        return -1;
    }
    
    // Initialize buffers - fixed double allocation
    buffer_in = malloc(BUFFER_SIZE);
    buffer_out = malloc(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    if (!buffer_in || !buffer_out) {
        printf("Error: Memory allocation failed\n");
        goto cleanup;
    }
    
    // Read IV from chunk file
    if (fread(iv, 1, IV_SIZE, ifp) != IV_SIZE) {
        printf("Error reading IV from chunk\n");
        goto cleanup;
    }
    
    // Initialize decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error: Failed to create cipher context\n");
        goto cleanup;
    }
    
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        printf("Error: Failed to initialize decryption\n");
        goto cleanup;
    }
    
    // Process the encrypted data - note that we exclude IV and tag from the chunk size
    size_t data_size = chunk_size;
    size_t total_read = 0;
    
    while (total_read < data_size) {
        size_t to_read = (data_size - total_read < BUFFER_SIZE) ? 
                        (data_size - total_read) : BUFFER_SIZE;
                        
        size_t bytes_read = fread(buffer_in, 1, to_read, ifp);
        if (bytes_read == 0) {
            if (feof(ifp)) {
                printf("Error: Unexpected end of file\n");
            } else {
                printf("Error: Failed to read chunk data\n");
            }
            goto cleanup;
        }
        
        int outlen;
        if (!EVP_DecryptUpdate(ctx, buffer_out, &outlen, buffer_in, bytes_read)) {
            printf("Error: Decryption update failed\n");
            goto cleanup;
        }
        
        if (outlen > 0) {
            if (fwrite(buffer_out, 1, outlen, ofp) != (size_t)outlen) {
                printf("Error: Failed to write decrypted data\n");
                goto cleanup;
            }
        }
        
        total_read += bytes_read;
    }
    
    if (total_read != data_size) {
        printf("Error: Chunk size mismatch - expected %zu bytes but read %zu\n", 
               data_size, total_read);
        goto cleanup;
    }

    // Read authentication tag
    if (fread(tag, 1, 16, ifp) != 16) {
        printf("Error: Failed to read authentication tag\n");
        goto cleanup;
    }
    
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        printf("Error: Failed to set authentication tag\n");
        goto cleanup;
    }
    
    int final_len;
    unsigned char final_buffer[EVP_MAX_BLOCK_LENGTH];
    if (!EVP_DecryptFinal_ex(ctx, final_buffer, &final_len)) {
        printf("Error: Authentication failed\n");
        goto cleanup;
    }
    
    if (final_len > 0) {
        if (fwrite(final_buffer, 1, final_len, ofp) != (size_t)final_len) {
            printf("Error: Failed to write final block\n");
            goto cleanup;
        }
    }
    
    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
    }
    
    if (buffer_in) {
        secure_wipe(buffer_in, BUFFER_SIZE);
        free(buffer_in);
    }
    
    if (buffer_out) {
        secure_wipe(buffer_out, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        free(buffer_out);
    }

    // Add memory fence to ensure all cleanup operations complete
    __sync_synchronize();
    
    return ret;
}


#endif // CRYPTO_OPS_H
