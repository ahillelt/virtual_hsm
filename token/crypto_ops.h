// crypto_ops.h
#ifndef CRYPTO_OPS_H
#define CRYPTO_OPS_H 

#include "security_defs.h"
#include "metadata.h"
#include "file_ops.h"
#include "key_derivation.h"
#include "token_utils.h"

#include <sodium.h>
#include <sodium/crypto_auth.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>

#ifndef SUCCESS
#define SUCCESS 0
#endif

#ifndef HMAC_SIZE
#define HMAC_SIZE crypto_auth_BYTES
#endif

// Enum for more specific error handling
typedef enum {
    DECRYPT_SUCCESS = 0,
    ERROR_INVALID_KEY = 1,
    ERROR_METADATA_CORRUPT = 2,
    ERROR_CHUNK_MISSING = 3,
    ERROR_CHUNK_SIZE_MISMATCH = 4,
    ERROR_DECRYPTION_FAILED = 5,
    ERROR_FILE_WRITE_FAILED = 6,
    ERROR_AUTHENTICATION_FAILED = 7
} DecryptionResult;




// Forward Declarations
void log_security_event(const char* event, const char* details);

int verify_chunk(const char* hash, size_t size);
int ensure_directory_exists(const char* path);

char* handle_file_conflict(const char* dir, const char* filename);

void secure_wipe(void* ptr, size_t size);

int derive_key(const unsigned char* key, size_t key_len,
              const unsigned char* salt, size_t salt_len,
              const unsigned char* info, size_t info_len,
              unsigned char* out, size_t out_len);
			  
void debug_hex_dump(const char* desc, const void* addr, size_t len);

size_t calculate_chunk_count(size_t file_size);			
size_t generate_chunk_size(size_t remaining_size);

int generate_chunk_hash(const char* token, size_t chunk_index, char* chunk_hash);

//int crypto_auth(unsigned char* out, const unsigned char* in,size_t inlen, const unsigned char* k);
			   
// Updated function signatures
// HKDF declaration
int HKDF(const EVP_MD *evp_md,
         const unsigned char *salt, size_t salt_len,
         const unsigned char *key, size_t key_len,
         const unsigned char *info, size_t info_len,
         unsigned char *out, size_t out_len);


int encrypt_file_secure(const char* input_path, 
                       char** chunk_paths,
                       size_t chunk_count, 
                       const unsigned char* master_key,
                       SecureMetadata* metadata,
                       SecurityError* error);

int encrypt_file_chunked(const char* input_path, char*** chunk_paths, 
                        size_t* max_chunks, unsigned char* key, 
                        SecureMetadata* metadata);

int decrypt_file_chunked(const char* output_dir, 
                        unsigned char* key,  // Changed to match file_ops.h
                        const SecureMetadata* metadata, const char* token);

int decrypt_file_core(FILE* ifp, FILE* ofp,
                     const unsigned char* key,
                     const unsigned char* provided_iv,  
                     size_t chunk_size);

                     
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex); // see token_utils.h
void log_decryption_error(DecryptionResult result, const char* context);
static ErrorCode verify_decryption_prerequisites(const SecureMetadata* metadata, const char* token);

DecryptionResult validate_decryption_key(const unsigned char* key, size_t key_len);
DecryptionResult verify_metadata_integrity(const SecureMetadata* metadata,const unsigned char* master_key);


// Enhanced logging function
void log_decryption_error(DecryptionResult result, const char* context) {
    const char* error_messages[] = {
        "Decryption successful",
        "Invalid encryption key",
        "Metadata corruption detected",
        "Chunk file missing",
        "Chunk size mismatch",
        "Decryption process failed",
        "File write operation failed", 
        "Authentication tag verification failed"
    };

    char log_message[512];
    snprintf(log_message, sizeof(log_message), 
             "Decryption Error [%d]: %s - Context: %s", 
             result, error_messages[result], context);
    
    log_security_event("DECRYPT_ERROR", log_message);
}

// HMAC-based Key Derivation Function (HKDF)
int HKDF(const EVP_MD *evp_md,
         const unsigned char *salt, size_t salt_len,
         const unsigned char *key, size_t key_len,
         const unsigned char *info, size_t info_len,
         unsigned char *out, size_t out_len) {
    int ret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;
    
    // Create a new KDF
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        goto cleanup;
    }
    
    // Create a new KDF context
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        goto cleanup;
    }
    
    // Set the digest algorithm
    *p++ = OSSL_PARAM_construct_utf8_string("digest", 
                                          (char *)EVP_MD_get0_name(evp_md), 
                                          0);
    
    // Set the key
    *p++ = OSSL_PARAM_construct_octet_string("key", 
                                           (unsigned char *)key, 
                                           key_len);
    
    // Set the salt (if provided)
    if (salt != NULL && salt_len > 0) {
        *p++ = OSSL_PARAM_construct_octet_string("salt", 
                                               (unsigned char *)salt, 
                                               salt_len);
    }
    
    // Set the info (if provided)
    if (info != NULL && info_len > 0) {
        *p++ = OSSL_PARAM_construct_octet_string("info", 
                                               (unsigned char *)info, 
                                               info_len);
    }
    
    // Terminate the parameter list
    *p = OSSL_PARAM_construct_end();
    
    // Derive the key
    if (EVP_KDF_derive(kctx, out, out_len, params) != 1) {
        goto cleanup;
    }
    
    ret = 1;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

DecryptionResult validate_decryption_key(const unsigned char* key, size_t key_len) {
    // Implement key validation checks
    if (!key || key_len == 0) {
        return ERROR_INVALID_KEY;
    }

    // Additional checks like key complexity, entropy
    size_t zero_bytes = 0;
    for (size_t i = 0; i < key_len; i++) {
        if (key[i] == 0) zero_bytes++;
    }

    // Reject keys with too many zero bytes
    if (zero_bytes > key_len / 2) {
        return ERROR_INVALID_KEY;
    }

    return DECRYPT_SUCCESS;
}

// Enhanced metadata integrity check
DecryptionResult verify_metadata_integrity(const SecureMetadata* metadata, 
                                           const unsigned char* master_key) {
    if (!metadata) {
        return ERROR_METADATA_CORRUPT;
    }

    // Verify metadata magic number
    if (metadata->version != METADATA_MAGIC) {
        log_decryption_error(ERROR_METADATA_CORRUPT, "Invalid metadata version");
        return ERROR_METADATA_CORRUPT;
    }

    // Verify HMAC of metadata
    unsigned char calculated_hmac[HMAC_SIZE];
    
    // Note: You'll need to implement crypto_auth function based on libsodium
    // This is a placeholder - implement with actual libsodium HMAC generation
    if (crypto_auth(calculated_hmac, 
                    (unsigned char*)metadata, 
                    offsetof(SecureMetadata, hmac), 
                    master_key) != 0) {
        log_decryption_error(ERROR_METADATA_CORRUPT, "HMAC verification failed");
        return ERROR_METADATA_CORRUPT;
    }

    // Compare calculated HMAC with stored HMAC
    if (memcmp(calculated_hmac, metadata->hmac, HMAC_SIZE) != 0) {
        log_decryption_error(ERROR_METADATA_CORRUPT, "HMAC mismatch");
        return ERROR_METADATA_CORRUPT;
    }

    return DECRYPT_SUCCESS;
}

int encrypt_file_chunked(const char* input_path, char*** chunk_paths, 
                        size_t* max_chunks, unsigned char* key, 
                        SecureMetadata* metadata) {
    
    printf(!DEBUG ? "" :"DEBUG: Starting encryption of file: %s\n", input_path);
    
    // Enhanced input validation
    if (!input_path || !chunk_paths || !*chunk_paths || !max_chunks || 
        !key || !metadata || *max_chunks == 0) {
        printf(!DEBUG ? "" :"ERROR: Invalid input parameters\n");
        return -1;
    }
    
    // Open input file
    FILE* input_file = fopen(input_path, "rb");
    if (!input_file) {
        printf(!DEBUG ? "" :"ERROR: Failed to open input file: %s (errno: %d)\n", input_path, errno);
        return -1;
    }
    
    // Get file size
    if (fseek(input_file, 0, SEEK_END) != 0) {
        fclose(input_file);
        return -1;
    }
    long file_pos = ftell(input_file);
    if (file_pos < 0) {
        fclose(input_file);
        return -1;
    }
    size_t total_size = (size_t)file_pos;
    rewind(input_file);
    
    printf(!DEBUG ? "" :"DEBUG: Total file size: %zu bytes\n", total_size);
    
    // Initialize encryption context and buffers
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(input_file);
        return -1;
    }
    
    unsigned char *buffer = calloc(1, MAX_CHUNK_SIZE);
    unsigned char *encrypted = calloc(1, MAX_CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
    if (!buffer || !encrypted) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(input_file);
        free(buffer);
        free(encrypted);
        return -1;
    }
    
    // Track chunks during processing
    size_t current_chunk = 0;
    size_t total_processed = 0;
    
    // Process file in chunks until all data is processed
    while (total_processed < total_size) {
        // Check if we need to grow the chunk paths array
        if (current_chunk >= *max_chunks) {
            size_t new_size = *max_chunks * 2;
            if (new_size > MAX_CHUNKS) {
                if (*max_chunks >= MAX_CHUNKS) {
                    printf(!DEBUG ? "" :"ERROR: Maximum chunk limit reached\n");
                    goto cleanup_error;
                }
                new_size = MAX_CHUNKS;
            }
            
            char** new_paths = realloc(*chunk_paths, new_size * sizeof(char*));
            if (!new_paths) {
                printf(!DEBUG ? "" :"ERROR: Failed to reallocate chunk paths array\n");
                goto cleanup_error;
            }
            
            // Initialize new elements to NULL
            for (size_t i = *max_chunks; i < new_size; i++) {
                new_paths[i] = NULL;
            }
            
            *chunk_paths = new_paths;
            *max_chunks = new_size;
        }
        
        size_t remaining_size = total_size - total_processed;
        size_t chunk_size = generate_chunk_size(remaining_size);
        chunk_size = MIN(chunk_size, remaining_size);
        chunk_size = MIN(chunk_size, MAX_CHUNK_SIZE);
        
        printf(!DEBUG ? "" :"DEBUG: Processing chunk %zu (size: %zu bytes, remaining: %zu bytes)\n", 
               current_chunk + 1, chunk_size, remaining_size);
        
        // Generate chunk hash and path
        char chunk_hash[HASH_SIZE] = {0};
        if (generate_chunk_hash(metadata->token, current_chunk, chunk_hash) != 0) {
            printf(!DEBUG ? "" :"ERROR: Failed to generate chunk hash\n");
            goto cleanup_error;
        }
        
        // Allocate and generate chunk path
        size_t path_len = strlen(STORAGE_PATH) + HASH_SIZE + 7;  // +7 for ".chunk\0"
        (*chunk_paths)[current_chunk] = malloc(path_len);
        if (!(*chunk_paths)[current_chunk]) {
            printf(!DEBUG ? "" :"ERROR: Failed to allocate chunk path\n");
            goto cleanup_error;
        }
        
        int sprintf_result = snprintf((*chunk_paths)[current_chunk], path_len,
                                    "%s%s.chunk", STORAGE_PATH, chunk_hash);
        if (sprintf_result < 0 || sprintf_result >= (int)path_len) {
            printf(!DEBUG ? "" :"ERROR: Failed to generate chunk path\n");
            goto cleanup_error;
        }
        
        // Generate IV for this chunk
        unsigned char chunk_iv[IV_SIZE];
        if (RAND_bytes(chunk_iv, IV_SIZE) != 1) {
            printf(!DEBUG ? "" :"ERROR: Failed to generate IV for chunk %zu\n", current_chunk + 1);
            goto cleanup_error;
        }
        
        // Initialize encryption for this chunk
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, chunk_iv)) {
            goto cleanup_error;
        }
        
        // Read chunk data
        size_t bytes_read = fread(buffer, 1, chunk_size, input_file);
        if (bytes_read != chunk_size) {
            printf(!DEBUG ? "" :"ERROR: Read failed for chunk %zu. Expected %zu bytes, got %zu\n", 
                   current_chunk + 1, chunk_size, bytes_read);
            goto cleanup_error;
        }
        
        // Open chunk file
        FILE* chunk_file = fopen((*chunk_paths)[current_chunk], "wb");
        if (!chunk_file) {
            printf(!DEBUG ? "" :"ERROR: Failed to create chunk file %zu\n", current_chunk + 1);
            goto cleanup_error;
        }
        
        // Write IV
        if (fwrite(chunk_iv, 1, IV_SIZE, chunk_file) != IV_SIZE) {
            fclose(chunk_file);
            goto cleanup_error;
        }
        
        // Encrypt and write chunk data
        int encrypted_len;
        if (!EVP_EncryptUpdate(ctx, encrypted, &encrypted_len, buffer, chunk_size)) {
            fclose(chunk_file);
            goto cleanup_error;
        }
        
        if (fwrite(encrypted, 1, encrypted_len, chunk_file) != (size_t)encrypted_len) {
            fclose(chunk_file);
            goto cleanup_error;
        }
        
        // Finalize encryption
        int final_len;
        if (!EVP_EncryptFinal_ex(ctx, encrypted + encrypted_len, &final_len)) {
            fclose(chunk_file);
            goto cleanup_error;
        }
        
        if (final_len > 0) {
            if (fwrite(encrypted + encrypted_len, 1, final_len, chunk_file) != (size_t)final_len) {
                fclose(chunk_file);
                goto cleanup_error;
            }
            encrypted_len += final_len;
        }
        
        // Get and write authentication tag
        unsigned char tag[TAG_SIZE];
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) {
            fclose(chunk_file);
            goto cleanup_error;
        }
        
        if (fwrite(tag, 1, TAG_SIZE, chunk_file) != TAG_SIZE) {
            fclose(chunk_file);
            goto cleanup_error;
        }
        
        fclose(chunk_file);
        
        // Store chunk information in metadata
        metadata->chunk_sizes[current_chunk] = chunk_size;
        memcpy(metadata->chunk_hashes[current_chunk], chunk_hash, HASH_SIZE - 1);
        metadata->chunk_hashes[current_chunk][HASH_SIZE - 1] = '\0';
        
        total_processed += chunk_size;
        current_chunk++;
        EVP_CIPHER_CTX_reset(ctx);
        
        printf(SILENT ? "" :"Progress: %zu/%zu bytes (%.1f%%)\n", 
               total_processed, total_size, 
               (double)total_processed / total_size * 100);
    }
    
    // Update metadata with final chunk count
    metadata->chunk_count = current_chunk;
    metadata->file_size = total_size;
    
    // Cleanup and return success
    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    free(buffer);
    free(encrypted);
    
    printf(SILENT ? "" :"Encryption complete. Processed %zu bytes in %zu chunks\n", 
           total_processed, metadata->chunk_count);
           
    return 0;

cleanup_error:
    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    free(buffer);
    free(encrypted);
    return -1;
}

int encrypt_file_secure(const char* input_path, 
                       char** chunk_paths,
                       size_t chunk_count, 
                       const unsigned char* master_key,
                       SecureMetadata* metadata,
                       SecurityError* error) {
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *ifp = NULL;
    FILE *temp_fp = NULL;
    unsigned char *buffer_in = NULL;
    unsigned char *buffer_out = NULL;
    unsigned char derived_key[KEY_SIZE];
    int ret = -1;
    
    // Validate input parameters
    if (!input_path || !chunk_paths || !master_key || !metadata || !error) {
        if (error) {
            snprintf(error->message, sizeof(error->message),
                    "Invalid NULL parameters provided");
        }
        return -1;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Initialize progress tracking
    const int progress_width = 50;
    size_t total_bytes_processed = 0;
    int last_progress = 0;
    
    // Allocate buffers with secure error handling
    buffer_in = OPENSSL_secure_malloc(BUFFER_SIZE);
    buffer_out = OPENSSL_secure_malloc(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    
    if (!buffer_in || !buffer_out) {
        snprintf(error->message, sizeof(error->message),
                "Failed to allocate secure memory");
        goto cleanup;
    }
    
    // Open input file
    ifp = fopen(input_path, "rb");
    if (!ifp) {
        snprintf(error->message, sizeof(error->message),
                "Failed to open input file: %s", strerror(errno));
        goto cleanup;
    }
    
    // Get file size securely
    struct stat st;
    if (fstat(fileno(ifp), &st) != 0) {
        snprintf(error->message, sizeof(error->message),
                "Failed to get file size: %s", strerror(errno));
        goto cleanup;
    }
    metadata->data_size = st.st_size;
	metadata->file_size = st.st_size;
	metadata->version = METADATA_MAGIC;
    
    // Initialize encryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        snprintf(error->message, sizeof(error->message),
                "Failed to create encryption context");
        goto cleanup;
    }
    
    // Generate salt for key derivation
    if (RAND_bytes(metadata->key_salt, SALT_SIZE) != 1) {
        snprintf(error->message, sizeof(error->message),
                "Failed to generate key salt");
        goto cleanup;
    }
    
    // Derive encryption key using key_derivation.h
	if (!derive_encryption_key(master_key, KEY_SIZE,
							  metadata->key_salt, SALT_SIZE,
							  derived_key, KEY_SIZE)) {
		snprintf(error->message, sizeof(error->message),
				 "Failed to derive encryption key");
		goto cleanup;
	}
	
    metadata->chunk_count = chunk_count;
    size_t bytes_remaining = metadata->data_size;
    size_t chunk_index = 0;
    
    // Initialize progress display
    printf(SILENT ? "" :"\nEncryption Progress:\n[");
    for (int i = 0; i < progress_width; i++) printf(SILENT ? "" :" ");
    printf(SILENT ? "" :"]\r[");
    fflush(stdout);
    
    // Process each chunk
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
        
        // Initialize encryption for this chunk
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
        
        // Write IV
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
            
            if (out_len > 0 && fwrite(buffer_out, 1, out_len, temp_fp) != (size_t)out_len) {
                snprintf(error->message, sizeof(error->message),
                        "Failed to write encrypted data for chunk %zu", chunk_index);
                goto cleanup;
            }
            
            bytes_processed += bytes_read;
            total_bytes_processed += bytes_read;
            
            // Update progress
            float progress = (float)total_bytes_processed / metadata->data_size;
            int current_progress = (int)(progress * progress_width);
            
            while (last_progress < current_progress) {
                printf(SILENT ? "" :"=");
                fflush(stdout);
                last_progress++;
            }
        }
        
        // Finalize encryption for this chunk
        int final_len;
        if (!EVP_EncryptFinal_ex(ctx, buffer_out, &final_len)) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to finalize encryption for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        if (final_len > 0 && fwrite(buffer_out, 1, final_len, temp_fp) != (size_t)final_len) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to write final block for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        // Get and write authentication tag
        unsigned char tag[TAG_SIZE];
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to get authentication tag for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        if (fwrite(tag, 1, TAG_SIZE, temp_fp) != TAG_SIZE) {
            snprintf(error->message, sizeof(error->message),
                    "Failed to write authentication tag for chunk %zu", chunk_index);
            goto cleanup;
        }
        
        bytes_remaining -= chunk_size;
        fclose(temp_fp);
        temp_fp = NULL;
        EVP_CIPHER_CTX_reset(ctx);
        chunk_index++;
    }
    
    // Complete progress bar
    while (last_progress < progress_width) {
        printf(SILENT ? "" :"=");
        last_progress++;
    }
    printf(SILENT ? "" :"] 100%%\n");
    
    // Calculate metadata HMAC
    if (crypto_auth(metadata->hmac,
                   (unsigned char*)metadata,
                   offsetof(SecureMetadata, hmac),
                   master_key) != 0) {
        snprintf(error->message, sizeof(error->message),
                "Failed to calculate metadata HMAC");
        goto cleanup;
    }
    
    ret = 0;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ifp) fclose(ifp);
    if (temp_fp) fclose(temp_fp);
    
    if (buffer_in) {
        secure_wipe(buffer_in, BUFFER_SIZE);
        OPENSSL_secure_free(buffer_in);
    }
    
    if (buffer_out) {
        secure_wipe(buffer_out, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        OPENSSL_secure_free(buffer_out);
    }
    
    if (derived_key) {
        secure_wipe(derived_key, KEY_SIZE);
    }

    ERR_free_strings();
    EVP_cleanup();
    
    __sync_synchronize();
    return ret;
}

static ErrorCode verify_decryption_prerequisites(const SecureMetadata* metadata, const char* token) {
    if (!metadata || !token) return ERROR_INVALID_INPUT;
    
    // Verify metadata integrity
    if (metadata->version != METADATA_MAGIC) {
        log_security_event("ERROR", "Invalid metadata version");
        return ERROR_INVALID_INPUT;
    }
    
    // Verify token matches metadata
    if (strncmp(metadata->token, token, TOKEN_SIZE) != 0) {
        log_security_event("ERROR", "Token mismatch");
        return ERROR_INVALID_INPUT;
    }
	

    
    // Verify all chunks exist and have correct sizes
    for (size_t i = 0; i < metadata->chunk_count; i++) {
        if (verify_chunk(metadata->chunk_hashes[i], metadata->chunk_sizes[i]) != 0) {
            log_security_event("ERROR", "Chunk verification failed");
            return ERROR_INVALID_INPUT;
        }
    }
    
    return SUCCESS;
}

// Decryption function
int decrypt_file_chunked(const char* output_dir, unsigned char* key,
                         const SecureMetadata* metadata, const char* token) {
							 
							 
    // Ensure output directory exists (using output_dir)
    if (ensure_directory_exists(output_dir) != 0) {
        return -1; 
    }

    // Construct full output path 
    char output_path[PATH_MAX];
    snprintf(output_path, sizeof(output_path), "%s/%s", 
            output_dir, metadata->original_filename);

    // Handle file conflicts (using handle_file_conflict from file_ops.h)
    char* final_path = handle_file_conflict(output_dir, metadata->original_filename);
    if (!final_path) {
        return -1; 
    }

    // Proceed with file decryption
    FILE* output_file = fopen(final_path, "wb");
    if (!output_file) {
        return -1; 
    }					


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(output_file);
        return -1;
    }

    unsigned char *buffer = malloc(MAX_CHUNK_SIZE + IV_SIZE + TAG_SIZE);
    unsigned char *decrypted = malloc(MAX_CHUNK_SIZE);
    if (!buffer || !decrypted) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(output_file);
        free(buffer);
        free(decrypted);
        return -1;
    }
	

    
    // Progress Bar Preamble: Calculate total size
	float total_size = 0;    
    for (size_t i = 0; i < metadata->chunk_count; i++) {
        total_size += metadata->chunk_sizes[i];
    }

	// Initialize progress bar
	const int progress_width = 50;
    printf("\nDecryption Progress:\n[");
    for (int i = 0; i < progress_width; i++) {
        printf(" ");
    }
    printf("]\r[");
    fflush(stdout);

    int last_progress = 0;
    int decryption_failed = 0;

    size_t total_processed = 0;
	
	
	

    // Process each chunk
 for (size_t i = 0; i < metadata->chunk_count; i++) {
        // Generate chunk hash using the token and chunk index
        char chunk_hash[HASH_SIZE] = {0};
        generate_chunk_hash(token, i, chunk_hash); // Use token, not chunk_path

        // Construct the chunk path using the generated hash
        char chunk_path[PATH_MAX];
        snprintf(chunk_path, sizeof(chunk_path), "%s%s.chunk", STORAGE_PATH, chunk_hash);


        // Verify chunk integrity
        if (verify_chunk(chunk_path, metadata->chunk_sizes[i] + IV_SIZE + TAG_SIZE) != 0) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Read chunk file
        FILE* chunk_file = fopen(chunk_path, "rb");
        if (!chunk_file) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Read IV
        unsigned char iv[IV_SIZE];
        if (fread(iv, 1, IV_SIZE, chunk_file) != IV_SIZE) {
            fclose(chunk_file);
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Read encrypted data
        size_t encrypted_size = metadata->chunk_sizes[i];
        if (fread(buffer, 1, encrypted_size, chunk_file) != encrypted_size) {
            fclose(chunk_file);
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Read authentication tag
        unsigned char tag[TAG_SIZE];
        if (fread(tag, 1, TAG_SIZE, chunk_file) != TAG_SIZE) {
            fclose(chunk_file);
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        fclose(chunk_file);

        // Initialize decryption
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Set expected tag
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Decrypt chunk
        int decrypted_len;
        if (!EVP_DecryptUpdate(ctx, decrypted, &decrypted_len, 
                             buffer, encrypted_size)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Write decrypted data
        if (fwrite(decrypted, 1, decrypted_len, output_file) != 
            (size_t)decrypted_len) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Finalize decryption
        int final_len;
        if (!EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &final_len)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(output_file);
            free(buffer);
            free(decrypted);
			decryption_failed = 1;
            return -1;
        }

        // Write any remaining decrypted data
        if (final_len > 0) {
            if (fwrite(decrypted + decrypted_len, 1, final_len, output_file) != 
                (size_t)final_len) {
                EVP_CIPHER_CTX_free(ctx);
                fclose(output_file);
                free(buffer);
                free(decrypted);
				decryption_failed = 1;
                return -1;
            }
        }

        total_processed += decrypted_len + final_len;
		
		// Update progress bar
        float progress = (total_processed / total_size);
        int current_progress = (int)(progress * progress_width);
        
        for (int j = last_progress; j < current_progress; j++) {
            printf(SILENT ? "" :"=");
            fflush(stdout);
        }
		last_progress = current_progress;
    }
	
	// Complete progress bar only if successful
    if (!decryption_failed) {
        while (last_progress < progress_width) {
            printf(SILENT ? "" :"=");
            last_progress++;
        }
        printf(SILENT ? "" :"] 100%%\n");
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(output_file);
    free(buffer);
    free(decrypted);

    // Verify all data was processed
    return (total_processed == metadata->file_size) ? 0 : -1;
}

// Core decryption function
int decrypt_file_core(FILE* ifp, FILE* ofp,
                     const unsigned char* key,
                     const unsigned char* provided_iv,  // renamed from iv to avoid conflict
                     size_t chunk_size) {              // renamed from file_size to match usage
    EVP_CIPHER_CTX* ctx = NULL;
    unsigned char local_iv[IV_SIZE];  // renamed from iv to avoid conflict
    unsigned char tag[16];
    unsigned char* buffer_in = NULL;
    unsigned char* buffer_out = NULL;
    int ret = -1;
    
    // Validate input parameters
    if (!ifp || !ofp || !key) {
        printf(!DEBUG ? "" :"Error: Invalid parameters provided to decrypt_file_core\n");
        return -1;
    }
    
    // Initialize buffers
    buffer_in = malloc(BUFFER_SIZE);
    buffer_out = malloc(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    if (!buffer_in || !buffer_out) {
        printf(!DEBUG ? "" :"Error: Memory allocation failed\n");
        goto cleanup;
    }
    
    // If IV is provided, use it; otherwise read from file
    if (provided_iv) {
        memcpy(local_iv, provided_iv, IV_SIZE);
    } else {
        if (fread(local_iv, 1, IV_SIZE, ifp) != IV_SIZE) {
            printf("Error reading IV from chunk\n");
            goto cleanup;
        }
    }
    
    // Initialize decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf(!DEBUG ? "" :"Error: Failed to create cipher context\n");
        goto cleanup;
    }
    
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, local_iv)) {
        printf(!DEBUG ? "" :"Error: Failed to initialize decryption\n");
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
                printf(!DEBUG ? "" :"Error: Unexpected end of file\n");
            } else {
                printf(!DEBUG ? "" :"Error: Failed to read chunk data\n");
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
                printf(!DEBUG ? "" :"Error: Failed to write decrypted data\n");
                goto cleanup;
            }
        }
        
        total_read += bytes_read;
    }
    
    if (total_read != data_size) {
        printf(!DEBUG ? "" :"Error: Chunk size mismatch - expected %zu bytes but read %zu\n", 
               data_size, total_read);
        goto cleanup;
    }

    // Read authentication tag
    if (fread(tag, 1, 16, ifp) != 16) {
        printf(!DEBUG ? "" :"Error: Failed to read authentication tag\n");
        goto cleanup;
    }
    
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        printf(!DEBUG ? "" :"Error: Failed to set authentication tag\n");
        goto cleanup;
    }
    
    int final_len;
    unsigned char final_buffer[EVP_MAX_BLOCK_LENGTH];
    if (!EVP_DecryptFinal_ex(ctx, final_buffer, &final_len)) {
        printf(!DEBUG ? "" :"Error: Authentication failed\n");
        goto cleanup;
    }
    
    if (final_len > 0) {
        if (fwrite(final_buffer, 1, final_len, ofp) != (size_t)final_len) {
            printf(!DEBUG ? "" :"Error: Failed to write final block\n");
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
