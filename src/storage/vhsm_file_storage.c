#include "vhsm.h"
#include "../utils/secure_memory.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <uuid/uuid.h>
#include <zlib.h>
#include <sys/stat.h>
#include <dirent.h>

#define MIN_CHUNK_SIZE (64 * 1024)      /* 64 KB */
#define MAX_CHUNK_SIZE (1024 * 1024)    /* 1 MB */
#define TOKEN_SIZE 37                    /* UUID string + null */

/* Chunk metadata */
typedef struct {
    char token[TOKEN_SIZE];
    uint32_t chunk_index;
    uint32_t total_chunks;
    size_t original_size;
    size_t compressed_size;
    size_t encrypted_size;
    uint8_t chunk_hash[VHSM_SHA256_SIZE];
    uint8_t iv[VHSM_GCM_IV_SIZE];
    uint8_t tag[VHSM_GCM_TAG_SIZE];
    vhsm_compress_t compression;
    int homomorphic;
} chunk_metadata_t;

/* File metadata */
typedef struct {
    char token[TOKEN_SIZE];
    char original_filename[256];
    size_t original_size;
    uint32_t chunk_count;
    time_t stored_time;
    vhsm_compress_t compression;
    int homomorphic;
    uint8_t file_hash[VHSM_SHA256_SIZE];
} file_metadata_t;

/* Generate random chunk size */
static size_t get_random_chunk_size(void) {
    uint32_t rand_val;
    if (RAND_bytes((uint8_t*)&rand_val, sizeof(rand_val)) != 1) {
        return MIN_CHUNK_SIZE;
    }

    size_t range = MAX_CHUNK_SIZE - MIN_CHUNK_SIZE;
    return MIN_CHUNK_SIZE + (rand_val % range);
}

/* Generate UUID token */
static void generate_token(char* token) {
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse_lower(uuid, token);
}

/* Compress data using zlib */
static vhsm_error_t compress_data(const uint8_t* input, size_t input_len,
                                   uint8_t* output, size_t* output_len) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return VHSM_ERROR_COMPRESSION_FAILED;
    }

    stream.next_in = (Bytef*)input;
    stream.avail_in = input_len;
    stream.next_out = output;
    stream.avail_out = *output_len;

    int ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&stream);
        return VHSM_ERROR_COMPRESSION_FAILED;
    }

    *output_len = stream.total_out;
    deflateEnd(&stream);

    return VHSM_SUCCESS;
}

/* Decompress data using zlib */
static vhsm_error_t decompress_data(const uint8_t* input, size_t input_len,
                                     uint8_t* output, size_t* output_len) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    if (inflateInit(&stream) != Z_OK) {
        return VHSM_ERROR_DECOMPRESSION_FAILED;
    }

    stream.next_in = (Bytef*)input;
    stream.avail_in = input_len;
    stream.next_out = output;
    stream.avail_out = *output_len;

    int ret = inflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&stream);
        return VHSM_ERROR_DECOMPRESSION_FAILED;
    }

    *output_len = stream.total_out;
    inflateEnd(&stream);

    return VHSM_SUCCESS;
}

/* Encrypt chunk (placeholder for homomorphic encryption) */
static vhsm_error_t encrypt_chunk(const uint8_t* key, const uint8_t* plaintext,
                                   size_t plaintext_len, uint8_t* ciphertext,
                                   size_t* ciphertext_len, uint8_t* iv, uint8_t* tag,
                                   int homomorphic) {
    if (homomorphic) {
        /* TODO: Implement homomorphic encryption using library like SEAL or HElib */
        /* For now, fall back to regular AES-GCM */
    }

    /* Generate IV */
    if (RAND_bytes(iv, VHSM_GCM_IV_SIZE) != 1) {
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    int len;
    size_t total_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }
    total_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VHSM_GCM_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);

    return VHSM_SUCCESS;
}

/* Decrypt chunk */
static vhsm_error_t decrypt_chunk(const uint8_t* key, const uint8_t* ciphertext,
                                   size_t ciphertext_len, uint8_t* plaintext,
                                   size_t* plaintext_len, const uint8_t* iv,
                                   const uint8_t* tag, int homomorphic) {
    if (homomorphic) {
        /* TODO: Implement homomorphic decryption */
        /* For now, fall back to regular AES-GCM */
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    int len;
    size_t total_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VHSM_GCM_TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }
    total_len += len;

    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);

    return VHSM_SUCCESS;
}

/* Save chunk to disk */
static vhsm_error_t save_chunk(const char* storage_path, chunk_metadata_t* meta,
                                const uint8_t* data, size_t data_len) {
    char dir_path[VHSM_MAX_PATH];
    char chunk_path[VHSM_MAX_PATH];

    snprintf(dir_path, sizeof(dir_path), "%s/chunks/%s", storage_path, meta->token);
    mkdir(dir_path, 0700);

    snprintf(chunk_path, sizeof(chunk_path), "%s/%08u.chunk", dir_path, meta->chunk_index);

    FILE* fp = fopen(chunk_path, "wb");
    if (!fp) {
        return VHSM_ERROR_IO_FAILED;
    }

    /* Write metadata */
    fwrite(meta, sizeof(chunk_metadata_t), 1, fp);

    /* Write encrypted data */
    fwrite(data, 1, data_len, fp);

    fclose(fp);
    chmod(chunk_path, 0600);

    return VHSM_SUCCESS;
}

/* Save file metadata */
static vhsm_error_t save_file_metadata(const char* storage_path, file_metadata_t* meta) {
    char meta_path[VHSM_MAX_PATH];
    snprintf(meta_path, sizeof(meta_path), "%s/chunks/%s/metadata.dat",
             storage_path, meta->token);

    FILE* fp = fopen(meta_path, "wb");
    if (!fp) {
        return VHSM_ERROR_IO_FAILED;
    }

    fwrite(meta, sizeof(file_metadata_t), 1, fp);
    fclose(fp);
    chmod(meta_path, 0600);

    return VHSM_SUCCESS;
}

/* Store file with chunking and encryption */
vhsm_error_t vhsm_file_store(vhsm_session_t session, vhsm_key_handle_t key_handle,
                              const char* source_path, vhsm_compress_t compression,
                              int use_homomorphic, char* token_out, size_t token_len) {
    if (!session || key_handle == VHSM_INVALID_HANDLE || !source_path ||
        !token_out || token_len < TOKEN_SIZE) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    if (!vhsm_session_is_valid(session)) {
        return VHSM_ERROR_SESSION_INVALID;
    }

    /* Open source file */
    FILE* fp = fopen(source_path, "rb");
    if (!fp) {
        return VHSM_ERROR_IO_FAILED;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Generate token */
    char token[TOKEN_SIZE];
    generate_token(token);

    /* Initialize file metadata */
    file_metadata_t file_meta;
    memset(&file_meta, 0, sizeof(file_meta));
    strncpy(file_meta.token, token, TOKEN_SIZE - 1);
    strncpy(file_meta.original_filename, source_path, sizeof(file_meta.original_filename) - 1);
    file_meta.original_size = file_size;
    file_meta.compression = compression;
    file_meta.homomorphic = use_homomorphic;
    file_meta.stored_time = time(NULL);

    /* TODO: Get storage path and encryption key from session context */
    /* For now, this is a skeleton implementation */

    uint8_t temp_key[32] = {0};  /* Placeholder */
    const char* storage_path = "/tmp/vhsm";  /* Placeholder */

    /* Process file in random-sized chunks */
    uint32_t chunk_index = 0;
    size_t bytes_read;
    uint8_t* chunk_buffer = malloc(MAX_CHUNK_SIZE);
    uint8_t* compressed_buffer = malloc(MAX_CHUNK_SIZE * 2);
    uint8_t* encrypted_buffer = malloc(MAX_CHUNK_SIZE * 2 + 256);

    if (!chunk_buffer || !compressed_buffer || !encrypted_buffer) {
        fclose(fp);
        free(chunk_buffer);
        free(compressed_buffer);
        free(encrypted_buffer);
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    vhsm_error_t result = VHSM_SUCCESS;

    while ((bytes_read = fread(chunk_buffer, 1, get_random_chunk_size(), fp)) > 0) {
        chunk_metadata_t chunk_meta;
        memset(&chunk_meta, 0, sizeof(chunk_meta));
        strncpy(chunk_meta.token, token, TOKEN_SIZE - 1);
        chunk_meta.chunk_index = chunk_index++;
        chunk_meta.original_size = bytes_read;
        chunk_meta.compression = compression;
        chunk_meta.homomorphic = use_homomorphic;

        /* Hash chunk */
        SHA256(chunk_buffer, bytes_read, chunk_meta.chunk_hash);

        const uint8_t* data_to_encrypt = chunk_buffer;
        size_t encrypt_len = bytes_read;

        /* Compress if requested */
        if (compression == VHSM_COMPRESS_ZLIB) {
            size_t compressed_len = MAX_CHUNK_SIZE * 2;
            result = compress_data(chunk_buffer, bytes_read,
                                   compressed_buffer, &compressed_len);
            if (result != VHSM_SUCCESS) {
                break;
            }
            data_to_encrypt = compressed_buffer;
            encrypt_len = compressed_len;
            chunk_meta.compressed_size = compressed_len;
        } else {
            chunk_meta.compressed_size = bytes_read;
        }

        /* Encrypt chunk */
        size_t encrypted_len = MAX_CHUNK_SIZE * 2 + 256;
        result = encrypt_chunk(temp_key, data_to_encrypt, encrypt_len,
                               encrypted_buffer, &encrypted_len,
                               chunk_meta.iv, chunk_meta.tag, use_homomorphic);
        if (result != VHSM_SUCCESS) {
            break;
        }

        chunk_meta.encrypted_size = encrypted_len;

        /* Save chunk */
        result = save_chunk(storage_path, &chunk_meta, encrypted_buffer, encrypted_len);
        if (result != VHSM_SUCCESS) {
            break;
        }
    }

    file_meta.chunk_count = chunk_index;

    /* Save file metadata */
    if (result == VHSM_SUCCESS) {
        result = save_file_metadata(storage_path, &file_meta);
        if (result == VHSM_SUCCESS) {
            strncpy(token_out, token, token_len - 1);
        }
    }

    /* Cleanup */
    secure_wipe(chunk_buffer, MAX_CHUNK_SIZE);
    secure_wipe(compressed_buffer, MAX_CHUNK_SIZE * 2);
    secure_wipe(encrypted_buffer, MAX_CHUNK_SIZE * 2 + 256);
    free(chunk_buffer);
    free(compressed_buffer);
    free(encrypted_buffer);
    fclose(fp);

    return result;
}

vhsm_error_t vhsm_file_retrieve(vhsm_session_t session, vhsm_key_handle_t key_handle,
                                 const char* token, const char* dest_path) {
    if (!session || key_handle == VHSM_INVALID_HANDLE || !token || !dest_path) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    if (!vhsm_session_is_valid(session)) {
        return VHSM_ERROR_SESSION_INVALID;
    }

    /* TODO: Implement file retrieval */
    return VHSM_ERROR_NOT_IMPLEMENTED;
}

vhsm_error_t vhsm_file_delete(vhsm_session_t session, const char* token) {
    if (!session || !token) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    if (!vhsm_session_is_valid(session)) {
        return VHSM_ERROR_SESSION_INVALID;
    }

    /* TODO: Implement file deletion */
    return VHSM_ERROR_NOT_IMPLEMENTED;
}

vhsm_error_t vhsm_file_list(vhsm_session_t session, char** tokens, size_t* count) {
    if (!session || !count) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    if (!vhsm_session_is_valid(session)) {
        return VHSM_ERROR_SESSION_INVALID;
    }

    /* TODO: Implement file listing */
    return VHSM_ERROR_NOT_IMPLEMENTED;
}
