// token_utils.h - Token generation and validation
#ifndef TOKEN_UTILS_H
#define TOKEN_UTILS_H

#include "security_defs.h"
#include <uuid/uuid.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

// Function declarations
char* generate_token(void);
int validate_token(const char* token);
void hash_token(const char* token, char* hashed_filename);
void generate_chunk_hash(const char* token, size_t chunk_index, char* chunk_hash);
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex);

// Generate a unique token using UUID
char* generate_token(void) {
    char* token = malloc(TOKEN_SIZE);
    if (!token) {
        return NULL;
    }
    
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, token);
    return token;
}

// Validate token format and length
int validate_token(const char* token) {
    if (!token || strlen(token) < MIN_TOKEN_LEN) {
        return -1;
    }
    
    for (size_t i = 0; token[i]; i++) {
        if (!isalnum(token[i]) && token[i] != '-') {
            return -1;
        }
    }
    
    return 0;
}

// Convert bytes to hexadecimal string
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2] = hex_chars[bytes[i] >> 4];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0f];
    }
    hex[len * 2] = '\0';
}

// Function to hash token into filename
void hash_token(const char* token, char* hashed_filename) {
    if (!token || !hashed_filename) return;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("Error creating message digest context\n");
        return;
    }

    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, token, strlen(token)) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        printf("Error in digest operation\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    bytes_to_hex(hash, hash_len, hashed_filename);
    EVP_MD_CTX_free(mdctx);
}

// Generate hash for a specific chunk
void generate_chunk_hash(const char* token, size_t chunk_index, char* chunk_hash) {
    if (!token || !chunk_hash) return;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("Error creating message digest context\n");
        return;
    }

    const EVP_MD *md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    char index_str[32];
    snprintf(index_str, sizeof(index_str), "%zu", chunk_index);

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, token, strlen(token)) != 1 ||
        EVP_DigestUpdate(mdctx, index_str, strlen(index_str)) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        printf("Error in digest operation\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    bytes_to_hex(hash, hash_len, chunk_hash);
    EVP_MD_CTX_free(mdctx);
}

#endif // TOKEN_UTILS_H