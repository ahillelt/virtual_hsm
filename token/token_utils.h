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

//forward declare
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

#endif // TOKEN_UTILS_H