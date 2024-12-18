#ifndef KEY_FUNC_H
#define KEY_FUNC_H

#define DEBUG_PRINT(fmt, ...) fprintf(stderr, "Debug: " fmt "\n", ##__VA_ARGS__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>

#include "hsm_shared.h"
#include "utils.h"
#include "common_defs.h"

// External declarations for global variables
extern unsigned char master_key[KEY_SIZE];
extern char master_key_file[MAX_FILENAME];
extern char keystore_file[MAX_FILENAME];
extern KeyEntry keystore[MAX_KEYS];
extern int key_count;

// Function declarations
void generate_master_key(void);
void load_master_key(const char *provided_key);
void save_keystore(void);
void load_keystore(void);
int encrypt_key(const unsigned char *plaintext, unsigned char *ciphertext, 
                int *ciphertext_len, unsigned char *iv, unsigned char *tag);
int decrypt_key(const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext, const unsigned char *iv,
                const unsigned char *tag);
void store_key(const char *name, const unsigned char *key, int is_public_key);
void store_public_key(const char *name, const unsigned char *key, size_t key_len);
void retrieve_key(const char *name);
void list_keys(void);

void generate_master_key() {
    unsigned char new_master_key[KEY_SIZE];
    if (RAND_bytes(new_master_key, KEY_SIZE) != 1) {
        handle_errors();
    }

    printf("Generated Master Key (hex format for GitHub Secret):\n");
    for (int i = 0; i < KEY_SIZE; i++) {
        printf("%02x", new_master_key[i]);
    }
    printf("\n");

    // Removed implicit storing of master key
}

void load_master_key(const char *provided_key) {
    DEBUG_PRINT("Entering load_master_key function");
    if (provided_key) {
        DEBUG_PRINT("Master key provided via command line");
        if (strlen(provided_key) != KEY_SIZE * 2) {
            fprintf(stderr, "Error: Invalid master key length. Expected %d hex characters, got %zu.\n", 
                    KEY_SIZE * 2, strlen(provided_key));
            exit(1);
        }
        hex_to_bytes(provided_key, master_key, KEY_SIZE);
        DEBUG_PRINT("Master key loaded successfully");
        return;
    }

    FILE *file = fopen(master_key_file, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: Master key file not found and no key provided.\n");
        exit(1);
    } else {
        if (fread(master_key, 1, KEY_SIZE, file) != KEY_SIZE) {
            fprintf(stderr, "Error: Invalid master key file.\n");
            fclose(file);
            exit(1);
        }
        fclose(file);
        printf("WARNING: Master key loaded from file. This is insecure and should only be used for educational purposes.\n");
    }
}

void save_keystore() {
    FILE *file = fopen(keystore_file, "wb");
    if (file == NULL) {
        fprintf(stderr, "Error opening keystore file for writing.\n");
        exit(1);
    }
    fwrite(&key_count, sizeof(int), 1, file);
    fwrite(keystore, sizeof(KeyEntry), key_count, file);
    fclose(file);
}

void load_keystore() {
    DEBUG_PRINT("Entering load_keystore function");
    FILE *file = fopen(keystore_file, "rb");
    if (file != NULL) {
        fread(&key_count, sizeof(int), 1, file);
        fread(keystore, sizeof(KeyEntry), key_count, file);
        fclose(file);
        DEBUG_PRINT("Keystore loaded with %d keys", key_count);
    } else {
        DEBUG_PRINT("No existing keystore found");
    }
}

int encrypt_key(const unsigned char *plaintext, unsigned char *ciphertext, 
                int *ciphertext_len, unsigned char *iv, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        handle_errors();
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) 
        handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv))
        handle_errors();

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, KEY_SIZE))
        handle_errors();
    
    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_errors();
    
    *ciphertext_len += len;

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt_key(const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext, const unsigned char *iv,
                const unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    DEBUG_PRINT("Entering decrypt_key function");
    DEBUG_PRINT("Ciphertext length: %d", ciphertext_len);
    DEBUG_PRINT("IV (first 4 bytes): %02x%02x%02x%02x", iv[0], iv[1], iv[2], iv[3]);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        DEBUG_PRINT("Failed to create cipher context");
        handle_errors();
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv)) {
        DEBUG_PRINT("Failed to initialize decryption");
        handle_errors();
    }

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        DEBUG_PRINT("Failed during decryption update");
        handle_errors();
    }
    plaintext_len = len;

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag)) {
        DEBUG_PRINT("Failed to set authentication tag");
        handle_errors();
    }

    // Finalize decryption and verify tag
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret <= 0) {
        DEBUG_PRINT("Authentication failed or decrypt error");
        handle_errors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    DEBUG_PRINT("Decryption completed successfully");
    return plaintext_len;
}

void store_key(const char *name, const unsigned char *key, int is_public_key) {
    DEBUG_PRINT("Entering store_key function for key '%s'", name);
    if (key_count >= MAX_KEYS) {
        fprintf(stderr, "Error: Keystore is full.\n");
        exit(1);
    }

    if (strlen(name) > MAX_NAME_LENGTH) {
        fprintf(stderr, "Error: Key name is too long.\n");
        exit(1);
    }

	
    KeyEntry *entry = &keystore[key_count++];
    strncpy(entry->name, name, MAX_NAME_LENGTH);
    entry->name[MAX_NAME_LENGTH] = '\0';
    entry->is_public_key = is_public_key;




    if (is_public_key) {
        memcpy(entry->key_data, key, KEY_SIZE);
        entry->encrypted_len = KEY_SIZE;
    } else {
        DEBUG_PRINT("Starting encryption process");
        if (!encrypt_key(key, entry->key_data, &entry->encrypted_len, 
                        entry->iv, entry->tag)) {
            fprintf(stderr, "Error: Failed to encrypt key.\n");
            exit(1);
        }
    }
	
	// Compute and store master key hash
    unsigned char master_key_hash[MASTER_KEY_HASH_SIZE];
    SHA256(master_key, KEY_SIZE, master_key_hash); // Assuming SHA256 hash
    memcpy(entry->master_key_hash, master_key_hash, MASTER_KEY_HASH_SIZE);
    
    save_keystore();
    DEBUG_PRINT("Key stored successfully");
}

void store_public_key(const char *name, const unsigned char *key, size_t key_len) {
    DEBUG_PRINT("Entering store_public_key function for key '%s'", name);
    if (key_count >= MAX_KEYS) {
        fprintf(stderr, "Error: Keystore is full.\n");
        exit(1);
    }

    if (strlen(name) > MAX_NAME_LENGTH) {
        fprintf(stderr, "Error: Key name is too long.\n");
        exit(1);
    }

    if (key_len != KEY_SIZE) {
        fprintf(stderr, "Error: Invalid key length.\n");
        exit(1);
    }

    KeyEntry *entry = &keystore[key_count++];
    strncpy(entry->name, name, MAX_NAME_LENGTH);
    entry->name[MAX_NAME_LENGTH] = '\0';
    entry->is_public_key = 1;
    memcpy(entry->key_data, key, KEY_SIZE);
    entry->encrypted_len = KEY_SIZE;

    save_keystore();
    DEBUG_PRINT("Public key stored successfully");
}

void retrieve_key(const char *name) {
    DEBUG_PRINT("Entering retrieve_key function for key '%s'", name);
    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            DEBUG_PRINT("Key '%s' found in keystore", name);
            DEBUG_PRINT("Encrypted length: %d", keystore[i].encrypted_len);
            
            unsigned char decrypted_key[KEY_SIZE];
            memset(decrypted_key, 0, KEY_SIZE);
            
            DEBUG_PRINT("Starting decryption process");
            int decrypted_len = decrypt_key(keystore[i].key_data,  // Changed from encrypted_key to key_data
                                          keystore[i].encrypted_len,
                                          decrypted_key, 
                                          keystore[i].iv,
                                          keystore[i].tag);
            
            if (decrypted_len != KEY_SIZE) {
                fprintf(stderr, "Error: Decrypted key length mismatch\n");
                exit(1);
            }
            
            // Output in hex format
            for (int j = 0; j < KEY_SIZE; j++) {
                printf("%02x", decrypted_key[j]);
            }
            printf("\n");
            DEBUG_PRINT("Key retrieved successfully");
            return;
        }
    }
    fprintf(stderr, "Error: Key '%s' not found.\n", name);
    exit(1);
}

void list_keys() {
    unsigned char current_master_key_hash[MASTER_KEY_HASH_SIZE];
    SHA256(master_key, KEY_SIZE, current_master_key_hash); // Assuming SHA256 hash

    for (int i = 0; i < key_count; i++) {
        if (memcmp(current_master_key_hash, keystore[i].master_key_hash, MASTER_KEY_HASH_SIZE) == 0) {
            // Hash matches, display the key name
            printf("%s\n", keystore[i].name);
        }
    }
}

#endif // KEY_FUNC_H
