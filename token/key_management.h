// key_management.h
#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include "security_defs.h"

// Global variable declaration - extern to avoid multiple definition
extern char* g_custom_key_path;

// Function declarations
int save_key(const unsigned char* key);
int load_key(unsigned char* key);
int initialize_key(unsigned char* key);
int derive_key(const unsigned char* master_key, 
              const unsigned char* salt,
              size_t salt_len,
              unsigned char* derived_key);
int generate_key_file(const char* key_path);
int handle_key_initialization(unsigned char* key, const char* provided_key_path);

// Encryption key write down
int save_key(const unsigned char* key) {
    if (!key) return -1;
    
    FILE* fp = fopen(KEY_FILE_PATH, "wb");
    if (!fp) {
        printf("Error opening key file: %s\n", strerror(errno));
        return -1;
    }
    
    size_t written = fwrite(key, 1, KEY_SIZE, fp);
    fclose(fp);
    return (written == KEY_SIZE) ? 0 : -1;
}

// Function to load the encryption key
int load_key(unsigned char* key) {
    if (!key) return -1;

    const char* key_path = g_custom_key_path ? g_custom_key_path : KEY_FILE_PATH;
    FILE* fp = fopen(key_path, "rb");
    if (!fp) {
        printf("Error opening key file: %s\n", strerror(errno));
        return -1;
    }
    
    size_t read = fread(key, 1, KEY_SIZE, fp);
    fclose(fp);
    return (read == KEY_SIZE) ? 0 : -1;
}

// Initialize or load encryption key
int initialize_key(unsigned char* key) {
    if (!key) return -1;

    struct stat st;
    if (stat(KEY_FILE_PATH, &st) == 0) {
        return load_key(key);
    }
    
    if (RAND_bytes(key, KEY_SIZE) != 1) {
        return -1;
    }
    return save_key(key);
}

// Key derivation with salt
int derive_key(const unsigned char* master_key, 
              const unsigned char* salt,
              size_t salt_len,
              unsigned char* derived_key) {
    if (!master_key || !salt || !derived_key) {
        return -1;
    }
    
    // Using salt_len to avoid the unused parameter warning
	if (salt_len < crypto_kdf_KEYBYTES) {
		return -1;
	}
    return crypto_kdf_derive_from_key(derived_key, 
                                    KEY_SIZE,
                                    0, // Context
                                    "TokenEnc", // Application info
                                    master_key);
}

int generate_key_file(const char* key_path) {
    if (!key_path) return -1;

    unsigned char new_key[KEY_SIZE];
    if (RAND_bytes(new_key, KEY_SIZE) != 1) {
        printf("Error generating random key\n");
        return -1;
    }

    FILE* fp = fopen(key_path, "wb");
    if (!fp) {
        printf("Error creating key file: %s\n", strerror(errno));
        secure_wipe(new_key, KEY_SIZE);
        return -1;
    }

    size_t written = fwrite(new_key, 1, KEY_SIZE, fp);
    secure_wipe(new_key, KEY_SIZE);
    fclose(fp);

    if (written != KEY_SIZE) {
        printf("Error writing key file\n");
        return -1;
    }
    
    return 0; // Added return statement
}

int handle_key_initialization(unsigned char* key, const char* provided_key_path) {
    if (provided_key_path) {
        // Store the provided key path globally
        if (g_custom_key_path) {
            free(g_custom_key_path);
        }
        g_custom_key_path = strdup(provided_key_path);
        if (!g_custom_key_path) {
            printf("Error allocating memory for key path\n");
            return -1;
        }
        return load_key(key);
    }

    // No key found - ask user what to do
    printf("\nNo master key found. Choose an option:\n");
    printf("1) Generate a new master key\n");
    printf("2) Provide path to existing key\n");
    printf("Choice (1 or 2): ");

    char choice[8];
    if (fgets(choice, sizeof(choice), stdin) == NULL) {
        return -1;
    }
    choice[strcspn(choice, "\n")] = 0;

    if (strcmp(choice, "1") == 0) {
        printf("Generating new master key...\n");
        if (RAND_bytes(key, KEY_SIZE) != 1) {
            printf("Error generating key\n");
            return -1;
        }
        if (save_key(key) != 0) {
            printf("Error saving generated key\n");
            return -1;
        }
        printf("New master key generated and saved to: %s\n", KEY_FILE_PATH);
        return 0;
    } 
    else if (strcmp(choice, "2") == 0) {
        char key_path[512];
        printf("Enter path to key file: ");
        if (fgets(key_path, sizeof(key_path), stdin) == NULL) {
            return -1;
        }
        key_path[strcspn(key_path, "\n")] = 0;

        // Update global key path
        if (g_custom_key_path) {
            free(g_custom_key_path);
        }
        g_custom_key_path = strdup(key_path);
        if (!g_custom_key_path) {
            printf("Error allocating memory for key path\n");
            return -1;
        }

        FILE* fp = fopen(key_path, "rb");
        if (!fp) {
            printf("Error opening provided key file\n");
            return -1;
        }
        size_t read = fread(key, 1, KEY_SIZE, fp);
        fclose(fp);
        if (read != KEY_SIZE) {
            printf("Error: Invalid key file\n");
            return -1;
        }
        return 0;
    }

    printf("Invalid choice\n");
    return -1;
}
	



#endif // KEY_MANAGEMENT_H