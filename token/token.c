#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "security_defs.h"
#include "metadata.h"
#include "key_management.h"
#include "crypto_ops.h"
#include "token_utils.h"
#include "file_ops.h"

// Function declarations should be after includes but before any code
void cleanup_secure(void);
void cleanup_key_path(void);
void secure_wipe(void* ptr, size_t len);

// Global variables
char* g_custom_key_path = NULL;  // Custom key path storage

// Help text definition
#define HELP_TEXT \
    "Usage:\n" \
    "To store with auto-generated key:\n" \
    "  %s store <filepath>\n" \
    "To store with existing key:\n" \
    "  %s store <filepath> --key <keypath>\n" \
    "To retrieve:\n" \
    "  %s retrieve <token> <output_path> [--key <keypath>]\n" \
    "To generate a new master key:\n" \
    "  %s generate-key <output_keypath>\n"

// Cleanup functions
void cleanup_secure(void) {
    // Wipe sensitive global data
    if (g_custom_key_path) {
        secure_wipe(g_custom_key_path, strlen(g_custom_key_path));
        free(g_custom_key_path);
        g_custom_key_path = NULL;
    }
    
    // Reset OpenSSL state
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
}

void cleanup_key_path(void) {
    if (g_custom_key_path) {
        secure_wipe(g_custom_key_path, strlen(g_custom_key_path));
        free(g_custom_key_path);
        g_custom_key_path = NULL;
    }
}

void secure_wipe(void* ptr, size_t len) {
    SECURE_WIPE(ptr, len);
}

int main(int argc, char* argv[]) {
    int ret = 0;
    SecurityError error = {0};
    char** chunk_paths = NULL;
    char* token = NULL;
    size_t chunk_count = 0;

    if (argc < 2) {
        printf(HELP_TEXT, argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    // Create storage directory if it doesn't exist
    struct stat st = {0};
    if (stat(STORAGE_PATH, &st) == -1) {
        if (mkdir(STORAGE_PATH, 0700) == -1) {
            fprintf(stderr, "Error creating storage directory: %s\n", strerror(errno));
            return 1;
        }
    }

    OpenSSL_add_all_algorithms();
    
    // Initialize secure components
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }
    
    // Set up secure error handling
    if (atexit(cleanup_secure) != 0) {
        fprintf(stderr, "Failed to register cleanup handler\n");
        return 1;
    }

    // Handle generate-key command
    if (strcmp(argv[1], "generate-key") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Path required for key generation\n");
            return 1;
        }
        return generate_key_file(argv[2]);
    }

    // Parse command line arguments for key path
    char* key_path = NULL;
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--key") == 0) {
            key_path = argv[i + 1];
            break;
        }
    }

    unsigned char key[KEY_SIZE];
    if (handle_key_initialization(key, key_path) != 0) {
        fprintf(stderr, "Error initializing encryption key\n");
        return 1;
    }

    if (strcmp(argv[1], "store") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: File path required for storage\n");
            return 1;
        }

        token = generate_token();
        if (!token) {
            fprintf(stderr, "Error generating token\n");
            ret = 1;
            goto cleanup;
        }
        
        
        size_t original_file_size = 0;
        
        SecureMetadata metadata = {0};
        strncpy(metadata.token, token, TOKEN_SIZE);

        if (handle_store_file(argv[2], &chunk_paths, &chunk_count, token, 
                            &original_file_size, &metadata) != 0) {
            ret = 1;
            goto cleanup;
        }

        metadata.data_size = original_file_size;
        strncpy(metadata.original_filename, basename(argv[2]), 
                sizeof(metadata.original_filename) - 1);

        printf("Encrypting file in chunks...\n");
        if (encrypt_file_secure(argv[2], chunk_paths, chunk_count, key, 
                              &metadata, &error) == 0) {
            printf("Saving metadata...\n");
            if (save_metadata(&metadata) == 0) {
                printf("\nFile encrypted successfully in %zu chunks.\n", chunk_count);
                printf("Token: %s\n", token);
                printf("Keep this token safe - you'll need it to retrieve your file.\n");
            } else {
                fprintf(stderr, "Error saving metadata\n");
                ret = 1;
            }
        } else {
            fprintf(stderr, "Error: %s\n", error.message);
            ret = 1;
        }
    }
    else if (strcmp(argv[1], "retrieve") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Error: Token and output path required for retrieval\n");
            ret = 1;
            goto cleanup;
        }

        printf("\nStarting file retrieval process...\n");
        printf("Token: %s\n", argv[2]);
        
        SecureMetadata metadata;
        printf("Loading metadata...\n");
        
        if (load_metadata(argv[2], &metadata) == 0) {
            if (decrypt_file_chunked(argv[3], key, &metadata) == 0) {
                printf("\nRetrieval process completed successfully.\n");
            } else {
                if (handle_decryption_failure(key, argv[2], argv[3]) == 0) {
                    printf("\nRetrieval process completed successfully with alternative key.\n");
                } else {
                    fprintf(stderr, "\nDecryption failed with all attempted keys.\n");
                    ret = 1;
                }
            }
        } else {
            fprintf(stderr, "Error: Could not load or decrypt metadata.\n");
            if (handle_decryption_failure(key, argv[2], argv[3]) == 0) {
                printf("\nRetrieval process completed successfully with alternative key.\n");
            } else {
                fprintf(stderr, "\nAll decryption attempts failed.\n");
                ret = 1;
            }
        }
    }
    else {
        printf(HELP_TEXT, argv[0], argv[0], argv[0], argv[0]);
        ret = 1;
    }

cleanup:
    if (chunk_paths) {
        for (size_t i = 0; i < chunk_count; i++) {  // Use chunk_count instead of NULL check
            if (chunk_paths[i]) {  // Still check for NULL in case of partial allocation
                secure_wipe(chunk_paths[i], strlen(chunk_paths[i]));
                free(chunk_paths[i]);
            }
        }
        free(chunk_paths);
    }
    
    if (token) {
        secure_wipe(token, strlen(token));
        free(token);
    }

    cleanup_key_path();
    secure_wipe(key, KEY_SIZE);
    
    return ret;
}