// file_ops.h - File operations and handling
#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>
#include <errno.h>
#include <unistd.h>

#include "security_defs.h"
#include "metadata.h"
#include "types.h"

// Structure to track chunk status
typedef struct {
    char* path;
    size_t size;
    int written;
    char hash[HASH_SIZE];  
} ChunkStatus;

// Forward declaration from crypto_ops.h to break circular dependency
int decrypt_file_chunked(const char* output_dir, 
                        unsigned char* key, 
                        const SecureMetadata* metadata);

// Function declarations
void print_file_info(const char* filepath);
char* handle_file_conflict(const char* output_dir, const char* original_filename);

int handle_decryption_failure(unsigned char* key, 
                            const char* token, 
                            const char* output_path);
							
size_t generate_chunk_size(size_t remaining_size);

ErrorCode handle_store_file(void* args);
					 
int sanitize_path(const char* input, char* output, size_t outlen);
int ensure_directory_exists(const char* path);
typedef int (*operation_func)(void*);

// Print file information
void print_file_info(const char* filepath) {
    if (!filepath) return;

    struct stat st;
    if (stat(filepath, &st) == 0) {
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));
        printf("Size: %ld bytes\n", st.st_size);
        printf("Last modified: %s\n", time_str);
    }
}

// Handle file conflicts
char* handle_file_conflict(const char* output_dir, const char* original_filename) {
    static char final_path[512];
    const char* base_filename = strrchr(original_filename, '/');
    base_filename = (base_filename == NULL) ? original_filename : base_filename + 1;

    // Ensure output directory exists before proceeding
    if (ensure_directory_exists(output_dir) != 0) {
        printf("Failed to create output directory structure\n");
        return NULL;
    }

    snprintf(final_path, sizeof(final_path), "%s/%s", output_dir, base_filename);

    if (access(final_path, F_OK) != -1) {
        printf("\nFile already exists: %s\n", final_path);
        printf("Existing file information:\n");
        print_file_info(final_path);

        printf("\nChoose an option:\n");
        printf("1) Overwrite existing file\n");
        printf("2) Enter new filename\n");
        printf("Choice (1 or 2): ");
        
        char choice[8];
        if (fgets(choice, sizeof(choice), stdin) != NULL) {
            choice[strcspn(choice, "\n")] = 0;
            
            if (strcmp(choice, "2") == 0) {
                char new_filename[256];
                printf("Enter new filename: ");
                if (fgets(new_filename, sizeof(new_filename), stdin) != NULL) {
                    new_filename[strcspn(new_filename, "\n")] = 0;
                    snprintf(final_path, sizeof(final_path), "%s/%s", output_dir, new_filename);
                }
            } else if (strcmp(choice, "1") != 0) {
                return NULL;
            }
        }
    }

    return final_path;
}

int handle_decryption_failure(unsigned char* key, const char* token, const char* output_path) {
    printf("\nDecryption failed. This could be due to:\n");
    printf("1) Incorrect master key\n");
    printf("2) Corrupted data\n");
    printf("3) Invalid token\n\n");
    
    printf("Would you like to try a different master key? (y/n): ");
    char choice[8];
    if (fgets(choice, sizeof(choice), stdin) == NULL) {
        return -1;
    }
    choice[strcspn(choice, "\n")] = 0;

    if (choice[0] == 'y' || choice[0] == 'Y') {
        printf("Enter path to alternative key file: ");
        char key_path[512];
        if (fgets(key_path, sizeof(key_path), stdin) == NULL) {
            return -1;
        }
        key_path[strcspn(key_path, "\n")] = 0;

        FILE* fp = fopen(key_path, "rb");
        if (!fp) {
            printf("Error opening key file\n");
            return -1;
        }
        size_t read = fread(key, 1, KEY_SIZE, fp);
        fclose(fp);

        if (read != KEY_SIZE) {
            printf("Error: Invalid key file\n");
            return -1;
        }

        // Try decryption again with new key
        SecureMetadata metadata;
        printf("\nRetrying decryption with new key...\n");
        if (load_metadata(token, &metadata) == 0) {
            return decrypt_file_chunked(output_path, key, &metadata);
        }
    }

    return -1;
}

size_t generate_chunk_size(size_t remaining_size) {
    // If remaining size is less than or equal to MIN_CHUNK_SIZE, use all remaining
    if (remaining_size <= MIN_CHUNK_SIZE) {
        return remaining_size;
    }
    
    // If remaining size is less than or equal to MAX_CHUNK_SIZE, calculate appropriate size
    if (remaining_size <= MAX_CHUNK_SIZE) {
        return remaining_size;
    }
    
    // For files larger than MAX_CHUNK_SIZE, use MAX_CHUNK_SIZE
    // This ensures consistent chunking and prevents fragmentation
    return MAX_CHUNK_SIZE;
}


// verify chunk integrity
int verify_chunk(const char* chunk_path, size_t expected_size) {
    struct stat st;
    if (stat(chunk_path, &st) != 0) {
        printf("Error: Cannot access chunk file %s: %s\n", 
               chunk_path, strerror(errno));
        return -1;
    }
    
    // Convert st_size to unsigned for comparison
    if (st.st_size < 0 || (size_t)st.st_size != expected_size) {
        printf("Error: Chunk size mismatch for %s (expected: %zu, actual: %zu)\n",
               chunk_path, expected_size, (size_t)st.st_size);
        return -1;
    }
    
    return 0;
}

ErrorCode handle_store_file(void* args) {
    if (!args) {
        return ERROR_INVALID_INPUT;
    }

    StoreFileArgs* store_args = (StoreFileArgs*)args;
    
    // Validate all required parameters
    if (!store_args->filepath || !store_args->chunk_paths || 
        !store_args->chunk_count || !store_args->token || 
        !store_args->file_size || !store_args->metadata) {
        return ERROR_INVALID_INPUT;
    }

    // Get file size
    struct stat st;
    if (stat(store_args->filepath, &st) != 0) {
        return ERROR_SYSTEM;
    }
    *store_args->file_size = st.st_size;

    // Calculate number of chunks needed
    size_t chunk_count = (*store_args->file_size + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    *store_args->chunk_count = chunk_count;

    // Allocate memory for chunk paths array
    *store_args->chunk_paths = malloc(chunk_count * sizeof(char*));
    if (!*store_args->chunk_paths) {
        return ERROR_SYSTEM;
    }

    // Generate chunk paths and create empty files
    for (size_t i = 0; i < chunk_count; i++) {
        char chunk_hash[65] = {0};
        generate_chunk_hash(store_args->token, i, chunk_hash);
        
        (*store_args->chunk_paths)[i] = malloc(strlen(STORAGE_PATH) + HASH_SIZE + 7); // +7 for ".chunk\0"
        if (!(*store_args->chunk_paths)[i]) {
            // Cleanup previously allocated paths
            for (size_t j = 0; j < i; j++) {
                free((*store_args->chunk_paths)[j]);
            }
            free(*store_args->chunk_paths);
            *store_args->chunk_paths = NULL;
            return ERROR_SYSTEM;
        }

        if (snprintf((*store_args->chunk_paths)[i], strlen(STORAGE_PATH) + HASH_SIZE + 7,
                    "%s%s.chunk", STORAGE_PATH, chunk_hash) < 0) {
            // Handle error
            for (size_t j = 0; j <= i; j++) {
                free((*store_args->chunk_paths)[j]);
            }
            free(*store_args->chunk_paths);
            *store_args->chunk_paths = NULL;
            return ERROR_SYSTEM;
        }
        
        // Store chunk hash in metadata
        strncpy(store_args->metadata->chunk_hashes[i], chunk_hash, 64);
        
        // Create empty chunk file
        FILE* fp = fopen((*store_args->chunk_paths)[i], "wb");
        if (!fp) {
            // Cleanup on error
            for (size_t j = 0; j <= i; j++) {
                free((*store_args->chunk_paths)[j]);
            }
            free(*store_args->chunk_paths);
            *store_args->chunk_paths = NULL;
            return ERROR_SYSTEM;
        }
        fclose(fp);
    }

    return SUCCESS;
}

int sanitize_path(const char* input, char* output, size_t outlen) {
    char resolved[PATH_MAX];
    
    if (!input || !output || outlen == 0) {
        return -1;
    }
    
    // Resolve the full path
    if (!realpath(input, resolved)) {
        return -1;
    }
    
    // Verify path doesn't contain dangerous components
    if (strstr(resolved, "..") || strstr(resolved, "//")) {
        return -1;
    }
    
    // Copy sanitized path - use strlcpy if available, otherwise strncpy
    #ifdef __APPLE__
        if (strlcpy(output, resolved, outlen) >= outlen) {
            return -1;
        }
    #else
        strncpy(output, resolved, outlen - 1);
        output[outlen - 1] = '\0';
    #endif
    
    return 0;
}

int ensure_directory_exists(const char* path) {
    if (!path) return -1;
    
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0) return -1;
    
    // Remove trailing slash if present
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    
    // Start from the root
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (access(tmp, F_OK) != 0) {
                if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                    return -1;
                }
            }
            *p = '/';
        }
    }
    
    // Create the final directory
    if (access(tmp, F_OK) != 0) {
        if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
            return -1;
        }
    }
    
    return 0;
}

#endif // FILE_OPS_H