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
size_t generate_chunk_size(void);
int handle_store_file(const char* input_path, 
                     char*** chunk_paths,
                     size_t* chunk_count,
                     const char* token, 
                     size_t* file_size, 
                     SecureMetadata* metadata);
					 
int sanitize_path(const char* input, char* output, size_t outlen);
int ensure_directory_exists(const char* path);

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

// generate random chunk size
size_t generate_chunk_size(void) {
    size_t range = MAX_CHUNK_SIZE - MIN_CHUNK_SIZE;
    size_t random_offset = (size_t)(((double)rand() / RAND_MAX) * range);
    return MIN_CHUNK_SIZE + random_offset;
}

int handle_store_file(const char* input_path, char*** chunk_paths, size_t* chunk_count,
                      const char* token, size_t* file_size, SecureMetadata* metadata) {
    struct stat st;
    if (stat(input_path, &st) == -1) {
        printf("Error: Input file does not exist\n");
        return -1;
    }

    *file_size = st.st_size;
    size_t remaining_size = *file_size;
    *chunk_count = 0;
    
    // Calculate number of chunks needed
    while (remaining_size > 0) {
        size_t chunk_size = generate_chunk_size();
        if (chunk_size > remaining_size) {
            chunk_size = remaining_size;
        }
        (*chunk_count)++;
        remaining_size -= chunk_size;
        
        if (*chunk_count >= MAX_CHUNKS) {
            printf("Error: File too large, maximum chunks exceeded\n");
            return -1;
        }
    }

    // Allocate memory for chunk paths
    *chunk_paths = malloc(*chunk_count * sizeof(char*));
    if (!*chunk_paths) {
        printf("Error: Memory allocation failed\n");
        return -1;
    }

    mkdir(STORAGE_PATH, 0700);
    char base_hash[HASH_SIZE];
    hash_token(token, base_hash);

    // Generate chunk paths and store hashes
    for (size_t i = 0; i < *chunk_count; i++) {
        (*chunk_paths)[i] = malloc(512);
        if (!(*chunk_paths)[i]) {
            // Cleanup previously allocated memory
            for (size_t j = 0; j < i; j++) {
                free((*chunk_paths)[j]);
            }
            free(*chunk_paths);
            printf("Error: Memory allocation failed for chunk path\n");
            return -1;
        }

        // Generate unique hash for each chunk
        char chunk_input[HASH_SIZE + 20];
        snprintf(chunk_input, sizeof(chunk_input), "%s_%zu", base_hash, i);
        
        // Store just the hash in metadata
        char chunk_hash[HASH_SIZE];
        hash_token(chunk_input, chunk_hash);
        strncpy(metadata->chunk_hashes[i], chunk_hash, HASH_SIZE - 1);
        metadata->chunk_hashes[i][HASH_SIZE - 1] = '\0';

        // Construct the full path for chunk_paths
        snprintf((*chunk_paths)[i], 512, "%s%s.chunk", STORAGE_PATH, chunk_hash);
        
        printf("Chunk %zu path: %s\n", i, (*chunk_paths)[i]);
    }

    printf("File will be split into %zu chunks\n", *chunk_count);
    return 0;
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
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            // Skip if directory already exists
            if (access(tmp, F_OK) != 0) {
                if (mkdir(tmp, 0755) != 0) {
                    printf("Error creating directory %s: %s\n", tmp, strerror(errno));
                    return -1;
                }
            }
            *p = '/';
        }
    }
    // Create the final directory
    if (access(tmp, F_OK) != 0) {
        if (mkdir(tmp, 0755) != 0) {
            printf("Error creating directory %s: %s\n", tmp, strerror(errno));
            return -1;
        }
    }
    return 0;
}

#endif // FILE_OPS_H