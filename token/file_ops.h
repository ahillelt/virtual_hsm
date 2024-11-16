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

int handle_store_file(const char* input_path, char*** chunk_paths, size_t* chunk_count,
                      const char* token, size_t* file_size, SecureMetadata* metadata);
					 
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

int handle_store_file(const char* input_path, char*** chunk_paths, size_t* chunk_count,
                     const char* token, size_t* file_size, SecureMetadata* metadata) {
    struct stat st;
    if (stat(input_path, &st) == -1) {
        printf("Error: Input file does not exist\n");
        return -1;
    }

    *file_size = st.st_size;
    
    // Calculate initial chunk count - round up division
    size_t max_possible_chunks = (*file_size + MIN_CHUNK_SIZE - 1) / MIN_CHUNK_SIZE;
    if (max_possible_chunks > MAX_CHUNKS) {
        printf("Error: File too large, would exceed maximum chunks (%zu > %d)\n", 
               max_possible_chunks, MAX_CHUNKS);
        return -1;
    }
    
    // Allocate chunk tracking with maximum possible size
    ChunkStatus* chunks = calloc(max_possible_chunks, sizeof(ChunkStatus));
    if (!chunks) {
        printf("Error: Memory allocation failed for chunk tracking\n");
        return -1;
    }
    
    // Initialize all chunk pointers to NULL for safer cleanup
    for (size_t i = 0; i < max_possible_chunks; i++) {
        chunks[i].path = NULL;
        chunks[i].written = 0;
    }

    // Calculate chunk sizes
    size_t remaining_size = *file_size;
    size_t total_allocated = 0;
    size_t current_chunk = 0;
    
    while (remaining_size > 0 && current_chunk < max_possible_chunks) {
        size_t chunk_size = generate_chunk_size(remaining_size);
        
        // Validate chunk size
        if (chunk_size == 0 || 
            (remaining_size > chunk_size && chunk_size < MIN_CHUNK_SIZE) || 
            chunk_size > MAX_CHUNK_SIZE) {
            printf("Error: Invalid chunk size calculated: %zu (min: %d, max: %d)\n",
                   chunk_size, MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
            free(chunks);
            return -1;
        }
        
        chunks[current_chunk].size = chunk_size;
        total_allocated += chunk_size;
        remaining_size -= chunk_size;
        current_chunk++;
    }
    
    *chunk_count = current_chunk;
    
    // Verify total size matches file size
    if (total_allocated != *file_size) {
        printf("Error: Chunk size calculation mismatch (total: %zu, file: %zu)\n",
               total_allocated, *file_size);
        free(chunks);
        return -1;
    }

    // Update metadata with chunk count
    metadata->chunk_count = current_chunk;

    // Ensure storage directory exists
    if (ensure_directory_exists(STORAGE_PATH) != 0) {
        free(chunks);
        printf("Error: Failed to create storage directory\n");
        return -1;
    }

    // Generate chunk paths and prepare metadata
    char base_hash[HASH_SIZE];
    if (!token) {
        free(chunks);
        printf("Error: Invalid token\n");
        return -1;
    }
    hash_token(token, base_hash);

    // Allocate array of chunk path pointers
	*chunk_paths = malloc((current_chunk + 1) * sizeof(char*));  // +1 for NULL terminator
	if (!*chunk_paths) {
		free(chunks);
		printf("Error: Memory allocation failed for chunk paths array\n");
		return -1;
	}

	// Initialize all pointers to NULL
	for (size_t i = 0; i <= current_chunk; i++) {  // Note: <= to include terminator
		(*chunk_paths)[i] = NULL;
	}

    // Generate paths and hashes for each chunk
    for (size_t i = 0; i < current_chunk; i++) {
        // Allocate memory for chunk path
        (*chunk_paths)[i] = malloc(PATH_MAX);
        if (!(*chunk_paths)[i]) {
            // Clean up previously allocated paths
            for (size_t j = 0; j < i; j++) {
                free((*chunk_paths)[j]);
            }
            free(*chunk_paths);
            *chunk_paths = NULL;
            free(chunks);
            printf("Error: Memory allocation failed for chunk path\n");
            return -1;
        }

        // Generate unique hash for this chunk
        char chunk_input[HASH_SIZE + 32];
        snprintf(chunk_input, sizeof(chunk_input), "%s_%zu", base_hash, i);
        hash_token(chunk_input, chunks[i].hash);
        
        // Store hash and size in metadata
        strncpy(metadata->chunk_hashes[i], chunks[i].hash, HASH_SIZE - 1);
        metadata->chunk_hashes[i][HASH_SIZE - 1] = '\0';
        metadata->chunk_sizes[i] = chunks[i].size;

        // Generate full path for chunk file
        int path_len = snprintf((*chunk_paths)[i], PATH_MAX, "%s%s.chunk", 
                              STORAGE_PATH, metadata->chunk_hashes[i]);
        if (path_len >= PATH_MAX || path_len < 0) {
            // Clean up on path too long error
            for (size_t j = 0; j <= i; j++) {
                free((*chunk_paths)[j]);
            }
            free(*chunk_paths);
            *chunk_paths = NULL;
            free(chunks);
            printf("Error: Path too long for chunk file\n");
            return -1;
        }
    }

    // Open input file
    FILE* input = fopen(input_path, "rb");
    if (!input) {
        for (size_t i = 0; i < current_chunk; i++) {
            free((*chunk_paths)[i]);
        }
        free(*chunk_paths);
        *chunk_paths = NULL;
        free(chunks);
        printf("Error: Cannot open input file\n");
        return -1;
    }

    // Allocate buffer for chunk data
    unsigned char* buffer = malloc(MAX_CHUNK_SIZE);
    if (!buffer) {
        fclose(input);
        for (size_t i = 0; i < current_chunk; i++) {
            free((*chunk_paths)[i]);
        }
        free(*chunk_paths);
        *chunk_paths = NULL;
        free(chunks);
        printf("Error: Memory allocation failed for chunk buffer\n");
        return -1;
    }

    // Write and verify each chunk
    int success = 1;
    for (size_t i = 0; i < current_chunk; i++) {
        FILE* chunk_file = fopen((*chunk_paths)[i], "wb");
        if (!chunk_file) {
            printf("Error: Cannot create chunk file %s\n", (*chunk_paths)[i]);
            success = 0;
            break;
        }

        size_t bytes_read = fread(buffer, 1, chunks[i].size, input);
        if (bytes_read != chunks[i].size) {
            printf("Error: Failed to read chunk %zu from input file\n", i);
            fclose(chunk_file);
            success = 0;
            break;
        }

        size_t bytes_written = fwrite(buffer, 1, chunks[i].size, chunk_file);
        fclose(chunk_file);

        if (bytes_written != chunks[i].size) {
            printf("Error: Failed to write chunk %zu\n", i);
            success = 0;
            break;
        }

        // Verify the chunk was written correctly
        if (verify_chunk((*chunk_paths)[i], chunks[i].size) != 0) {
            printf("Error: Chunk verification failed for %s\n", (*chunk_paths)[i]);
            success = 0;
            break;
        }

        printf("Chunk %zu written and verified: %s (size: %.2f MB)\n", 
               i, (*chunk_paths)[i], (double)chunks[i].size / (1024 * 1024));
    }

    // Clean up resources
    fclose(input);
    free(buffer);

    // Handle any errors during chunk writing
    if (!success) {
        // Remove any chunks that were written
        for (size_t i = 0; i < current_chunk; i++) {
            unlink((*chunk_paths)[i]);  // Remove the chunk file
            free((*chunk_paths)[i]);    // Free the path memory
        }
        free(*chunk_paths);  // Free the array of pointers
        *chunk_paths = NULL;
        free(chunks);
        return -1;
    }

    free(chunks);  // Free the chunks structure
    printf("All %zu chunks written and verified successfully\n", current_chunk);
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