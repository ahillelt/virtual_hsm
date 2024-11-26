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
#include <ctype.h>

#include <openssl/rand.h>

#include "security_defs.h"
#include "metadata.h"
#include "types.h"
#include "token_utils.h"

// MIN MACRO
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define ERROR_INVALID_FILE_SIZE -1
#define ERROR_INVALID_CHUNK_SIZE -1

// Structure to track chunk status
typedef struct {
    char* path;
    size_t size;
    int written;
    char hash[HASH_SIZE];  
} ChunkStatus;

// Forward declarations
int decrypt_file_chunked(const char* output_dir, 
                        unsigned char* key, 
                        const SecureMetadata* metadata, const char* token);
void log_security_event(const char* event, const char* details);

// Function declarations
void print_file_info(const char* filepath);
char* handle_file_conflict(const char* output_dir, const char* original_filename);
void debug_hex_dump(const char* desc, const void* addr, size_t len);

int handle_decryption_failure(unsigned char* key, 
                            const char* token, 
                            const char* output_path);
							
size_t calculate_chunk_count(size_t file_size);			
static size_t calculate_optimal_chunk_count(size_t file_size);
size_t generate_chunk_size(size_t remaining_size);
int generate_chunk_hash(const char* token, size_t chunk_index, char* chunk_hash);

ErrorCode handle_store_file(void* args);
static ErrorCode validate_key_path(const char* path);

int secure_delete_file(const char *path);
					 
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

// Debug Print Out
void debug_hex_dump(const char* desc, const void* addr, size_t len) {
    const unsigned char* pc = (const unsigned char*)addr;
    char buff[17];
    size_t i;

    if (desc != NULL)
        printf("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %zu\n", len);
        return;
    }

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf("  %s\n", buff);
            printf("  %04zx ", i);
        }

        printf(" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }
    printf("  %s\n", buff);
}

int secure_delete_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }
    
    // Allocate a buffer for overwriting
    unsigned char *buffer = malloc(BUFFER_SIZE);
    if (!buffer) {
        fclose(fp);
        return -1;
    }
    
    // Multiple overwrite passes with different patterns
    for (int pass = 0; pass < 3; pass++) {
        // Reset file pointer
        rewind(fp);
        
        // Fill buffer with pattern
        memset(buffer, (pass == 0) ? 0xFF : (pass == 1) ? 0x00 : 0xAA, BUFFER_SIZE);
        
        // Write pattern to file
        size_t remaining = st.st_size;
        while (remaining > 0) {
            size_t to_write = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
            if (fwrite(buffer, 1, to_write, fp) != to_write) {
                free(buffer);
                fclose(fp);
                return -1;
            }
            remaining -= to_write;
        }
        
        // Force write to disk
        fflush(fp);
        fsync(fileno(fp));
    }
    
    free(buffer);
    fclose(fp);
    
    // Finally delete the file
    return unlink(path);
}

// Handle file conflicts
char* handle_file_conflict(const char* output_dir, const char* original_filename) {
    static char final_path[512];
    const char* base_filename = strrchr(original_filename, '/');
    base_filename = (base_filename == NULL) ? original_filename : base_filename + 1;

    // Ensure output directory exists before proceeding
    if (ensure_directory_exists(output_dir) != 0) {
        printf(!DEBUG ? "" :"Failed to create output directory structure\n");
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

static ErrorCode validate_key_path(const char* path) {
    if (!path || strlen(path) > MAX_PATH_LEN) {
        return ERROR_INVALID_INPUT;
    }

    char resolved_path[PATH_MAX];
    char resolved_storage_path[PATH_MAX];

    // Always resolve the storage path
    if (realpath(STORAGE_PATH, resolved_storage_path) == NULL) {
        log_security_event("ERROR", "Failed to resolve STORAGE_PATH");
        return ERROR_SYSTEM;
    }

    // For new paths, validate parent directory
    if (realpath(path, resolved_path) == NULL) {
        if (errno == ENOENT) {
            char* parent_copy = strdup(path);
            if (!parent_copy) return ERROR_SYSTEM;
            
            char* parent_dir = dirname(parent_copy);
            char resolved_parent[PATH_MAX];
            
            ErrorCode result = ERROR_SYSTEM;
            if (realpath(parent_dir, resolved_parent) != NULL) {
                // Verify parent directory is not within secure storage
                if (strncmp(resolved_parent, resolved_storage_path, strlen(resolved_storage_path)) != 0) {
                    result = SUCCESS;
                }
            }
            
            free(parent_copy);
            return result;
        }
        return ERROR_INVALID_INPUT;
    }

    // For existing paths, verify they're not in secure storage unless explicitly allowed
    if (strncmp(resolved_path, resolved_storage_path, strlen(resolved_storage_path)) == 0) {
        // Only allow access to specific files in secure storage
        if (strcmp(path, KEY_FILE_PATH) != 0) {
            log_security_event("SECURITY_VIOLATION", "Unauthorized secure storage access");
            return ERROR_INVALID_INPUT;
        }
    }

    return SUCCESS;
}

int handle_decryption_failure(unsigned char* key, const char* token, const char* output_path) {
	

    printf(!DEBUG ? "" :"\n=== Decryption Failure Debug Info ===\n");
    printf(!DEBUG ? "" :"Token: %s\n", token);
    printf(!DEBUG ? "" :"Output path: %s\n", output_path);
    printf(!DEBUG ? "" :"Key content (first 16 bytes): ");
    debug_hex_dump("Master Key", key, 16);  // Only show first 16 bytes for security
    
    // Add metadata verification
    SecureMetadata metadata;
    printf(SILENT ? "" :"\nAttempting to load metadata...\n");
    int metadata_result = load_metadata(token, &metadata);
    if (metadata_result != 0) {
        printf(!DEBUG ? "" :"Failed to load metadata: error code %d\n", metadata_result);
    } else {
        printf(!DEBUG ? "" :"Metadata loaded successfully\n");
        printf(!DEBUG ? "" :"Original filename: %s\n", metadata.original_filename);
        printf(!DEBUG ? "" :"File size: %zu\n", metadata.file_size);
        printf(!DEBUG ? "" :"Number of chunks: %zu\n", metadata.chunk_count);
        printf(!DEBUG ? "" :"First chunk hash: %s\n", metadata.chunk_hashes[0]);
    }
    
    // Check if chunk files exist and are accessible
    printf(!DEBUG ? "" :"\nVerifying chunk files:\n");
    for (size_t i = 0; i < metadata.chunk_count; i++) {
        char chunk_path[PATH_MAX];
        snprintf(chunk_path, sizeof(chunk_path), "%s%s.chunk", STORAGE_PATH, metadata.chunk_hashes[i]);
        
        struct stat st;
        if (stat(chunk_path, &st) == 0) {
            printf(!DEBUG ? "" :"Chunk %zu: Found, size: %ld bytes\n", i, st.st_size);
            
            // Read first few bytes of chunk to verify it's not empty/corrupted
            FILE* chunk_file = fopen(chunk_path, "rb");
            if (chunk_file) {
                unsigned char buffer[16];
                size_t read = fread(buffer, 1, sizeof(buffer), chunk_file);
                fclose(chunk_file);
                
                printf(!DEBUG ? "" :"First %zu bytes of chunk %zu:\n", read, i);
                debug_hex_dump(NULL, buffer, read);
            }
        } else {
            printf(!DEBUG ? "" :"Chunk %zu: NOT FOUND at path: %s\n", i, chunk_path);
        }
    }

    printf(SILENT ? "" :"\nDecryption failed.\n");
	printf(SILENT ? "" :"This could be due to:\n");
    printf(SILENT ? "" :"1) Incorrect master key\n");
    printf(SILENT ? "" :"2) Corrupted data\n");
    printf(SILENT ? "" :"3) Invalid token\n\n");
    
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

        printf(SILENT ? "" :"Attempting to read key file: %s\n", key_path);
        FILE* fp = fopen(key_path, "rb");
        if (!fp) {
            printf(!DEBUG ? "" :"Error opening key file: %s\n", strerror(errno));
            return -1;
        }
        
        printf(SILENT ? "" :"Reading key file...\n");
        size_t read = fread(key, 1, KEY_SIZE, fp);
        fclose(fp);

        if (read != KEY_SIZE) {
            printf(!DEBUG ? "" :"Error: Invalid key file (read %zu bytes, expected %d)\n", read, KEY_SIZE);
            return -1;
        }

        printf(!DEBUG ? "" :"Successfully read new key file. Key preview:\n");
        debug_hex_dump("New Key", key, 16);

        // Try decryption again with new key
        SecureMetadata metadata;
        printf(!DEBUG ? "" :"\nRetrying decryption with new key...\n");
        if (load_metadata(token, &metadata) == 0) {
            return decrypt_file_chunked(output_path, key, &metadata, token);
        }
    }

    return -1;
}

// Helper function to calculate total number of chunks needed for a file
size_t calculate_chunk_count(size_t file_size) {
    if (file_size == 0) {
        return 0;
    }
    
    // Start with a conservative estimate
    size_t chunk_count = 0;
    size_t remaining = file_size;
    
    while (remaining > 0) {
        size_t chunk_size = generate_chunk_size(remaining);
        remaining -= chunk_size;
        chunk_count++;
        
        // Safety check to prevent infinite loops
        if (chunk_count > MAX_CHUNKS) {
            return MAX_CHUNKS;
        }
    }
    
    return chunk_count;
}

size_t generate_chunk_size(size_t remaining_size) {
    // If remaining size is less than or equal to MIN_CHUNK_SIZE, use all remaining
    if (remaining_size <= MIN_CHUNK_SIZE) {
        return remaining_size;
    }
    
    // Calculate the maximum possible chunk size for this iteration
	size_t max_possible = MIN(remaining_size, MAX_CHUNK_SIZE);
	if (remaining_size > MAX_CHUNK_SIZE * 2) {
		// For larger files, limit individual chunk sizes more strictly
		max_possible = MAX_CHUNK_SIZE * 0.8;
	}
	
    // Calculate the range for randomization
    size_t range_start = MIN_CHUNK_SIZE;
    size_t range_end = max_possible;
    
    // Generate a random value within our range
    unsigned char rand_bytes[sizeof(size_t)];
    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) {
        // Fallback to deterministic size if randomization fails
        return (range_start + range_end) / 2;
    }
    
    // Convert random bytes to size_t
    size_t rand_val;
    memcpy(&rand_val, rand_bytes, sizeof(rand_val));
    
    // Calculate the random chunk size within our range
    size_t range_size = range_end - range_start;
    size_t random_offset = rand_val % (range_size + 1);
    size_t chunk_size = range_start + random_offset;
    
    // Ensure we don't overflow
    if (chunk_size > remaining_size) {
        chunk_size = remaining_size;
    }
    
    // Final safety check
    if (chunk_size < MIN_CHUNK_SIZE) {
        chunk_size = MIN_CHUNK_SIZE;
    } else if (chunk_size > MAX_CHUNK_SIZE) {
        chunk_size = MAX_CHUNK_SIZE;
    }
    
    return chunk_size;
}


// verify chunk integrity
int verify_chunk(const char* chunk_path, size_t expected_size) {
    struct stat st;
    if (stat(chunk_path, &st) != 0) {
        printf(!DEBUG ? "" :"Error: Cannot access chunk file %s: %s\n", 
               chunk_path, strerror(errno));
        return -1;
    }
    
    // Convert st_size to unsigned for comparison
    if (st.st_size < 0 || (size_t)st.st_size != expected_size) {
        printf(!DEBUG ? "" :"Error: Chunk size mismatch for %s (expected: %zu, actual: %zu)\n",
               chunk_path, expected_size, (size_t)st.st_size);
        return -1;
    }
    
    return 0;
}

static size_t calculate_optimal_chunk_count(size_t file_size) {
    // For very small files that can fit in MIN_CHUNK_SIZE, use one chunk
    if (file_size <= MIN_CHUNK_SIZE) {
        return 1;
    }
    
    // For medium files (up to 50MB), aim for chunks around 75% of MAX_CHUNK_SIZE
    if (file_size <= (MAX_CHUNK_SIZE * 10)) {  // 50MB threshold
        size_t target_size = MAX_CHUNK_SIZE * 3/4;  // ~3.75MB target
        return (file_size + target_size - 1) / target_size;
    }
    
    // For large files, aim for chunks around 50% of MAX_CHUNK_SIZE
    size_t target_size = MAX_CHUNK_SIZE / 2;  // 2.5MB target
    return (file_size + target_size - 1) / target_size;
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

    // Get file size with extensive error checking
    struct stat st;
    if (stat(store_args->filepath, &st) != 0) {
        return ERROR_SYSTEM;
    }
    
    // Validate file size
    if (st.st_size <= 0) {
        return ERROR_INVALID_FILE_SIZE;
    }
    
    printf(!DEBUG ? "" :"DEBUG: Initial file size read: %zu\n", st.st_size);
    *store_args->file_size = st.st_size;

    // Initialize chunk paths pointer to NULL
    *store_args->chunk_paths = NULL;
    *store_args->chunk_count = 0;

    // Pre-calculate minimum required chunks based on file size
    size_t min_chunks = (st.st_size + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
    if (min_chunks == 0) {
        min_chunks = 1;  // Always have at least one chunk
    }

    // Calculate initial chunk allocation size (with some room for growth)
    size_t initial_chunks = min_chunks + 4;  // Add some buffer
    if (initial_chunks > MAX_CHUNKS) {
        initial_chunks = MAX_CHUNKS;
    }

    // Allocate initial array for chunk paths
    *store_args->chunk_paths = malloc(initial_chunks * sizeof(char*));
    if (!*store_args->chunk_paths) {
        return ERROR_SYSTEM;
    }

    // Initialize all pointers to NULL
    for (size_t i = 0; i < initial_chunks; i++) {
        (*store_args->chunk_paths)[i] = NULL;
    }

    *store_args->chunk_count = initial_chunks;  // Store initial allocation size

    // Let encrypt_file_chunked handle the actual chunk creation
    // It will reallocate the array if needed
    
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