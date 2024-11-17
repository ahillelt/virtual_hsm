/**
 * token.c - Secure Token Management System
 * 
 * A secure implementation for storing and retrieving sensitive files using tokens.
 * Includes comprehensive security measures, proper error handling, and secure cleanup.
 * 
 * Security Features:
 * - Secure memory management with page alignment
 * - Protected key operations
 * - Input validation and sanitization
 * - Secure random number generation
 * - Proper error handling and cleanup
 * - Rate limiting and timeout controls
 */

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
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "security_defs.h"
#include "metadata.h"
#include "key_management.h"
#include "crypto_ops.h"
#include "token_utils.h"
#include "file_ops.h"
#include "types.h"

// Configuration constants
#define MAX_FAILED_ATTEMPTS 3
#define OPERATION_TIMEOUT_SECONDS 300
#define MIN_TOKEN_LENGTH 32
#define MAX_PATH_LENGTH 4096
#define SECURE_PERMISSIONS 0600
#define LOG_BUFFER_SIZE 1024

// Rate limiting
#define RATE_LIMIT_INTERVAL 60  // seconds
#define MAX_OPERATIONS_PER_INTERVAL 10


// Secure operation context
typedef struct {
    time_t start_time;
    unsigned int operation_count;
    time_t last_operation;
} SecurityContext;

// Global variables - kept to minimum and protected
char* g_custom_key_path = NULL;
static SecurityContext* g_security_context = NULL;
static volatile sig_atomic_t g_shutdown_flag = 0;

// Function declarations
static void initialize_security_context(void);
static void cleanup_security_context(void);

//error code declarations
static ErrorCode validate_input_parameters(int argc, char* argv[]);
static ErrorCode validate_path(const char* path);
static ErrorCode validate_storage_path(const char* path);
static ErrorCode validate_output_path(const char* path);

static ErrorCode check_rate_limit(void);

static ErrorCode handle_retrieve_file(void* args);
static ErrorCode perform_operation_with_timeout(operation_func func, void* args);

ErrorCode handle_retrieve_file(void* args);
ErrorCode handle_store_file(void* args);

void secure_wipe(void* ptr, size_t len);
static void* secure_malloc(size_t size);
static void handle_interrupt(int signal);
static void log_security_event(const char* event, const char* details);

static void cleanup_security_context(void) {
    if (g_security_context) {
        secure_wipe(g_security_context, sizeof(SecurityContext));
        free(g_security_context);
        g_security_context = NULL;
    }
}


ErrorCode handle_retrieve_file(void* args) {
    if (!args) return ERROR_INVALID_INPUT;
    
    RetrieveFileArgs* retrieve_args = (RetrieveFileArgs*)args;
    
    if (!retrieve_args->token || !retrieve_args->output_path || 
        !retrieve_args->key || !retrieve_args->metadata) {
        return ERROR_INVALID_INPUT;
    }
    
    // Load metadata
    if (load_metadata(retrieve_args->token, retrieve_args->metadata) != 0) {
        return ERROR_SYSTEM;
    }
    
    // Decrypt file
    if (decrypt_file_chunked(retrieve_args->output_path, 
                           retrieve_args->key, 
                           retrieve_args->metadata) != 0) {
        return ERROR_CRYPTO;
    }
    
    return SUCCESS;
}

/**
 * @brief Initializes security context with proper memory protection
 */
static void initialize_security_context(void) {
    g_security_context = secure_malloc(sizeof(SecurityContext));
    if (!g_security_context) {
        fprintf(stderr, "Failed to initialize security context\n");
        exit(ERROR_SYSTEM);
    }

    g_security_context->start_time = time(NULL);
    g_security_context->operation_count = 0;
    g_security_context->last_operation = 0;

    // Lock memory to prevent swapping
    if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
        log_security_event("WARNING", "Failed to lock memory pages");
    }
}

/**
 * @brief Securely allocates memory with page alignment
 */
static void* secure_malloc(size_t size) {
    void* ptr;
    int ret = posix_memalign(&ptr, 4096, size);
    if (ret != 0) return NULL;
    
    memset(ptr, 0, size);
    return ptr;
}

/**
 * @brief Validates all input parameters for security
 */
static ErrorCode validate_input_parameters(int argc, char* argv[]) {
    if (argc < 2) return ERROR_INVALID_INPUT;
    
    for (int i = 1; i < argc; i++) {
        if (!argv[i] || strlen(argv[i]) > MAX_PATH_LENGTH) {
            return ERROR_INVALID_INPUT;
        }
        
        // Check for directory traversal attempts
        if (strstr(argv[i], "..")) {
            log_security_event("SECURITY_VIOLATION", "Directory traversal attempt detected");
            return ERROR_INVALID_INPUT;
        }
    }
    
    return SUCCESS;
}

/**
 * @brief Validates file path for security issues
 */
static ErrorCode validate_path(const char* path) {
    if (!path || strlen(path) > MAX_PATH_LENGTH) {
        return ERROR_INVALID_INPUT;
    }

    struct stat st;
    char resolved_path[PATH_MAX];
    char resolved_storage_path[PATH_MAX];

    // Resolve the storage path to an absolute path
    if (realpath(STORAGE_PATH, resolved_storage_path) == NULL) {
        log_security_event("ERROR", "Failed to resolve STORAGE_PATH");
        return ERROR_SYSTEM;
    }

    // Allow paths that don’t exist but check parent directories
    if (realpath(path, resolved_path) == NULL) {
        if (errno == ENOENT) {
            // Check if parent directory exists or can be created
            char* parent_copy = strdup(path);
            if (!parent_copy) return ERROR_SYSTEM;

            char* parent_dir = dirname(parent_copy);
            int result = ensure_directory_exists(parent_dir);
            free(parent_copy);

            if (result != 0) {
                log_security_event("SECURITY_VIOLATION", "Parent directory validation failed");
                return ERROR_SYSTEM;
            }
            return SUCCESS;
        } else {
            return ERROR_INVALID_INPUT;  // Handle other errors
        }
    }

    // Ensure resolved path matches the expected secure storage directory
    if (strstr(path, "secure_storage/")) {
        fprintf(stderr, "DEBUG: Input path contains 'secure_storage/'\n");
        fprintf(stderr, "DEBUG: Input path: '%s'\n", path);
        fprintf(stderr, "DEBUG: Resolved path: '%s'\n", resolved_path);
        fprintf(stderr, "DEBUG: Expected resolved storage path: '%s'\n", resolved_storage_path);

        if (strncmp(resolved_path, resolved_storage_path, strlen(resolved_storage_path)) != 0) {
            fprintf(stderr, "DEBUG: strncmp failed. Comparison result: %d\n", 
                    strncmp(resolved_path, resolved_storage_path, strlen(resolved_storage_path)));
            log_security_event("SECURITY_VIOLATION", "Path validation failed");
            return ERROR_INVALID_INPUT;
        }
    } else {
        fprintf(stderr, "DEBUG: Input path does not contain 'secure_storage/'\n");
        fprintf(stderr, "DEBUG: Input path: '%s'\n", path);
    }

    return SUCCESS;
}

static ErrorCode validate_storage_path(const char* path) {
    if (!path || strlen(path) > MAX_PATH_LENGTH) {
        return ERROR_INVALID_INPUT;
    }

    char resolved_path[PATH_MAX];
    char resolved_storage_path[PATH_MAX];

    // Resolve the storage path to an absolute path
    if (realpath(STORAGE_PATH, resolved_storage_path) == NULL) {
        log_security_event("ERROR", "Failed to resolve STORAGE_PATH");
        return ERROR_SYSTEM;
    }

    // Resolve the input path
    if (realpath(path, resolved_path) == NULL) {
        return ERROR_INVALID_INPUT;
    }

    // Check if path is within allowed directories
    if (strncmp(resolved_path, resolved_storage_path, strlen(resolved_storage_path)) != 0) {
        fprintf(stderr, "DEBUG: Resolved path: '%s'\n", resolved_path);
        fprintf(stderr, "DEBUG: Expected resolved storage path: '%s'\n", resolved_storage_path);
        fprintf(stderr, "DEBUG: Comparison result: %d\n", 
                strncmp(resolved_path, resolved_storage_path, strlen(resolved_storage_path)));

        log_security_event("SECURITY_VIOLATION", "Path validation failed");
        return ERROR_INVALID_INPUT;
    }

    return SUCCESS;
}

static ErrorCode validate_output_path(const char* path) {
    if (!path || strlen(path) > MAX_PATH_LENGTH) {
        return ERROR_INVALID_INPUT;
    }

    // Make a copy of the path since dirname may modify it
    char* dir_copy = strdup(path);
    if (!dir_copy) {
        return ERROR_SYSTEM;
    }

    char* dir = dirname(dir_copy);

    // Resolve the directory path to ensure it can be validated
    char resolved_dir[PATH_MAX];
    if (realpath(dir, resolved_dir) == NULL && errno != ENOENT) {
        free(dir_copy);
        log_security_event("ERROR", "Failed to resolve directory path");
        return ERROR_INVALID_INPUT;
    }

    if (ensure_directory_exists(resolved_dir) != 0) {  // Ensure directory exists or create it
        free(dir_copy);
        log_security_event("ERROR", "Failed to create or validate directory");
        return ERROR_SYSTEM;
    }

    free(dir_copy);
    return SUCCESS;
}


/**
 * @brief Implements rate limiting for operations
 */
static ErrorCode check_rate_limit(void) {
    time_t current_time = time(NULL);
    
    if (current_time - g_security_context->last_operation < RATE_LIMIT_INTERVAL) {
        if (g_security_context->operation_count >= MAX_OPERATIONS_PER_INTERVAL) {
            log_security_event("RATE_LIMIT", "Operation rate limit exceeded");
            return ERROR_RATE_LIMIT;
        }
    } else {
        g_security_context->operation_count = 0;
    }
    
    g_security_context->operation_count++;
    g_security_context->last_operation = current_time;
    return SUCCESS;
}

/**
 * @brief Securely wipes memory containing sensitive data
 */
void secure_wipe(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
    
    volatile unsigned char* p = ptr;
    while (len--) {
        *p++ = 0;
    }
    __sync_synchronize();
}

/**
 * @brief Handles program interruption
 */
static void handle_interrupt(int signal __attribute__((unused))) {
    g_shutdown_flag = 1;
    log_security_event("SHUTDOWN", "Program interrupted");
}

/**
 * @brief Logs security events with timestamps
 */
static void log_security_event(const char* event, const char* details) {
    time_t now = time(NULL);
    char timestamp[26];
    ctime_r(&now, timestamp);
    timestamp[24] = '\0';  // Remove newline

    char log_buffer[LOG_BUFFER_SIZE];
    snprintf(log_buffer, sizeof(log_buffer), "[%s] %s: %s", 
             timestamp, event, details);

    // In production, this should write to a secure log facility
    fprintf(stderr, "%s\n", log_buffer);
}

/**
 * @brief Performs operation with timeout control
 */
static ErrorCode perform_operation_with_timeout(operation_func func, void* args) {
    time_t start_time = time(NULL);
    
    while (!g_shutdown_flag) {
        if (time(NULL) - start_time > OPERATION_TIMEOUT_SECONDS) {
            log_security_event("TIMEOUT", "Operation timed out");
            return ERROR_TIMEOUT;
        }
        
        ErrorCode result = func(args);
        if (result != ERROR_SYSTEM) {
            return result;
        }
    }
    
    return ERROR_TIMEOUT;
}

/**
 * @brief Cleanup handler for secure shutdown
 */
static void cleanup_secure(void) {
    if (g_security_context) {
        secure_wipe(g_security_context, sizeof(SecurityContext));
        free(g_security_context);
        g_security_context = NULL;
    }

    if (g_custom_key_path) {
        secure_wipe(g_custom_key_path, strlen(g_custom_key_path));
        free(g_custom_key_path);
        g_custom_key_path = NULL;
    }

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    munlockall();
}

int main(int argc, char* argv[]) {
	
	// before anything
	if (argc < 2) {
    printf(HELP_TEXT, argv[0], argv[0], argv[0], argv[0]);
    return ERROR_INVALID_INPUT;
	}
	
    ErrorCode ret = SUCCESS;
    SecurityError error = {0};
    char** chunk_paths = NULL;
    char* token = NULL;
    size_t chunk_count = 0;
	
	

    // Set up signal handlers
    signal(SIGINT, handle_interrupt);
    signal(SIGTERM, handle_interrupt);
    
    // Initialize security context
    initialize_security_context();
    
    // Register cleanup handler
    if (atexit(cleanup_secure) != 0) {
        log_security_event("FATAL", "Failed to register cleanup handler");
        return ERROR_SYSTEM;
    }

    // Validate input parameters
    if ((ret = validate_input_parameters(argc, argv)) != SUCCESS) {
        fprintf(stderr, "Invalid input parameters\n");
        return ret;
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        log_security_event("FATAL", "Failed to initialize libsodium");
        return ERROR_CRYPTO;
    }

    // Create storage directory with secure permissions
    struct stat st = {0};
    if (stat(STORAGE_PATH, &st) == -1) {
        if (mkdir(STORAGE_PATH, SECURE_PERMISSIONS) == -1) {
            log_security_event("ERROR", "Failed to create storage directory");
            return ERROR_SYSTEM;
        }
    }

    // Check rate limiting
    if ((ret = check_rate_limit()) != SUCCESS) {
        return ret;
    }

    // Handle commands
    if (strcmp(argv[1], "generate-key") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: Path required for key generation\n");
            return ERROR_INVALID_INPUT;
        }
        return generate_key_file(argv[2]);
    }

    // Parse and validate key path
    char* key_path = NULL;
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--key") == 0) {
            key_path = argv[i + 1];
            if ((ret = validate_path(key_path)) != SUCCESS) {  // Changed from validate_storage_path
                return ret;
            }
            break;
        }
    }

    // Initialize encryption key
    unsigned char key[KEY_SIZE];
    if (handle_key_initialization(key, key_path) != SUCCESS) {
        log_security_event("ERROR", "Key initialization failed");
        return ERROR_CRYPTO;
    }

    // Handle store command
    if (strcmp(argv[1], "store") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: File path required for storage\n");
            return ERROR_INVALID_INPUT;
        }

        // Generate secure token
        token = generate_token();
        if (!token || strlen(token) < MIN_TOKEN_LENGTH) {
            log_security_event("ERROR", "Token generation failed");
            ret = ERROR_CRYPTO;
            goto cleanup;
        }

        size_t original_file_size = 0;
        SecureMetadata metadata = {0};
        strncpy(metadata.token, token, TOKEN_SIZE);

        // Store file with timeout control
        StoreFileArgs args = {
            .filepath = argv[2],
            .chunk_paths = &chunk_paths,
            .chunk_count = &chunk_count,
            .token = token,
            .file_size = &original_file_size,
            .metadata = &metadata
        };

        if ((ret = perform_operation_with_timeout(handle_store_file, &args)) != SUCCESS) {
            goto cleanup;
        }

        metadata.data_size = original_file_size;
        strncpy(metadata.original_filename, basename(argv[2]), 
                sizeof(metadata.original_filename) - 1);

        printf("Encrypting file in chunks...\n");
        if (encrypt_file_secure(argv[2], chunk_paths, chunk_count, key, 
                              &metadata, &error) == SUCCESS) {
            printf("Saving metadata...\n");
            if (save_metadata(&metadata) == SUCCESS) {
                printf("\nFile encrypted successfully in %zu chunks.\n", chunk_count);
                printf("Token: %s\n", token);
                printf("Keep this token safe - you'll need it to retrieve your file.\n");
                
                log_security_event("SUCCESS", "File stored successfully");
            } else {
                log_security_event("ERROR", "Failed to save metadata");
                ret = ERROR_SYSTEM;
            }
        } else {
            log_security_event("ERROR", error.message);
            ret = ERROR_CRYPTO;
        }
    }
    // Handle retrieve command
	else if (strcmp(argv[1], "retrieve") == 0) {
		if (argc < 4) {
			fprintf(stderr, "Error: Token and output path required for retrieval\n");
			ret = ERROR_INVALID_INPUT;
			goto cleanup;
		}

		char* token = argv[2];
		char* output_path = argv[3];

		if ((ret = validate_output_path(output_path)) != SUCCESS) {
			fprintf(stderr, "Error: Could not create output directory\n");
			goto cleanup;
		}

		printf("\nStarting file retrieval process...\n");

		// Load metadata using the provided token
		SecureMetadata metadata = {0};
		if ((ret = load_metadata(token, &metadata)) != SUCCESS) {
			fprintf(stderr, "Error: Could not load metadata. Token might be invalid.\n");
			goto cleanup;
		}

		// Attempt to decrypt the file using the loaded metadata and key
		printf("Decrypting file in chunks...\n");
		if ((ret = decrypt_file_chunked(output_path, key, &metadata)) == SUCCESS) {
			printf("\nFile retrieved successfully.\n");
			log_security_event("SUCCESS", "File retrieved successfully");
		} else {
			fprintf(stderr, "Error: Decryption failed. Attempting recovery...\n");
			if ((ret = handle_decryption_failure(key, token, output_path)) == SUCCESS) {
				printf("\nFile retrieved successfully using fallback key.\n");
				log_security_event("SUCCESS", "File retrieved successfully with fallback key");
			} else {
				fprintf(stderr, "\nDecryption failed with all attempted keys.\n");
				log_security_event("ERROR", "File retrieval failed");
				goto cleanup;
			}
		}
	}



cleanup:
    // Secure cleanup of sensitive data
    if (chunk_paths) {
        for (size_t i = 0; i < chunk_count; i++) {
            if (chunk_paths[i]) {
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

    secure_wipe(key, KEY_SIZE);
    
    return ret;
}