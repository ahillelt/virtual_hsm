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

extern int g_debug_mode;
extern int g_silent_mode;

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

// Forward Declarations
void log_security_event(const char* event, const char* details);
static int verify_decryption_prerequisites(const SecureMetadata* metadata, const char* token);
static int validate_key_path(const char* path);

// Function declarations
static void initialize_security_context(void);
static void cleanup_security_context(void);

//error code declarations
static ErrorCode validate_input_parameters(int argc, char* argv[]);
static ErrorCode validate_path(const char* path);
static ErrorCode validate_storage_path(const char* path);
static ErrorCode validate_output_path(const char* path);

static ErrorCode check_rate_limit(void);
static ErrorCode verify_decryption_prerequisites(const SecureMetadata* metadata, const char* token);
static ErrorCode handle_retrieve_file(void* args);
static ErrorCode perform_operation_with_timeout(operation_func func, void* args);

ErrorCode handle_retrieve_file(void* args);
ErrorCode handle_store_file(void* args);

void secure_wipe(void* ptr, size_t len);
static void* secure_malloc(size_t size);
static void handle_interrupt(int signal);


static void cleanup_security_context(void) {
    if (g_security_context) {
        secure_wipe(g_security_context, sizeof(SecurityContext));
        free(g_security_context);
        g_security_context = NULL;
    }
}

// Help funcs
int is_debug_mode() {
    return g_debug_mode;
}

int is_silent_mode() {
    return g_silent_mode;
}

ErrorCode handle_retrieve_file(void* args) {
    ErrorCode ret = SUCCESS;
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
    
    // Verify prerequisites and decrypt file
    if ((ret = verify_decryption_prerequisites(retrieve_args->metadata, 
                                             retrieve_args->token)) != SUCCESS) {
        log_security_event("ERROR", "Invalid or corrupted data");
        return ret;
    }

    if ((ret = decrypt_file_chunked(retrieve_args->output_path, 
                                  retrieve_args->key, 
                                  retrieve_args->metadata,retrieve_args->token)) != SUCCESS) {
        log_security_event("ERROR", "Decryption failed");
        return ret;
    }
    
    return SUCCESS;
}

/**
 * @brief Initializes security context with proper memory protection
 */
static void initialize_security_context(void) {
    g_security_context = secure_malloc(sizeof(SecurityContext));
    if (!g_security_context) {
        fprintf(stderr,!DEBUG ? "" : "Failed to initialize security context\n");
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
        if (!argv[i] || strlen(argv[i]) > MAX_PATH_LEN) {
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
    if (!path || strlen(path) > MAX_PATH_LEN) {
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
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Input path contains 'secure_storage/'\n");
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Input path: '%s'\n", path);
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Resolved path: '%s'\n", resolved_path);
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Expected resolved storage path: '%s'\n", resolved_storage_path);

        if (strncmp(resolved_path, resolved_storage_path, strlen(resolved_storage_path)) != 0) {
            fprintf(stderr,!DEBUG ? "" : "DEBUG: strncmp failed. Comparison result: %d\n", 
                    strncmp(resolved_path, resolved_storage_path, strlen(resolved_storage_path)));
            log_security_event("SECURITY_VIOLATION", "Path validation failed");
            return ERROR_INVALID_INPUT;
        }
    } else {
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Input path does not contain 'secure_storage/'\n");
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Input path: '%s'\n", path);
    }

    return SUCCESS;
}

static ErrorCode validate_storage_path(const char* path) {
    if (!path || strlen(path) > MAX_PATH_LEN) {
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
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Resolved path: '%s'\n", resolved_path);
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Expected resolved storage path: '%s'\n", resolved_storage_path);
        fprintf(stderr,!DEBUG ? "" : "DEBUG: Comparison result: %d\n", 
                strncmp(resolved_path, resolved_storage_path, strlen(resolved_storage_path)));

        log_security_event("SECURITY_VIOLATION", "Path validation failed");
        return ERROR_INVALID_INPUT;
    }

    return SUCCESS;
}

static ErrorCode validate_output_path(const char* path) {
    if (!path || strlen(path) > MAX_PATH_LEN) {
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
void secure_wipe(void *ptr, size_t len) {
    volatile unsigned char *volatile p = (volatile unsigned char *volatile)ptr;
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
void log_security_event(const char* event, const char* details) {
	
	if(DEBUG){
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

// Argument parsing structure
typedef struct {
    char* command;
    char* filepath;
    char* token;
    char* output_path;
    char* key_path;
    int is_debug;
    int is_silent;
} ParsedArgs;



// Function to parse arguments flexibly
ErrorCode parse_arguments(int argc, char* argv[], ParsedArgs* parsed_args) {
    // Reset global flags first
    g_debug_mode = 0;
    g_silent_mode = 0;

    // Initialize all fields to NULL or 0
    memset(parsed_args, 0, sizeof(ParsedArgs));
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            parsed_args->is_debug = 1;
            g_debug_mode = 1;  // Set global debug flag
            continue;
        }
        
        if (strcmp(argv[i], "--silent") == 0) {
            parsed_args->is_silent = 1;
            g_silent_mode = 1;  // Set global silent flag
            continue;
        }
        
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            parsed_args->key_path = argv[++i];
            continue;
        }
        
        // Check for known commands
        if (strcmp(argv[i], "store") == 0 || 
            strcmp(argv[i], "retrieve") == 0 || 
            strcmp(argv[i], "generate-key") == 0) {
            parsed_args->command = argv[i];
            continue;
        }
        
        // If no command set yet, assume this is the first argument for the command
        if (!parsed_args->filepath && !parsed_args->token) {
            if (parsed_args->command) {
                if (strcmp(parsed_args->command, "store") == 0) {
                    parsed_args->filepath = argv[i];
                } else if (strcmp(parsed_args->command, "retrieve") == 0) {
                    parsed_args->token = argv[i];
                } else if (strcmp(parsed_args->command, "generate-key") == 0) {
                    parsed_args->filepath = argv[i];
                }
            }
            continue;
        }
        
        // If token is set, next argument is output path for retrieve
        if (parsed_args->token) {
            parsed_args->output_path = argv[i];
        }
    }
    
    // Validate parsed arguments based on command
    if (!parsed_args->command) {
        fprintf(stderr, "Error: No command specified.\n");
        printf(HELP_TEXT, argv[0]);
        return ERROR_INVALID_INPUT;
    }
    
    if (strcmp(parsed_args->command, "store") == 0 && !parsed_args->filepath) {
        fprintf(stderr, "Error: Filepath required for store command.\n");
        return ERROR_INVALID_INPUT;
    }
    
    if (strcmp(parsed_args->command, "retrieve") == 0 && 
        (!parsed_args->token || !parsed_args->output_path)) {
        fprintf(stderr, "Error: Token and output path required for retrieve command.\n");
        return ERROR_INVALID_INPUT;
    }
    
    if (strcmp(parsed_args->command, "generate-key") == 0 && !parsed_args->filepath) {
        fprintf(stderr, "Error: Output path required for generate-key command.\n");
        return ERROR_INVALID_INPUT;
    }
    
    return SUCCESS;
}

//Flexible Arg Parsing
int main(int argc, char* argv[]) {
    // Before anything
    if (argc < 2) {
        printf(HELP_TEXT, argv[0]);
        return ERROR_INVALID_INPUT;
    }
    
    ParsedArgs parsed_args = {0};
    ErrorCode ret = parse_arguments(argc, argv, &parsed_args);
    if (ret != SUCCESS) {
        return ret;
    }
    
    // Override debug and silent macros if flags are set
    #undef DEBUG
    #undef SILENT
    #define DEBUG parsed_args.is_debug
    #define SILENT parsed_args.is_silent
    
    ErrorCode result = SUCCESS;
    
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

    // Reusable variables for store and retrieve
    char* token = NULL;
    char** chunk_paths = NULL;
    size_t chunk_count = 0;
    unsigned char key[KEY_SIZE] = {0};

    // Determine key path
    char* key_path = parsed_args.key_path;

    // Initialize encryption key
    if ((ret = handle_key_initialization(key, key_path)) != SUCCESS) {
        log_security_event("ERROR", "Key initialization failed");
        return ERROR_CRYPTO;
    }

    // Handle commands based on parsed arguments
    if (strcmp(parsed_args.command, "generate-key") == 0) {
        result = generate_key_file(parsed_args.filepath);
    }
    else if (strcmp(parsed_args.command, "store") == 0) {
        // Reuse original store command logic
        // Generate secure token
        token = generate_token();
        if (!token || strlen(token) < MIN_TOKEN_LEN) {
            log_security_event("ERROR", "Token generation failed");
            result = ERROR_CRYPTO;
            goto cleanup;
        }

        size_t original_file_size = 0;
        SecureMetadata metadata = {0};
        strncpy(metadata.token, token, TOKEN_SIZE);

        // Store file with timeout control
        StoreFileArgs args = {
            .filepath = parsed_args.filepath,
            .chunk_paths = &chunk_paths,
            .chunk_count = &chunk_count,
            .token = token,
            .file_size = &original_file_size,
            .metadata = &metadata
        };

        if ((ret = perform_operation_with_timeout(handle_store_file, &args)) != SUCCESS) {
            printf(!DEBUG ? "" :"Store operation failed with ret=%d\n", ret);
            result = ret;
            goto cleanup;
        }

        metadata.data_size = original_file_size;
        strncpy(metadata.original_filename, basename(parsed_args.filepath), 
                sizeof(metadata.original_filename) - 1);

        if (!chunk_paths || chunk_count == 0) {
            log_security_event("ERROR", "Chunk paths not properly initialized");
            result = ERROR_CRYPTO;
            goto cleanup;
        }

        if (encrypt_file_chunked(parsed_args.filepath, &chunk_paths, &chunk_count, key, &metadata) == SUCCESS) {
            if (save_metadata(&metadata) == SUCCESS) {
                printf(SILENT ? "" : "Token:");
                printf("%s\n",token);
                printf(SILENT ? "" : "Keep this token safe - you'll need it to retrieve your file.\n");
                
                log_security_event("SUCCESS", "File stored successfully");
            } else {
                log_security_event("ERROR", "Failed to save metadata");
                result = ERROR_SYSTEM;
            }
        } else {
            log_security_event("ERROR", "File encryption failed");
            result = ERROR_CRYPTO;
        }
    }
    else if (strcmp(parsed_args.command, "retrieve") == 0) {
        // Reuse original retrieve command logic
        if ((ret = validate_output_path(parsed_args.output_path)) != SUCCESS) {
            fprintf(stderr,!DEBUG ? "" : "Error: Could not create output directory\n");
            result = ret;
            goto cleanup;
        }

        // Load metadata using the provided token
        SecureMetadata metadata = {0};
        if ((ret = load_metadata(parsed_args.token, &metadata)) != SUCCESS) {
            fprintf(stderr,!DEBUG ? "" : "Error: Could not load metadata. Token might be invalid.\n");
            result = ret;
            goto cleanup;
        }

        // Extract the token from the metadata
        char extracted_token[TOKEN_SIZE]; 
        strncpy(extracted_token, metadata.token, TOKEN_SIZE);

        // Attempt to decrypt the file
        if ((ret = decrypt_file_chunked(parsed_args.output_path, key, &metadata, extracted_token)) == SUCCESS) {
            printf("\nFile retrieved successfully.\n");
            log_security_event("SUCCESS", "File retrieved successfully");
        } else {
            fprintf(stderr,!DEBUG ? "" : "Error: Decryption failed. Attempting recovery...\n");
            if ((ret = handle_decryption_failure(key, parsed_args.token, parsed_args.output_path)) == SUCCESS) {
                printf("\nFile retrieved successfully using fallback key.\n");
                log_security_event("SUCCESS", "File retrieved successfully with fallback key");
            } else {
                fprintf(stderr,!DEBUG ? "" : "\nDecryption failed with all attempted keys.\n");
                log_security_event("ERROR", "File retrieval failed");
                result = ret;
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
    
    return result;
}