// Alon Hillel-Tuch
// 2024
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, "Debug: " fmt "\n", ##__VA_ARGS__)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/stat.h>

#include "common_defs.h"
#include "digital_signature.h"
#include "command_args.h"
#include "hsm_shared.h"
#include "utils.h"
#include "key_func.h"

KeyEntry keystore[MAX_KEYS];
int key_count = 0;
unsigned char master_key[KEY_SIZE];

char keystore_file[MAX_FILENAME] = "keystore.dat";
char master_key_file[MAX_FILENAME] = "master.key";

// Function prototypes
void update_global_paths(const CommandLineArgs* args);
void handle_sign_command(const CommandLineArgs* args);
int handle_verify_command(const CommandLineArgs* args);
void handle_export_public_key_command(const char* key_name);
void handle_import_public_key_command(const CommandLineArgs* args);

// Function to update global file paths from arguments
void update_global_paths(const CommandLineArgs* args) {
    if (strlen(args->keystore_file) > 0) {
        strncpy(keystore_file, args->keystore_file, MAX_FILENAME - 1);
        keystore_file[MAX_FILENAME - 1] = '\0';
    }
    
    if (strlen(args->master_key_file) > 0) {
        strncpy(master_key_file, args->master_key_file, MAX_FILENAME - 1);
        master_key_file[MAX_FILENAME - 1] = '\0';
    }
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "Debug: Starting virtual_hsm\n");
    
    CommandLineArgs args;
    if (!handle_arguments(argc, argv, &args)) {
        return 1;
    }

    update_global_paths(&args);

    // Handle generate_master_key command before trying to load the master key
    if (strcmp(args.command, "-generate_master_key") == 0) {
        generate_master_key();

        // Check for the "store_key" argument
        if (argc > 2 && strcmp(argv[2], "store_key") == 0) {
            // Store the generated master key in master_key_file
            FILE *file = fopen(master_key_file, "wb");
            if (file == NULL) {
                fprintf(stderr, "Error: Unable to open master key file for writing.\n");
                exit(1);
            }
            fwrite(master_key, 1, KEY_SIZE, file);
            fclose(file);
            printf("Master key stored in %s\n", master_key_file);
        }

        return 0;
    }

    // For all other commands, we need the master key
    load_master_key(args.provided_master_key);
    load_keystore();

    if (strcmp(args.command, "-store") == 0) {
        char hex_key[KEY_SIZE * 2 + 1];
        if (fread(hex_key, 1, KEY_SIZE * 2, stdin) != KEY_SIZE * 2) {
            fprintf(stderr, "Error: Invalid key input. Please provide %d hex characters.\n", KEY_SIZE * 2);
            return 1;
        }
        hex_key[KEY_SIZE * 2] = '\0';
        
        unsigned char binary_key[KEY_SIZE];
        hex_to_bytes(hex_key, binary_key, KEY_SIZE);
        store_key(args.key_name, binary_key, 0);
    } else if (strcmp(args.command, "-retrieve") == 0) {
        retrieve_key(args.key_name);
    } else if (strcmp(args.command, "-list") == 0) {
        list_keys();
    } else if (strcmp(args.command, "-generate_key_pair") == 0) {
        generate_key_pair(args.key_name);
    } else if (strcmp(args.command, "-sign") == 0) {
        handle_sign_command(&args);
    } else if (strcmp(args.command, "-verify") == 0) {
        handle_verify_command(&args);
    } else if (strcmp(args.command, "-export_public_key") == 0) {
        handle_export_public_key_command(args.key_name);
    } else if (strcmp(args.command, "-import_public_key") == 0) {
        handle_import_public_key_command(&args);
    }

    return 0;
}

void handle_sign_command(const CommandLineArgs* args) {
    if (!args) {
        fprintf(stderr, "Error: Invalid arguments\n");
        exit(1);
    }

    unsigned char *data = NULL;
    size_t data_len = 0;
    char buffer[BUFFER_SIZE];

    if (args->input_file) {
        data = read_file(args->input_file, &data_len);
        if (!data) {
            fprintf(stderr, "Error: Failed to read input file '%s'\n", args->input_file);
            exit(1);
        }
    } else if (args->input_string) {
        data_len = strlen(args->input_string);
        data = (unsigned char*)malloc(data_len + 1);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            exit(1);
        }
        memcpy(data, args->input_string, data_len);
        data[data_len] = '\0';
    } else {
        // Read from stdin
        data_len = fread(buffer, 1, sizeof(buffer) - 1, stdin);
        if (data_len == 0) {
            fprintf(stderr, "Error: No input data provided for signing\n");
            exit(1);
        }
        data = (unsigned char*)malloc(data_len + 1);
        if (!data) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            exit(1);
        }
        memcpy(data, buffer, data_len);
        data[data_len] = '\0';
    }

    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len = sizeof(signature);

    if (sign_data(args->key_name, data, data_len, signature, &sig_len)) {
        // Write signature to stdout if no output file specified
        if (args->output_file) {
            if (!write_file(args->output_file, signature, sig_len)) {
                fprintf(stderr, "Error: Failed to write signature to file\n");
                free(data);
                data = NULL;
                exit(1);
            }
        } else {
            if (fwrite(signature, 1, sig_len, stdout) != sig_len) {
                fprintf(stderr, "Error: Failed to write signature to stdout\n");
                free(data);
                data = NULL;
                exit(1);
            }
        }
    } else {
        fprintf(stderr, "Error: Signing failed\n");
        free(data);
        data = NULL;
        exit(1);
    }

    free(data);
    data = NULL;
}

int handle_verify_command(const CommandLineArgs* args) {
    unsigned char data[BUFFER_SIZE];
    unsigned char signature[SIG_LENGTH];
    size_t data_len = 0;
    size_t sig_len = 0;
    
    if (args->use_stdin) {
        // Read concatenated data and signature from stdin
        data_len = fread(data, 1, BUFFER_SIZE - 1, stdin);
        if (data_len == 0) {
            fprintf(stderr, "Error: No data provided for verification\n");
            return 0;
        }
        
        sig_len = fread(signature, 1, SIG_LENGTH, stdin);
        if (sig_len != SIG_LENGTH) {
            fprintf(stderr, "Error: Invalid signature length or missing signature\n");
            return 0;
        }
    } else if (args->input_string) {
        // Handle input string
        data_len = strlen(args->input_string);
        if (data_len >= BUFFER_SIZE) {
            fprintf(stderr, "Error: Input string too long\n");
            return 0;
        }
        memcpy(data, args->input_string, data_len);
        
        // Read signature from signature file
        FILE *sig_file = fopen(args->signature_file, "rb");
        if (!sig_file) {
            fprintf(stderr, "Error: Failed to open signature file '%s'\n", args->signature_file);
            return 0;
        }
        
        sig_len = fread(signature, 1, SIG_LENGTH, sig_file);
        fclose(sig_file);
        
        if (sig_len != SIG_LENGTH) {
            fprintf(stderr, "Error: Invalid signature length in file '%s'\n", args->signature_file);
            return 0;
        }
    } else if (args->input_file) {
        // Read data from input file
        FILE *data_file = fopen(args->input_file, "rb");
        if (!data_file) {
            fprintf(stderr, "Error: Failed to open input file '%s'\n", args->input_file);
            return 0;
        }
        
        data_len = fread(data, 1, BUFFER_SIZE - 1, data_file);
        fclose(data_file);
        
        if (data_len == 0) {
            fprintf(stderr, "Error: No data read from file '%s'\n", args->input_file);
            return 0;
        }
        
        // Read signature from signature file
        FILE *sig_file = fopen(args->signature_file, "rb");
        if (!sig_file) {
            fprintf(stderr, "Error: Failed to open signature file '%s'\n", args->signature_file);
            return 0;
        }
        
        sig_len = fread(signature, 1, SIG_LENGTH, sig_file);
        fclose(sig_file);
        
        if (sig_len != SIG_LENGTH) {
            fprintf(stderr, "Error: Invalid signature length in file '%s'\n", args->signature_file);
            return 0;
        }
    } else {
        fprintf(stderr, "Error: No input provided for verification\n");
        return 0;
    }
    
    // Call verify_signature with all required parameters
    if (data_len > 0 && sig_len == SIG_LENGTH) {
        return verify_signature(args->key_name, data, data_len, signature, sig_len);
    }
    
    return 0;
}

void handle_export_public_key_command(const char* key_name) {
    char *pem_key;
    pem_key = NULL;
    if (export_public_key(key_name, &pem_key)) {
        printf("%s", pem_key);
        free(pem_key);
        pem_key = NULL;
    } else {
        fprintf(stderr, "Public key export failed\n");
        exit(1);
    }
}

void handle_import_public_key_command(const CommandLineArgs* args) {
    char pem_key[PEM_KEY_CHAR_ARR_SIZE];
    size_t pem_len = 0;

    if (args->input_file) {
        unsigned char* data = read_file(args->input_file, &pem_len);
        if (data) {
            strncpy(pem_key, (char*)data, sizeof(pem_key) - 1);
            pem_key[sizeof(pem_key) - 1] = '\0';
            free(data);
            data = NULL;
        } else {
            fprintf(stderr, "Error: Failed to read input file\n");
            exit(1);
        }
    } else if (args->input_string) {
        pem_len = strlen(args->input_string);
        strncpy(pem_key, args->input_string, sizeof(pem_key) - 1);
        pem_key[sizeof(pem_key) - 1] = '\0';
    } else {
        pem_len = fread(pem_key, 1, sizeof(pem_key), stdin);
    }

    if (import_public_key(args->key_name, pem_key)) {
        printf("Public key imported successfully\n");
    } else {
        fprintf(stderr, "Public key import failed\n");
        exit(1);
    }
}
