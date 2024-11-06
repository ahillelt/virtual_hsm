#ifndef COMMAND_ARGS_H
#define COMMAND_ARGS_H

#include <stdio.h>
#include <string.h>

// Our imports
#include "common_defs.h"

#define MAX_FILENAME 256
#define MAX_NAME_LENGTH 49
#define MAX_STRING_INPUT 4096

// Structure to hold parsed command line arguments
typedef struct {
    char keystore_file[MAX_FILENAME];
    char master_key_file[MAX_FILENAME];
    const char* provided_master_key;
    const char* command;
    const char* key_name;
    
    // Input handling
    const char* input_file;     // File to read input from
    const char* input_string;   // Direct string input
    int use_stdin;             // Flag to indicate if using stdin
    
    // Output handling
    const char* output_file;    // File to write output to
    int use_stdout;            // Flag to indicate if using stdout (default)
    
    // Signature specific
    const char* signature_file; // Signature file for verify operations
} CommandLineArgs;

// Function prototypes
void init_command_line_args(CommandLineArgs* args);
void update_global_paths(const CommandLineArgs* args);
int handle_arguments(int argc, char *argv[], CommandLineArgs* args);
void print_usage(void);

void init_command_line_args(CommandLineArgs* args) {
    memset(args->keystore_file, 0, MAX_FILENAME);
    memset(args->master_key_file, 0, MAX_FILENAME);
    args->provided_master_key = NULL;
    args->command = NULL;
    args->key_name = NULL;
    args->input_file = NULL;
    args->input_string = NULL;
    args->output_file = NULL;
    args->signature_file = NULL;
    args->use_stdin = 0;
    args->use_stdout = 1;  // Default to stdout
}

void print_usage(void) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  ./virtual_hsm [-keystore <keystore_file>] [-master <master_key_file>] [-master_key <hex_key>] <command> [options]\n\n");
    
    fprintf(stderr, "Global Options:\n");
    fprintf(stderr, "  -keystore <file>      Specify custom keystore file (default: keystore.dat)\n");
    fprintf(stderr, "  -master <file>        Specify custom master key file (default: master.key)\n");
    fprintf(stderr, "  -master_key <hex>     Provide master key directly as hex string\n\n");
    
    fprintf(stderr, "Input/Output Options:\n");
    fprintf(stderr, "  -i <file>             Read input from file\n");
    fprintf(stderr, "  -is \"<string>\"        Provide input as string\n");
    fprintf(stderr, "  -o <file>             Write output to file (default: stdout)\n\n");
    
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  Key Management:\n");
    fprintf(stderr, "    -store <key_name>           Store a symmetric key\n");
    fprintf(stderr, "                                Traditional: echo \"0123456789abcdef\" | ./virtual_hsm -store mykey\n");
    fprintf(stderr, "                                New: ./virtual_hsm -store mykey -is \"0123456789abcdef\"\n");
    fprintf(stderr, "                                     ./virtual_hsm -store mykey -i keyfile.txt\n\n");
    
    fprintf(stderr, "    -retrieve <key_name>        Retrieve a key's value in hex format\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -retrieve mykey -o output.txt\n\n");
    
    fprintf(stderr, "    -list                       List all stored key names\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -list -o keys.txt\n\n");
    
    fprintf(stderr, "  Master Key Operations:\n");
    fprintf(stderr, "    -generate_master_key        Generate a new master key\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -generate_master_key -o master.key\n\n");
    
    fprintf(stderr, "  Asymmetric Key Operations:\n");
    fprintf(stderr, "    -generate_key_pair <name>   Generate ED25519 key pair\n");
    fprintf(stderr, "                                Creates both <name> (private) and <name>_public\n\n");
    
    fprintf(stderr, "    -sign <key_name>           Sign data using private key\n");
    fprintf(stderr, "                                Traditional: echo -n \"hello\" | ./virtual_hsm -sign signing_key > signature.bin\n");
    fprintf(stderr, "                                New: ./virtual_hsm -sign signing_key -i file.txt -o signature.bin\n");
    fprintf(stderr, "                                     ./virtual_hsm -sign signing_key -is \"hello\" -o signature.bin\n\n");
    
    fprintf(stderr, "    -verify <key_name>         Verify signature\n");
    fprintf(stderr, "                                Traditional: cat file.txt signature.bin | ./virtual_hsm -verify signing_key_public\n");
    fprintf(stderr, "                                New: ./virtual_hsm -verify signing_key_public -i file.txt -s signature.bin\n");
    fprintf(stderr, "                                     ./virtual_hsm -verify signing_key_public -is \"hello\" -s signature.bin\n\n");
    
    fprintf(stderr, "    -export_public_key <name>   Export public key in PEM format\n");
    fprintf(stderr, "                                Example: ./virtual_hsm -export_public_key signing_key_public -o public.pem\n\n");
    
    fprintf(stderr, "    -import_public_key <name>   Import public key from PEM format\n");
    fprintf(stderr, "                                Traditional: cat public.pem | ./virtual_hsm -import_public_key new_key\n");
    fprintf(stderr, "                                New: ./virtual_hsm -import_public_key new_key -i public.pem\n\n");
}

int handle_arguments(int argc, char *argv[], CommandLineArgs* args) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    init_command_line_args(args);

    int i;
    // Parse optional arguments first
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-keystore") == 0 && i + 1 < argc) {
            strncpy(args->keystore_file, argv[++i], MAX_FILENAME - 1);
            args->keystore_file[MAX_FILENAME - 1] = '\0';
        } else if (strcmp(argv[i], "-master") == 0 && i + 1 < argc) {
            strncpy(args->master_key_file, argv[++i], MAX_FILENAME - 1);
            args->master_key_file[MAX_FILENAME - 1] = '\0';
        } else if (strcmp(argv[i], "-master_key") == 0 && i + 1 < argc) {
            args->provided_master_key = argv[++i];
        } else {
            break;  // Found the command
        }
    }

    if (i >= argc) {
        print_usage();
        return 0;
    }

    // Store the command
    args->command = argv[i];
    
    // Store the key name if the command requires it
    if (i + 1 < argc && strcmp(args->command, "-list") != 0 && 
        strcmp(args->command, "-generate_master_key") != 0) {
        args->key_name = argv[i + 1];
        i++;  // Move past the key name
    }

    // Parse remaining arguments
    for (; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            args->input_file = argv[++i];
            args->use_stdin = 0;
        } else if (strcmp(argv[i], "-is") == 0 && i + 1 < argc) {
            args->input_string = argv[++i];
            args->use_stdin = 0;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            args->output_file = argv[++i];
            args->use_stdout = 0;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            args->signature_file = argv[++i];
        }
    }

    // Handle verify command's special case for backward compatibility
    if (strcmp(args->command, "-verify") == 0) {
        if (!args->input_file && !args->input_string && !args->signature_file) {
            args->use_stdin = 1;  // Default to stdin for backward compatibility
        } else if (!args->signature_file) {
            fprintf(stderr, "Error: Signature file (-s) required for verify command when using -i or -is\n");
            return 0;
        }
    }

    // Validate command and arguments
    if (strcmp(args->command, "-store") == 0 ||
        strcmp(args->command, "-retrieve") == 0 ||
        strcmp(args->command, "-generate_key_pair") == 0 ||
        strcmp(args->command, "-sign") == 0 ||
        strcmp(args->command, "-verify") == 0 ||
        strcmp(args->command, "-export_public_key") == 0 ||
        strcmp(args->command, "-import_public_key") == 0) {
        if (!args->key_name) {
            fprintf(stderr, "Error: Key name required for %s command\n", args->command);
            print_usage();
            return 0;
        }
    } else if (strcmp(args->command, "-list") != 0 && 
               strcmp(args->command, "-generate_master_key") != 0) {
        fprintf(stderr, "Error: Unknown command: %s\n", args->command);
        print_usage();
        return 0;
    }

    return 1;
}

#endif // COMMAND_ARGS_H
