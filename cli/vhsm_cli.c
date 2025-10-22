#include "../include/vhsm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#define MAX_COMMAND_LEN 1024
#define MAX_ARGS 32

static vhsm_ctx_t g_ctx = NULL;
static vhsm_session_t g_session = NULL;
static char g_storage_path[VHSM_MAX_PATH] = "./vhsm_storage";

/* Read password without echo */
static int read_password(const char* prompt, char* buffer, size_t size) {
    struct termios old_term, new_term;

    printf("%s", prompt);
    fflush(stdout);

    /* Disable echo */
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    /* Read password */
    char* result = fgets(buffer, size, stdin);

    /* Restore echo */
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");

    if (result) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        return 1;
    }

    return 0;
}

/* Command: help */
static void cmd_help(int argc, char* argv[]) {
    printf("Virtual HSM CLI v%s\n\n", vhsm_version());
    printf("Available commands:\n");
    printf("  help                      - Show this help\n");
    printf("  version                   - Show version information\n");
    printf("  init [path]               - Initialize HSM storage\n");
    printf("  user-create <username>    - Create a new user\n");
    printf("  login <username>          - Login and create session\n");
    printf("  logout                    - Logout current session\n");
    printf("  key-generate <name> <type> - Generate a new key\n");
    printf("  key-list                  - List all keys\n");
    printf("  key-delete <name>         - Delete a key\n");
    printf("  key-rotate <name>         - Rotate a key\n");
    printf("  encrypt <keyname> <data>  - Encrypt data\n");
    printf("  decrypt <keyname> <data>  - Decrypt data\n");
    printf("  sign <keyname> <data>     - Sign data\n");
    printf("  verify <keyname> <data> <sig> - Verify signature\n");
    printf("  file-store <keyname> <path> - Store file with encryption\n");
    printf("  file-retrieve <keyname> <token> <outpath> - Retrieve file\n");
    printf("  audit-enable <path>       - Enable audit logging\n");
    printf("  audit-query               - Query audit log\n");
    printf("  exit, quit                - Exit CLI\n");
    printf("\nKey types: aes128, aes256, ed25519, hmac256, hmac512\n");
}

/* Command: version */
static void cmd_version(int argc, char* argv[]) {
    printf("Virtual HSM Library v%s\n", vhsm_version());
}

/* Command: init */
static void cmd_init(int argc, char* argv[]) {
    if (argc > 1) {
        strncpy(g_storage_path, argv[1], VHSM_MAX_PATH - 1);
    }

    if (g_ctx) {
        printf("Already initialized\n");
        return;
    }

    vhsm_error_t err = vhsm_init();
    if (err != VHSM_SUCCESS) {
        printf("Error: %s\n", vhsm_error_string(err));
        return;
    }

    err = vhsm_ctx_create(&g_ctx, g_storage_path);
    if (err != VHSM_SUCCESS) {
        printf("Error: %s\n", vhsm_error_string(err));
        vhsm_cleanup();
        return;
    }

    uint8_t master_key[32];
    err = vhsm_ctx_generate_master_key(g_ctx, master_key);
    if (err != VHSM_SUCCESS) {
        printf("Error: %s\n", vhsm_error_string(err));
        vhsm_ctx_destroy(g_ctx);
        g_ctx = NULL;
        vhsm_cleanup();
        return;
    }

    printf("HSM initialized successfully\n");
    printf("Storage path: %s\n", g_storage_path);
}

/* Command: user-create */
static void cmd_user_create(int argc, char* argv[]) {
    if (!g_ctx) {
        printf("Error: HSM not initialized. Run 'init' first.\n");
        return;
    }

    if (argc < 2) {
        printf("Usage: user-create <username>\n");
        return;
    }

    char password[256];
    char confirm[256];

    if (!read_password("Password: ", password, sizeof(password))) {
        printf("Error reading password\n");
        return;
    }

    if (!read_password("Confirm password: ", confirm, sizeof(confirm))) {
        printf("Error reading password\n");
        return;
    }

    if (strcmp(password, confirm) != 0) {
        printf("Passwords do not match\n");
        return;
    }

    vhsm_error_t err = vhsm_user_create(g_ctx, argv[1], password, NULL, VHSM_ROLE_USER);
    if (err != VHSM_SUCCESS) {
        printf("Error: %s\n", vhsm_error_string(err));
        return;
    }

    printf("User '%s' created successfully\n", argv[1]);
}

/* Command: login */
static void cmd_login(int argc, char* argv[]) {
    if (!g_ctx) {
        printf("Error: HSM not initialized. Run 'init' first.\n");
        return;
    }

    if (argc < 2) {
        printf("Usage: login <username>\n");
        return;
    }

    if (g_session) {
        printf("Already logged in. Logout first.\n");
        return;
    }

    char password[256];
    if (!read_password("Password: ", password, sizeof(password))) {
        printf("Error reading password\n");
        return;
    }

    vhsm_error_t err = vhsm_session_login(g_ctx, &g_session, argv[1], password, NULL);
    if (err != VHSM_SUCCESS) {
        printf("Error: %s\n", vhsm_error_string(err));
        return;
    }

    printf("Logged in as '%s'\n", argv[1]);
}

/* Command: logout */
static void cmd_logout(int argc, char* argv[]) {
    if (!g_session) {
        printf("Not logged in\n");
        return;
    }

    vhsm_session_logout(g_session);
    g_session = NULL;
    printf("Logged out\n");
}

/* Command: key-generate */
static void cmd_key_generate(int argc, char* argv[]) {
    if (!g_session) {
        printf("Error: Not logged in. Run 'login' first.\n");
        return;
    }

    if (argc < 3) {
        printf("Usage: key-generate <name> <type>\n");
        printf("Types: aes128, aes256, ed25519, hmac256, hmac512\n");
        return;
    }

    vhsm_key_type_t type;
    if (strcmp(argv[2], "aes128") == 0) type = VHSM_KEY_TYPE_AES_128;
    else if (strcmp(argv[2], "aes256") == 0) type = VHSM_KEY_TYPE_AES_256;
    else if (strcmp(argv[2], "ed25519") == 0) type = VHSM_KEY_TYPE_ED25519;
    else if (strcmp(argv[2], "hmac256") == 0) type = VHSM_KEY_TYPE_HMAC_SHA256;
    else if (strcmp(argv[2], "hmac512") == 0) type = VHSM_KEY_TYPE_HMAC_SHA512;
    else {
        printf("Unknown key type: %s\n", argv[2]);
        return;
    }

    vhsm_key_handle_t handle;
    vhsm_error_t err = vhsm_key_generate(g_session, argv[1], type,
                                          VHSM_KEY_USAGE_ALL, &handle);
    if (err != VHSM_SUCCESS) {
        printf("Error: %s\n", vhsm_error_string(err));
        return;
    }

    printf("Key '%s' generated successfully (handle: %lu)\n", argv[1], handle);
}

/* Command: key-list */
static void cmd_key_list(int argc, char* argv[]) {
    if (!g_session) {
        printf("Error: Not logged in. Run 'login' first.\n");
        return;
    }

    vhsm_key_metadata_t metadata[100];
    size_t count = 100;

    vhsm_error_t err = vhsm_key_list(g_session, metadata, &count);
    if (err != VHSM_SUCCESS) {
        printf("Error: %s\n", vhsm_error_string(err));
        return;
    }

    printf("Found %zu keys:\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("  %s (type: %d, state: %d)\n",
               metadata[i].name, metadata[i].type, metadata[i].state);
    }
}

/* Command: audit-enable */
static void cmd_audit_enable(int argc, char* argv[]) {
    if (!g_ctx) {
        printf("Error: HSM not initialized. Run 'init' first.\n");
        return;
    }

    const char* log_path = "vhsm_audit.log";
    if (argc > 1) {
        log_path = argv[1];
    }

    vhsm_error_t err = vhsm_audit_enable(g_ctx, log_path);
    if (err != VHSM_SUCCESS) {
        printf("Error: %s\n", vhsm_error_string(err));
        return;
    }

    printf("Audit logging enabled: %s\n", log_path);
}

/* Interactive mode */
static void interactive_mode(void) {
    char line[MAX_COMMAND_LEN];
    char* args[MAX_ARGS];
    int argc;

    printf("Virtual HSM CLI v%s\n", vhsm_version());
    printf("Type 'help' for available commands\n\n");

    while (1) {
        printf("vhsm> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }

        /* Remove newline */
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        /* Skip empty lines */
        if (strlen(line) == 0) {
            continue;
        }

        /* Parse command */
        argc = 0;
        char* token = strtok(line, " \t");
        while (token && argc < MAX_ARGS) {
            args[argc++] = token;
            token = strtok(NULL, " \t");
        }

        if (argc == 0) {
            continue;
        }

        /* Execute command */
        if (strcmp(args[0], "help") == 0) {
            cmd_help(argc, args);
        } else if (strcmp(args[0], "version") == 0) {
            cmd_version(argc, args);
        } else if (strcmp(args[0], "init") == 0) {
            cmd_init(argc, args);
        } else if (strcmp(args[0], "user-create") == 0) {
            cmd_user_create(argc, args);
        } else if (strcmp(args[0], "login") == 0) {
            cmd_login(argc, args);
        } else if (strcmp(args[0], "logout") == 0) {
            cmd_logout(argc, args);
        } else if (strcmp(args[0], "key-generate") == 0) {
            cmd_key_generate(argc, args);
        } else if (strcmp(args[0], "key-list") == 0) {
            cmd_key_list(argc, args);
        } else if (strcmp(args[0], "audit-enable") == 0) {
            cmd_audit_enable(argc, args);
        } else if (strcmp(args[0], "exit") == 0 || strcmp(args[0], "quit") == 0) {
            break;
        } else {
            printf("Unknown command: %s\n", args[0]);
            printf("Type 'help' for available commands\n");
        }
    }

    /* Cleanup */
    if (g_session) {
        vhsm_session_logout(g_session);
    }
    if (g_ctx) {
        vhsm_ctx_destroy(g_ctx);
        vhsm_cleanup();
    }
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        /* Interactive mode */
        interactive_mode();
    } else {
        /* Command-line mode */
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            cmd_help(0, NULL);
        } else {
            printf("Use without arguments for interactive mode\n");
        }
    }

    return 0;
}
