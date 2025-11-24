#include <stddef.h>
#include <fido.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <json-c/json.h>
#include <limits.h>
#include <openssl/rand.h>
#include <stdint.h>

/* Constants - moved to top */
#define MAX_DEVICES 8
#define RPID "nyu.edu"
#define USER_ID "ah5647"
#define USER_NAME "Alon"
#define CREDENTIAL_LEN 32
#define MAX_PIN_LENGTH 64
#define STORAGE_DIR ".passkeys"
#define CRED_FILE "credentials.json"
#define CRED_TYPE_ES256 1
#define MAX_CREDENTIAL_SIZE 1024
#define CHALLENGE_SIZE 32

static int debug_enabled = 0;
#define DEBUG_PRINT(...) do { if (debug_enabled) printf(__VA_ARGS__); } while (0)

typedef struct {
    unsigned char *id;
    size_t id_len;
    char *name;
    char *rpid;
} credential_info_t;

/* Function prototypes */
char* get_pin(void);
int ensure_storage_dir(void);
int save_credential(const unsigned char *cred_id, size_t cred_len, const char *name);
credential_info_t *load_credential(const char *name);
void free_credential(credential_info_t *cred);
void check_device_capabilities(fido_dev_t *dev);
int generate_passkey(fido_dev_t *dev, const char *name);
int authenticate_credential(fido_dev_t *dev, const char *name);

/**
 * Securely get PIN from user with echo disabled
 * Returns: Allocated PIN string or NULL on failure
 * Caller must free and wipe returned buffer
 */
char* get_pin(void) {
    struct termios old_term, new_term;
    char* pin = NULL;
    size_t len;

    pin = calloc(1, MAX_PIN_LENGTH);
    if (pin == NULL) {
        DEBUG_PRINT("Failed to allocate PIN buffer\n");
        return NULL;
    }

    if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
        DEBUG_PRINT("Failed to get terminal attributes\n");
        free(pin);
        return NULL;
    }

    new_term = old_term;
    new_term.c_lflag &= ~(ECHO);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
        DEBUG_PRINT("Failed to set terminal attributes\n");
        free(pin);
        return NULL;
    }

    printf("Enter YubiKey PIN: ");
    fflush(stdout);

    if (fgets(pin, MAX_PIN_LENGTH, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        memset(pin, 0, MAX_PIN_LENGTH);
        free(pin);
        DEBUG_PRINT("Failed to read PIN\n");
        return NULL;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");

    /* Remove newline */
    len = strlen(pin);
    if (len > 0 && pin[len-1] == '\n') {
        pin[len-1] = '\0';
    }

    return pin;
}

/**
 * Ensure storage directory exists with secure permissions
 * Returns: 0 on success, -1 on failure
 */
int ensure_storage_dir(void) {
    char *home;
    char storage_path[PATH_MAX];
    struct stat st = {0};
    int result;

    home = getenv("HOME");
    if (!home) {
        DEBUG_PRINT("Could not get HOME directory\n");
        return -1;
    }

    result = snprintf(storage_path, sizeof(storage_path), "%s/%s", home, STORAGE_DIR);
    if (result < 0 || (size_t)result >= sizeof(storage_path)) {
        DEBUG_PRINT("Path too long\n");
        return -1;
    }

    if (stat(storage_path, &st) == -1) {
        if (mkdir(storage_path, 0700) == -1) {
            DEBUG_PRINT("Could not create storage directory: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}

/**
 * Save credential to JSON file
 * SECURITY: Fixed sprintf buffer overflow, added size validation
 * Returns: 0 on success, -1 on failure
 */
int save_credential(const unsigned char *cred_id, size_t cred_len, const char *name) {
    char *home = NULL;
    char file_path[PATH_MAX];
    json_object *root = NULL;
    json_object *cred_obj = NULL;
    char *hex_cred = NULL;
    size_t hex_size;
    struct stat st = {0};
    int result;
    size_t i;

    if (!cred_id || cred_len == 0 || !name) {
        DEBUG_PRINT("Invalid parameters\n");
        return -1;
    }

    /* SECURITY: Check for integer overflow before allocation */
    if (cred_len > SIZE_MAX / 2 - 1 || cred_len > MAX_CREDENTIAL_SIZE) {
        DEBUG_PRINT("Credential too large\n");
        return -1;
    }

    if (ensure_storage_dir() != 0) {
        return -1;
    }

    home = getenv("HOME");
    if (!home) {
        DEBUG_PRINT("Could not get HOME directory\n");
        return -1;
    }

    result = snprintf(file_path, sizeof(file_path), "%s/%s/%s", home, STORAGE_DIR, CRED_FILE);
    if (result < 0 || (size_t)result >= sizeof(file_path)) {
        DEBUG_PRINT("Path too long\n");
        return -1;
    }

    cred_obj = json_object_new_object();
    if (!cred_obj) {
        DEBUG_PRINT("Failed to create JSON object\n");
        return -1;
    }

    /* SECURITY: Safe allocation with overflow check */
    hex_size = cred_len * 2 + 1;
    hex_cred = calloc(1, hex_size);
    if (!hex_cred) {
        DEBUG_PRINT("Failed to allocate hex buffer\n");
        json_object_put(cred_obj);
        return -1;
    }

    /* SECURITY: Use snprintf instead of sprintf for bounds checking */
    for (i = 0; i < cred_len; i++) {
        result = snprintf(&hex_cred[i*2], hex_size - (i*2), "%02x", cred_id[i]);
        if (result < 0 || (size_t)result >= hex_size - (i*2)) {
            DEBUG_PRINT("Failed to format credential\n");
            free(hex_cred);
            json_object_put(cred_obj);
            return -1;
        }
    }

    json_object_object_add(cred_obj, "id", json_object_new_string(hex_cred));
    json_object_object_add(cred_obj, "rpid", json_object_new_string(RPID));

    /* Wipe sensitive data */
    memset(hex_cred, 0, hex_size);
    free(hex_cred);
    hex_cred = NULL;

    if (stat(file_path, &st) != -1) {
        json_object *existing = json_object_from_file(file_path);
        if (existing) {
            root = existing;
        }
    }

    if (!root) {
        root = json_object_new_object();
        if (!root) {
            DEBUG_PRINT("Failed to create root JSON object\n");
            json_object_put(cred_obj);
            return -1;
        }
    }

    json_object_object_add(root, name, cred_obj);

    if (json_object_to_file(file_path, root) != 0) {
        DEBUG_PRINT("Failed to write JSON file\n");
        json_object_put(root);
        return -1;
    }

    json_object_put(root);
    return 0;
}

/**
 * Load credential from JSON file
 * SECURITY: Added validation, fixed memory leaks
 * Returns: Allocated credential structure or NULL on failure
 * Caller must free with free_credential()
 */
credential_info_t *load_credential(const char *name) {
    char *home = NULL;
    char file_path[PATH_MAX];
    json_object *root = NULL;
    json_object *cred_obj = NULL;
    json_object *id_obj = NULL;
    json_object *rpid_obj = NULL;
    credential_info_t *cred = NULL;
    const char *hex_id = NULL;
    const char *rpid_str = NULL;
    size_t hex_len;
    int result;
    size_t i;
    unsigned int byte_val;

    if (!name) {
        DEBUG_PRINT("Invalid name parameter\n");
        return NULL;
    }

    home = getenv("HOME");
    if (!home) {
        DEBUG_PRINT("Could not get HOME directory\n");
        return NULL;
    }

    result = snprintf(file_path, sizeof(file_path), "%s/%s/%s", home, STORAGE_DIR, CRED_FILE);
    if (result < 0 || (size_t)result >= sizeof(file_path)) {
        DEBUG_PRINT("Path too long\n");
        return NULL;
    }

    root = json_object_from_file(file_path);
    if (!root) {
        DEBUG_PRINT("Failed to load JSON file\n");
        return NULL;
    }

    if (!json_object_object_get_ex(root, name, &cred_obj)) {
        DEBUG_PRINT("Credential not found\n");
        json_object_put(root);
        return NULL;
    }

    cred = calloc(1, sizeof(credential_info_t));
    if (!cred) {
        DEBUG_PRINT("Failed to allocate credential structure\n");
        json_object_put(root);
        return NULL;
    }

    if (!json_object_object_get_ex(cred_obj, "id", &id_obj) ||
        !json_object_object_get_ex(cred_obj, "rpid", &rpid_obj)) {
        DEBUG_PRINT("Missing required fields in credential\n");
        free(cred);
        json_object_put(root);
        return NULL;
    }

    hex_id = json_object_get_string(id_obj);
    if (!hex_id) {
        DEBUG_PRINT("Invalid credential ID\n");
        free(cred);
        json_object_put(root);
        return NULL;
    }

    hex_len = strlen(hex_id);
    if (hex_len % 2 != 0 || hex_len == 0 || hex_len > MAX_CREDENTIAL_SIZE * 2) {
        DEBUG_PRINT("Invalid credential ID length\n");
        free(cred);
        json_object_put(root);
        return NULL;
    }

    cred->id_len = hex_len / 2;
    cred->id = malloc(cred->id_len);
    if (!cred->id) {
        DEBUG_PRINT("Failed to allocate credential ID buffer\n");
        free(cred);
        json_object_put(root);
        return NULL;
    }

    /* SECURITY: Validate sscanf return value */
    for (i = 0; i < cred->id_len; i++) {
        if (sscanf(&hex_id[i*2], "%2x", &byte_val) != 1) {
            DEBUG_PRINT("Failed to parse credential ID\n");
            free(cred->id);
            free(cred);
            json_object_put(root);
            return NULL;
        }
        cred->id[i] = (unsigned char)byte_val;
    }

    /* SECURITY: Check strdup return values */
    cred->name = strdup(name);
    if (!cred->name) {
        DEBUG_PRINT("Failed to duplicate name\n");
        free(cred->id);
        free(cred);
        json_object_put(root);
        return NULL;
    }

    rpid_str = json_object_get_string(rpid_obj);
    if (!rpid_str) {
        DEBUG_PRINT("Invalid RPID\n");
        free(cred->name);
        free(cred->id);
        free(cred);
        json_object_put(root);
        return NULL;
    }

    cred->rpid = strdup(rpid_str);
    if (!cred->rpid) {
        DEBUG_PRINT("Failed to duplicate RPID\n");
        free(cred->name);
        free(cred->id);
        free(cred);
        json_object_put(root);
        return NULL;
    }

    json_object_put(root);
    return cred;
}

/**
 * Free credential structure and wipe sensitive data
 * SECURITY: Prevents dangling pointers, wipes memory
 */
void free_credential(credential_info_t *cred) {
    if (!cred) {
        return;
    }

    if (cred->id) {
        memset(cred->id, 0, cred->id_len);
        free(cred->id);
        cred->id = NULL;
    }

    if (cred->name) {
        memset(cred->name, 0, strlen(cred->name));
        free(cred->name);
        cred->name = NULL;
    }

    if (cred->rpid) {
        memset(cred->rpid, 0, strlen(cred->rpid));
        free(cred->rpid);
        cred->rpid = NULL;
    }

    memset(cred, 0, sizeof(credential_info_t));
    free(cred);
}

void check_device_capabilities(fido_dev_t *dev) {
    if (!dev) return;

    DEBUG_PRINT("Device capabilities:\n");
    DEBUG_PRINT("  FIDO2 Support: %s\n", fido_dev_is_fido2(dev) ? "Yes" : "No");
    DEBUG_PRINT("  PIN Support: %s\n", fido_dev_has_pin(dev) ? "Yes" : "No");
}

/**
 * Generate new passkey credential
 * SECURITY: Use OpenSSL RAND_bytes, enhanced error handling
 */
int generate_passkey(fido_dev_t *dev, const char *name) {
    /* Variables declared at top */
    int ret = -1;
    fido_cred_t *cred = NULL;
    char *pin = NULL;
    unsigned char user_id[CHALLENGE_SIZE];
    unsigned char cdh[CHALLENGE_SIZE];
    const unsigned char *cred_id = NULL;
    size_t cred_len = 0;
    int err;

    if (!dev || !name) {
        DEBUG_PRINT("Invalid parameters\n");
        return -1;
    }

    /* SECURITY: Use OpenSSL RAND_bytes instead of /dev/urandom */
    if (RAND_bytes(cdh, sizeof(cdh)) != 1) {
        DEBUG_PRINT("Failed to generate challenge\n");
        goto cleanup;
    }

    if (RAND_bytes(user_id, sizeof(user_id)) != 1) {
        DEBUG_PRINT("Failed to generate user ID\n");
        goto cleanup;
    }

    cred = fido_cred_new();
    if (!cred) {
        DEBUG_PRINT("Failed to create credential\n");
        goto cleanup;
    }

    if ((err = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK) {
        DEBUG_PRINT("Failed to set credential type: %s\n", fido_strerr(err));
        goto cleanup;
    }

    if ((err = fido_cred_set_rp(cred, RPID, NULL)) != FIDO_OK) {
        DEBUG_PRINT("Failed to set relying party ID: %s\n", fido_strerr(err));
        goto cleanup;
    }

    if ((err = fido_cred_set_user(cred, user_id, sizeof(user_id), USER_NAME, USER_NAME, NULL)) != FIDO_OK) {
        DEBUG_PRINT("Failed to set user information: %s\n", fido_strerr(err));
        goto cleanup;
    }

    if ((err = fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh))) != FIDO_OK) {
        DEBUG_PRINT("Failed to set client data hash: %s\n", fido_strerr(err));
        goto cleanup;
    }

    if (fido_dev_has_pin(dev)) {
        pin = get_pin();
        if (!pin) {
            DEBUG_PRINT("Failed to get PIN\n");
            goto cleanup;
        }
    }

    printf("Please touch your YubiKey to complete registration...\n");
    fflush(stdout);

    if ((err = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK) {
        DEBUG_PRINT("Failed to make credential: %s\n", fido_strerr(err));
        goto cleanup;
    }

    cred_id = fido_cred_id_ptr(cred);
    cred_len = fido_cred_id_len(cred);

    if (!cred_id || cred_len == 0) {
        DEBUG_PRINT("Invalid credential ID\n");
        goto cleanup;
    }

    if (save_credential(cred_id, cred_len, name) != 0) {
        DEBUG_PRINT("Failed to save credential\n");
        goto cleanup;
    }

    printf("Passkey generated and stored successfully\n");
    ret = 0;

cleanup:
    if (pin) {
        memset(pin, 0, MAX_PIN_LENGTH);
        free(pin);
        pin = NULL;
    }
    if (cred) {
        fido_cred_free(&cred);
        cred = NULL;
    }

    /* Wipe sensitive data */
    memset(cdh, 0, sizeof(cdh));
    memset(user_id, 0, sizeof(user_id));

    return ret;
}

/**
 * Authenticate using stored credential
 * SECURITY: Use OpenSSL RAND_bytes, enhanced cleanup
 */
int authenticate_credential(fido_dev_t *dev, const char *name) {
    /* Variables declared at top */
    int ret = -1;
    fido_assert_t *assert = NULL;
    char *pin = NULL;
    unsigned char cdh[CHALLENGE_SIZE];
    credential_info_t *cred = NULL;
    int err;

    if (!dev || !name) {
        DEBUG_PRINT("Invalid parameters\n");
        return -1;
    }

    cred = load_credential(name);
    if (!cred) {
        printf("Error: Credential with name '%s' not found. Cannot continue authentication.\n", name);
        return ret;
    }

    /* SECURITY: Use OpenSSL RAND_bytes instead of /dev/urandom */
    if (RAND_bytes(cdh, sizeof(cdh)) != 1) {
        DEBUG_PRINT("Failed to generate challenge\n");
        goto cleanup;
    }

    assert = fido_assert_new();
    if (!assert) {
        DEBUG_PRINT("Failed to create assertion\n");
        goto cleanup;
    }

    if ((err = fido_assert_set_rp(assert, cred->rpid)) != FIDO_OK) {
        DEBUG_PRINT("Failed to set relying party ID: %s\n", fido_strerr(err));
        goto cleanup;
    }

    if ((err = fido_assert_set_clientdata_hash(assert, cdh, sizeof(cdh))) != FIDO_OK) {
        DEBUG_PRINT("Failed to set client data hash: %s\n", fido_strerr(err));
        goto cleanup;
    }

    if ((err = fido_assert_allow_cred(assert, cred->id, cred->id_len)) != FIDO_OK) {
        DEBUG_PRINT("Failed to allow credential: %s\n", fido_strerr(err));
        goto cleanup;
    }

    if (fido_dev_has_pin(dev)) {
        pin = get_pin();
        if (!pin) {
            DEBUG_PRINT("Failed to get PIN\n");
            goto cleanup;
        }
    }

    printf("Please touch your YubiKey to authenticate...\n");
    fflush(stdout);

    if ((err = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
        DEBUG_PRINT("Failed to get assertion: %s\n", fido_strerr(err));
        goto cleanup;
    }

    printf("Authentication successful\n");
    ret = 0;

cleanup:
    if (pin) {
        memset(pin, 0, MAX_PIN_LENGTH);
        free(pin);
        pin = NULL;
    }
    if (assert) {
        fido_assert_free(&assert);
        assert = NULL;
    }

    /* SECURITY: Use dedicated free function to prevent dangling pointers */
    free_credential(cred);
    cred = NULL;

    /* Wipe sensitive data */
    memset(cdh, 0, sizeof(cdh));

    return ret;
}

void print_usage(const char *program_name) {
    printf("Usage:\n");
    printf("  Generate and store a new passkey:\n");
    printf("    %s --generate_store <name>\n", program_name);
    printf("  Authenticate with stored passkey:\n");
    printf("    %s --authenticate <name>\n", program_name);
    printf("  Enable debug output:\n");
    printf("    Add --debug to any command\n");
}

int main(int argc, char *argv[]) {
    /* Variables declared at top */
    fido_dev_t *dev = NULL;
    int ret = 1;
    char *command = NULL;
    char *name = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            debug_enabled = 1;
        } else if (strcmp(argv[i], "--generate_store") == 0) {
            command = "generate";
            if (i + 1 < argc) {
                name = argv[++i];
            }
        } else if (strcmp(argv[i], "--authenticate") == 0) {
            command = "authenticate";
            if (i + 1 < argc) {
                name = argv[++i];
            }
        }
    }

    if (!command || !name) {
        print_usage(argv[0]);
        return 1;
    }

    fido_init(debug_enabled ? FIDO_DEBUG : 0);

    dev = fido_dev_new();
    if (!dev) {
        DEBUG_PRINT("Failed to allocate device\n");
        return 1;
    }

    /* SECURITY: Hardcoded device path - should be configurable */
    if (fido_dev_open(dev, "/dev/hidraw1") != FIDO_OK) {
        DEBUG_PRINT("Failed to open device /dev/hidraw1\n");
        goto cleanup;
    }

    DEBUG_PRINT("Device opened successfully\n");
    check_device_capabilities(dev);

    if (strcmp(command, "generate") == 0) {
        ret = generate_passkey(dev, name);
    } else if (strcmp(command, "authenticate") == 0) {
        ret = authenticate_credential(dev, name);
    }

cleanup:
    if (dev) {
        fido_dev_close(dev);
        fido_dev_free(&dev);
        dev = NULL;
    }

    return ret;
}
