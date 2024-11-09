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

#define MAX_DEVICES 8
#define RPID "nyu.edu"
#define USER_ID "ah5647"
#define USER_NAME "Alon"
#define CREDENTIAL_LEN 32
#define MAX_PIN_LENGTH 64
#define STORAGE_DIR ".passkeys"
#define CRED_FILE "credentials.json"
#define CRED_TYPE_ES256 1

static int debug_enabled = 0;
#define DEBUG_PRINT(...) do { if (debug_enabled) printf(__VA_ARGS__); } while (0)

typedef struct {
    unsigned char *id;
    size_t id_len;
    char *name;
    char *rpid;
} credential_info_t;

char* get_pin(void);
int ensure_storage_dir(void);
int save_credential(const unsigned char *cred_id, size_t cred_len, const char *name);
credential_info_t *load_credential(const char *name);
void check_device_capabilities(fido_dev_t *dev);
int generate_passkey(fido_dev_t *dev, const char *name);
int authenticate_credential(fido_dev_t *dev, const char *name);

char* get_pin(void) {
    struct termios old_term, new_term;
    char* pin = malloc(MAX_PIN_LENGTH);
    if (pin == NULL) {
        DEBUG_PRINT("Failed to allocate PIN buffer\n");
        return NULL;
    }

    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    printf("Enter YubiKey PIN: ");
    if (fgets(pin, MAX_PIN_LENGTH, stdin) == NULL) {
        free(pin);
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        DEBUG_PRINT("Failed to read PIN\n");
        return NULL;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    printf("\n");

    pin[strcspn(pin, "\n")] = 0;
    return pin;
}

int ensure_storage_dir(void) {
    char *home = getenv("HOME");
    if (!home) {
        DEBUG_PRINT("Could not get HOME directory\n");
        return -1;
    }

    char storage_path[PATH_MAX];
    snprintf(storage_path, sizeof(storage_path), "%s/%s", home, STORAGE_DIR);

    struct stat st = {0};
    if (stat(storage_path, &st) == -1) {
        if (mkdir(storage_path, 0700) == -1) {
            DEBUG_PRINT("Could not create storage directory: %s\n", strerror(errno));
            return -1;
        }
    }

    return 0;
}

int save_credential(const unsigned char *cred_id, size_t cred_len, const char *name) {
    if (ensure_storage_dir() != 0) {
        return -1;
    }

    char *home = getenv("HOME");
    if (!home) return -1;

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/%s/%s", home, STORAGE_DIR, CRED_FILE);

    json_object *root = NULL;
    json_object *cred_obj = json_object_new_object();
    if (!cred_obj) return -1;

    char *b64_cred = malloc(cred_len * 2);
    if (!b64_cred) {
        json_object_put(cred_obj);
        return -1;
    }

    for (size_t i = 0; i < cred_len; i++) {
        sprintf(&b64_cred[i*2], "%02x", cred_id[i]);
    }

    json_object_object_add(cred_obj, "id", json_object_new_string(b64_cred));
    json_object_object_add(cred_obj, "rpid", json_object_new_string(RPID));
    free(b64_cred);

    struct stat st = {0};
    if (stat(file_path, &st) != -1) {
        json_object *existing = json_object_from_file(file_path);
        if (existing) root = existing;
    }

    if (!root) {
        root = json_object_new_object();
        if (!root) {
            json_object_put(cred_obj);
            return -1;
        }
    }

    json_object_object_add(root, name, cred_obj);

    if (json_object_to_file(file_path, root) != 0) {
        json_object_put(root);
        return -1;
    }

    json_object_put(root);
    return 0;
}

credential_info_t *load_credential(const char *name) {
    char *home = getenv("HOME");
    if (!home) return NULL;

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), "%s/%s/%s", home, STORAGE_DIR, CRED_FILE);

    json_object *root = json_object_from_file(file_path);
    if (!root) return NULL;

    json_object *cred_obj;
    if (!json_object_object_get_ex(root, name, &cred_obj)) {
        json_object_put(root);
        return NULL;
    }

    credential_info_t *cred = malloc(sizeof(credential_info_t));
    if (!cred) {
        json_object_put(root);
        return NULL;
    }

    json_object *id_obj, *rpid_obj;
    if (!json_object_object_get_ex(cred_obj, "id", &id_obj) ||
        !json_object_object_get_ex(cred_obj, "rpid", &rpid_obj)) {
        free(cred);
        json_object_put(root);
        return NULL;
    }

    const char *hex_id = json_object_get_string(id_obj);
    size_t hex_len = strlen(hex_id);
    cred->id_len = hex_len / 2;
    cred->id = malloc(cred->id_len);
    
    if (!cred->id) {
        free(cred);
        json_object_put(root);
        return NULL;
    }

    for (size_t i = 0; i < cred->id_len; i++) {
        sscanf(&hex_id[i*2], "%2hhx", &cred->id[i]);
    }

    cred->name = strdup(name);
    cred->rpid = strdup(json_object_get_string(rpid_obj));

    json_object_put(root);
    return cred;
}

void check_device_capabilities(fido_dev_t *dev) {
    if (!dev) return;

    DEBUG_PRINT("Device capabilities:\n");
    DEBUG_PRINT("  FIDO2 Support: %s\n", fido_dev_is_fido2(dev) ? "Yes" : "No");
    DEBUG_PRINT("  PIN Support: %s\n", fido_dev_has_pin(dev) ? "Yes" : "No");
}

int generate_passkey(fido_dev_t *dev, const char *name) {
    int ret = -1;
    fido_cred_t *cred = NULL;
    char *pin = NULL;
    unsigned char user_id[32];
    unsigned char cdh[32];
    const unsigned char *cred_id;
    size_t cred_len;
    int err;

    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom || fread(cdh, 1, sizeof(cdh), urandom) != sizeof(cdh)) {
        DEBUG_PRINT("Failed to generate challenge\n");
        if (urandom) fclose(urandom);
        goto cleanup;
    }
    fclose(urandom);

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
    if ((err = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK) {
        DEBUG_PRINT("Failed to make credential: %s\n", fido_strerr(err));
        goto cleanup;
    }

    cred_id = fido_cred_id_ptr(cred);
    cred_len = fido_cred_id_len(cred);

    if (save_credential(cred_id, cred_len, name) != 0) {
        DEBUG_PRINT("Failed to save credential\n");
        goto cleanup;
    }

    printf("Passkey generated and stored successfully\n");
    ret = 0;

cleanup:
    if (pin) {
        memset(pin, 0, strlen(pin));
        free(pin);
    }
    if (cred) fido_cred_free(&cred);
    return ret;
}

int authenticate_credential(fido_dev_t *dev, const char *name) {
    int ret = -1;
    fido_assert_t *assert = NULL;
    char *pin = NULL;
    unsigned char cdh[32];
    credential_info_t *cred = NULL;
    int err;

    cred = load_credential(name);
    if (!cred) {
        printf("Error: Credential with name '%s' not found. Cannot continue authentication.\n", name);
        return ret;
    }

    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom || fread(cdh, 1, sizeof(cdh), urandom) != sizeof(cdh)) {
        DEBUG_PRINT("Failed to generate challenge\n");
        if (urandom) fclose(urandom);
        goto cleanup;
    }
    fclose(urandom);

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
    if ((err = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK) {
        DEBUG_PRINT("Failed to get assertion: %s\n", fido_strerr(err));
        goto cleanup;
    }

    printf("Authentication successful\n");
    ret = 0;

cleanup:
    if (pin) {
        memset(pin, 0, strlen(pin));
        free(pin);
    }
    if (assert) fido_assert_free(&assert);
    if (cred) {
        if (cred->id) free(cred->id);
        if (cred->name) free(cred->name);
        if (cred->rpid) free(cred->rpid);
        free(cred);
    }
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
    fido_dev_t *dev = NULL;
    int ret = 1;
    char *command = NULL;
    char *name = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            debug_enabled = 1;
        } else if (strcmp(argv[i], "--generate_store") == 0) {
            command = "generate";
            if (i + 1 < argc) name = argv[++i];
        } else if (strcmp(argv[i], "--authenticate") == 0) {
            command = "authenticate";
            if (i + 1 < argc) name = argv[++i];
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
    }

    return ret;
}
