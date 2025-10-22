#include "vhsm.h"
#include "../utils/secure_memory.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#define SALT_SIZE 32
#define HASH_SIZE 64
#define MAX_USERS 1000
#define SESSION_TIMEOUT 3600  /* 1 hour */
#define MAX_SESSIONS 100

/* User structure */
typedef struct {
    char username[VHSM_MAX_USERNAME];
    uint8_t password_hash[HASH_SIZE];
    uint8_t password_salt[SALT_SIZE];
    uint8_t pin_hash[HASH_SIZE];
    uint8_t pin_salt[SALT_SIZE];
    vhsm_role_t role;
    int has_pin;
    int active;
    time_t created;
    time_t last_login;
    uint32_t failed_attempts;
} vhsm_user_t;

/* Session structure */
typedef struct {
    uint64_t session_id;
    char username[VHSM_MAX_USERNAME];
    vhsm_role_t role;
    time_t created;
    time_t last_activity;
    int active;
    void* ctx;
} vhsm_session_data_t;

/* Auth context */
typedef struct {
    char storage_path[VHSM_MAX_PATH];
    vhsm_user_t users[MAX_USERS];
    int user_count;
    vhsm_session_data_t sessions[MAX_SESSIONS];
    pthread_mutex_t lock;
    uint64_t next_session_id;
} vhsm_auth_ctx_t;

/* Helper functions */
static int hash_password(const char* password, const uint8_t* salt, uint8_t* hash) {
    unsigned int hash_len = HASH_SIZE;
    return PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE,
                             100000, EVP_sha512(), HASH_SIZE, hash) == 1;
}

static int verify_password(const char* password, const uint8_t* salt, const uint8_t* expected_hash) {
    uint8_t hash[HASH_SIZE];
    if (!hash_password(password, salt, hash)) {
        return 0;
    }

    int match = (memcmp(hash, expected_hash, HASH_SIZE) == 0);
    secure_wipe(hash, sizeof(hash));
    return match;
}

static vhsm_user_t* find_user(vhsm_auth_ctx_t* auth, const char* username) {
    for (int i = 0; i < auth->user_count; i++) {
        if (auth->users[i].active && strcmp(auth->users[i].username, username) == 0) {
            return &auth->users[i];
        }
    }
    return NULL;
}

static int save_users(vhsm_auth_ctx_t* auth) {
    char path[VHSM_MAX_PATH];
    snprintf(path, sizeof(path), "%s/users.dat", auth->storage_path);

    FILE* fp = fopen(path, "wb");
    if (!fp) {
        return 0;
    }

    /* Write user count */
    fwrite(&auth->user_count, sizeof(int), 1, fp);

    /* Write users */
    for (int i = 0; i < auth->user_count; i++) {
        fwrite(&auth->users[i], sizeof(vhsm_user_t), 1, fp);
    }

    fclose(fp);
    chmod(path, 0600);
    return 1;
}

static int load_users(vhsm_auth_ctx_t* auth) {
    char path[VHSM_MAX_PATH];
    snprintf(path, sizeof(path), "%s/users.dat", auth->storage_path);

    FILE* fp = fopen(path, "rb");
    if (!fp) {
        /* File doesn't exist yet */
        auth->user_count = 0;
        return 1;
    }

    /* Read user count */
    if (fread(&auth->user_count, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return 0;
    }

    /* Validate count */
    if (auth->user_count < 0 || auth->user_count > MAX_USERS) {
        fclose(fp);
        return 0;
    }

    /* Read users */
    for (int i = 0; i < auth->user_count; i++) {
        if (fread(&auth->users[i], sizeof(vhsm_user_t), 1, fp) != 1) {
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return 1;
}

/* Public API */
vhsm_auth_ctx_t* vhsm_auth_init(const char* storage_path) {
    vhsm_auth_ctx_t* auth = calloc(1, sizeof(vhsm_auth_ctx_t));
    if (!auth) {
        return NULL;
    }

    strncpy(auth->storage_path, storage_path, VHSM_MAX_PATH - 1);
    pthread_mutex_init(&auth->lock, NULL);
    auth->next_session_id = 1;

    /* Load existing users */
    if (!load_users(auth)) {
        pthread_mutex_destroy(&auth->lock);
        free(auth);
        return NULL;
    }

    return auth;
}

void vhsm_auth_cleanup(vhsm_auth_ctx_t* auth) {
    if (!auth) {
        return;
    }

    /* Invalidate all sessions */
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (auth->sessions[i].active) {
            auth->sessions[i].active = 0;
            secure_wipe(&auth->sessions[i], sizeof(vhsm_session_data_t));
        }
    }

    /* Wipe sensitive data */
    secure_wipe(auth->users, sizeof(auth->users));

    pthread_mutex_destroy(&auth->lock);
    free(auth);
}

vhsm_error_t vhsm_user_create(vhsm_ctx_t ctx, const char* username,
                               const char* password, const char* pin,
                               vhsm_role_t role) {
    if (!ctx || !username || !password) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;
    vhsm_auth_ctx_t* auth = (vhsm_auth_ctx_t*)context->auth_ctx;

    if (!auth) {
        /* Initialize auth context if not already */
        auth = vhsm_auth_init(context->storage_path);
        if (!auth) {
            return VHSM_ERROR_OUT_OF_MEMORY;
        }
        context->auth_ctx = auth;
    }

    pthread_mutex_lock(&auth->lock);

    /* Check if user already exists */
    if (find_user(auth, username)) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_KEY_EXISTS;  /* Reuse error code */
    }

    /* Check capacity */
    if (auth->user_count >= MAX_USERS) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    /* Create new user */
    vhsm_user_t* user = &auth->users[auth->user_count];
    memset(user, 0, sizeof(vhsm_user_t));

    strncpy(user->username, username, VHSM_MAX_USERNAME - 1);
    user->role = role;
    user->active = 1;
    user->created = time(NULL);
    user->failed_attempts = 0;

    /* Generate password salt and hash */
    if (RAND_bytes(user->password_salt, SALT_SIZE) != 1) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    if (!hash_password(password, user->password_salt, user->password_hash)) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    /* Handle PIN if provided */
    if (pin && strlen(pin) > 0) {
        if (RAND_bytes(user->pin_salt, SALT_SIZE) != 1) {
            pthread_mutex_unlock(&auth->lock);
            return VHSM_ERROR_CRYPTO_FAILED;
        }

        if (!hash_password(pin, user->pin_salt, user->pin_hash)) {
            pthread_mutex_unlock(&auth->lock);
            return VHSM_ERROR_CRYPTO_FAILED;
        }

        user->has_pin = 1;
    } else {
        user->has_pin = 0;
    }

    auth->user_count++;

    /* Save users */
    if (!save_users(auth)) {
        auth->user_count--;
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_IO_FAILED;
    }

    pthread_mutex_unlock(&auth->lock);
    return VHSM_SUCCESS;
}

vhsm_error_t vhsm_user_delete(vhsm_ctx_t ctx, const char* username) {
    if (!ctx || !username) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;
    vhsm_auth_ctx_t* auth = (vhsm_auth_ctx_t*)context->auth_ctx;

    if (!auth) {
        return VHSM_ERROR_NOT_INITIALIZED;
    }

    pthread_mutex_lock(&auth->lock);

    vhsm_user_t* user = find_user(auth, username);
    if (!user) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_KEY_NOT_FOUND;
    }

    /* Mark as inactive and wipe */
    user->active = 0;
    secure_wipe(user, sizeof(vhsm_user_t));

    /* Save users */
    save_users(auth);

    pthread_mutex_unlock(&auth->lock);
    return VHSM_SUCCESS;
}

vhsm_error_t vhsm_user_change_password(vhsm_ctx_t ctx, const char* username,
                                        const char* old_password,
                                        const char* new_password) {
    if (!ctx || !username || !old_password || !new_password) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;
    vhsm_auth_ctx_t* auth = (vhsm_auth_ctx_t*)context->auth_ctx;

    if (!auth) {
        return VHSM_ERROR_NOT_INITIALIZED;
    }

    pthread_mutex_lock(&auth->lock);

    vhsm_user_t* user = find_user(auth, username);
    if (!user) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_KEY_NOT_FOUND;
    }

    /* Verify old password */
    if (!verify_password(old_password, user->password_salt, user->password_hash)) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_AUTH_FAILED;
    }

    /* Generate new salt and hash */
    if (RAND_bytes(user->password_salt, SALT_SIZE) != 1) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    if (!hash_password(new_password, user->password_salt, user->password_hash)) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    /* Save users */
    save_users(auth);

    pthread_mutex_unlock(&auth->lock);
    return VHSM_SUCCESS;
}

vhsm_error_t vhsm_session_login(vhsm_ctx_t ctx, vhsm_session_t* session,
                                 const char* username, const char* password,
                                 const char* pin) {
    if (!ctx || !session || !username || !password) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;
    vhsm_auth_ctx_t* auth = (vhsm_auth_ctx_t*)context->auth_ctx;

    if (!auth) {
        return VHSM_ERROR_NOT_INITIALIZED;
    }

    pthread_mutex_lock(&auth->lock);

    vhsm_user_t* user = find_user(auth, username);
    if (!user) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_AUTH_FAILED;
    }

    /* Verify password */
    if (!verify_password(password, user->password_salt, user->password_hash)) {
        user->failed_attempts++;
        save_users(auth);
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_AUTH_FAILED;
    }

    /* Verify PIN if required */
    if (user->has_pin) {
        if (!pin) {
            pthread_mutex_unlock(&auth->lock);
            return VHSM_ERROR_AUTH_FAILED;
        }

        if (!verify_password(pin, user->pin_salt, user->pin_hash)) {
            user->failed_attempts++;
            save_users(auth);
            pthread_mutex_unlock(&auth->lock);
            return VHSM_ERROR_AUTH_FAILED;
        }
    }

    /* Find available session slot */
    vhsm_session_data_t* sess = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!auth->sessions[i].active) {
            sess = &auth->sessions[i];
            break;
        }
    }

    if (!sess) {
        pthread_mutex_unlock(&auth->lock);
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    /* Create session */
    memset(sess, 0, sizeof(vhsm_session_data_t));
    sess->session_id = auth->next_session_id++;
    strncpy(sess->username, username, VHSM_MAX_USERNAME - 1);
    sess->role = user->role;
    sess->created = time(NULL);
    sess->last_activity = sess->created;
    sess->active = 1;
    sess->ctx = ctx;

    /* Update user */
    user->last_login = time(NULL);
    user->failed_attempts = 0;
    save_users(auth);

    *session = sess;
    pthread_mutex_unlock(&auth->lock);

    return VHSM_SUCCESS;
}

void vhsm_session_logout(vhsm_session_t session) {
    if (!session) {
        return;
    }

    vhsm_session_data_t* sess = (vhsm_session_data_t*)session;
    struct vhsm_context* context = (struct vhsm_context*)sess->ctx;

    if (!context || !context->auth_ctx) {
        return;
    }

    vhsm_auth_ctx_t* auth = (vhsm_auth_ctx_t*)context->auth_ctx;

    pthread_mutex_lock(&auth->lock);
    sess->active = 0;
    secure_wipe(sess, sizeof(vhsm_session_data_t));
    pthread_mutex_unlock(&auth->lock);
}

int vhsm_session_is_valid(vhsm_session_t session) {
    if (!session) {
        return 0;
    }

    vhsm_session_data_t* sess = (vhsm_session_data_t*)session;

    if (!sess->active) {
        return 0;
    }

    /* Check session timeout */
    time_t now = time(NULL);
    if (now - sess->last_activity > SESSION_TIMEOUT) {
        sess->active = 0;
        return 0;
    }

    /* Update last activity */
    sess->last_activity = now;

    return 1;
}

/* Internal helper to get session role */
vhsm_role_t vhsm_session_get_role(vhsm_session_t session) {
    if (!session) {
        return VHSM_ROLE_NONE;
    }

    vhsm_session_data_t* sess = (vhsm_session_data_t*)session;
    return sess->role;
}

/* Internal helper to get session username */
const char* vhsm_session_get_username(vhsm_session_t session) {
    if (!session) {
        return NULL;
    }

    vhsm_session_data_t* sess = (vhsm_session_data_t*)session;
    return sess->username;
}
