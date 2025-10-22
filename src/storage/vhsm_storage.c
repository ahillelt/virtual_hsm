#include "vhsm.h"
#include "../core/vhsm_internal.h"
#include "../utils/secure_memory.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#define MAX_KEY_DATA_SIZE 8192

/* Internal key structure */
struct vhsm_key_entry_s {
    vhsm_key_handle_t handle;
    vhsm_key_metadata_t metadata;
    uint8_t* encrypted_data;
    size_t encrypted_len;
    uint8_t iv[VHSM_GCM_IV_SIZE];
    uint8_t tag[VHSM_GCM_TAG_SIZE];
    uint8_t* public_key_data;
    size_t public_key_len;
    int allocated;
};

/* Storage context - matches forward declaration in vhsm_internal.h */
struct vhsm_storage_ctx_s {
    char storage_path[VHSM_MAX_PATH];
    vhsm_key_entry_t keys[VHSM_MAX_KEYS];
    int key_count;
    pthread_mutex_t lock;
    uint64_t next_handle;
    uint8_t* master_key;
};

/* Helper: Encrypt key data */
static vhsm_error_t encrypt_key_data(const uint8_t* master_key,
                                      const uint8_t* plaintext, size_t plaintext_len,
                                      uint8_t* ciphertext, size_t* ciphertext_len,
                                      uint8_t* iv, uint8_t* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    /* Generate random IV */
    if (RAND_bytes(iv, VHSM_GCM_IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    int len;
    size_t total_len = 0;

    /* Encrypt data */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }
    total_len += len;

    /* Finalize encryption */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }
    total_len += len;

    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, VHSM_GCM_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return VHSM_SUCCESS;
}

/* Helper: Decrypt key data */
static vhsm_error_t decrypt_key_data(const uint8_t* master_key,
                                      const uint8_t* ciphertext, size_t ciphertext_len,
                                      uint8_t* plaintext, size_t* plaintext_len,
                                      const uint8_t* iv, const uint8_t* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    int len;
    size_t total_len = 0;

    /* Decrypt data */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }
    total_len += len;

    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, VHSM_GCM_TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }

    /* Finalize decryption (verifies tag) */
    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return VHSM_ERROR_CRYPTO_FAILED;
    }
    total_len += len;

    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return VHSM_SUCCESS;
}

/* Helper: Save keystore */
static vhsm_error_t save_keystore(vhsm_storage_ctx_t* storage) {
    char path[VHSM_MAX_PATH];
    snprintf(path, sizeof(path), "%s/keystore.dat", storage->storage_path);

    FILE* fp = fopen(path, "wb");
    if (!fp) {
        return VHSM_ERROR_IO_FAILED;
    }

    /* Write version and key count */
    uint32_t version = 2;
    fwrite(&version, sizeof(uint32_t), 1, fp);
    fwrite(&storage->key_count, sizeof(int), 1, fp);

    /* Write each key */
    for (int i = 0; i < VHSM_MAX_KEYS; i++) {
        if (!storage->keys[i].allocated) {
            continue;
        }

        vhsm_key_entry_t* key = &storage->keys[i];

        /* Write metadata */
        fwrite(&key->handle, sizeof(uint64_t), 1, fp);
        fwrite(&key->metadata, sizeof(vhsm_key_metadata_t), 1, fp);

        /* Write encrypted data */
        fwrite(&key->encrypted_len, sizeof(size_t), 1, fp);
        fwrite(key->encrypted_data, 1, key->encrypted_len, fp);
        fwrite(key->iv, 1, VHSM_GCM_IV_SIZE, fp);
        fwrite(key->tag, 1, VHSM_GCM_TAG_SIZE, fp);

        /* Write public key if present */
        fwrite(&key->public_key_len, sizeof(size_t), 1, fp);
        if (key->public_key_len > 0) {
            fwrite(key->public_key_data, 1, key->public_key_len, fp);
        }
    }

    fclose(fp);
    chmod(path, 0600);
    return VHSM_SUCCESS;
}

/* Helper: Load keystore */
static vhsm_error_t load_keystore(vhsm_storage_ctx_t* storage) {
    char path[VHSM_MAX_PATH];
    snprintf(path, sizeof(path), "%s/keystore.dat", storage->storage_path);

    FILE* fp = fopen(path, "rb");
    if (!fp) {
        /* File doesn't exist yet */
        storage->key_count = 0;
        return VHSM_SUCCESS;
    }

    /* Read version and key count */
    uint32_t version;
    if (fread(&version, sizeof(uint32_t), 1, fp) != 1) {
        fclose(fp);
        return VHSM_ERROR_INVALID_FORMAT;
    }

    if (version != 2) {
        fclose(fp);
        return VHSM_ERROR_INVALID_FORMAT;
    }

    if (fread(&storage->key_count, sizeof(int), 1, fp) != 1) {
        fclose(fp);
        return VHSM_ERROR_INVALID_FORMAT;
    }

    if (storage->key_count < 0 || storage->key_count > VHSM_MAX_KEYS) {
        fclose(fp);
        return VHSM_ERROR_INVALID_FORMAT;
    }

    /* Read each key */
    for (int i = 0; i < storage->key_count; i++) {
        vhsm_key_entry_t* key = &storage->keys[i];

        /* Read metadata */
        if (fread(&key->handle, sizeof(uint64_t), 1, fp) != 1 ||
            fread(&key->metadata, sizeof(vhsm_key_metadata_t), 1, fp) != 1) {
            fclose(fp);
            return VHSM_ERROR_INVALID_FORMAT;
        }

        /* Read encrypted data */
        if (fread(&key->encrypted_len, sizeof(size_t), 1, fp) != 1) {
            fclose(fp);
            return VHSM_ERROR_INVALID_FORMAT;
        }

        if (key->encrypted_len > MAX_KEY_DATA_SIZE) {
            fclose(fp);
            return VHSM_ERROR_INVALID_FORMAT;
        }

        key->encrypted_data = malloc(key->encrypted_len);
        if (!key->encrypted_data) {
            fclose(fp);
            return VHSM_ERROR_OUT_OF_MEMORY;
        }

        if (fread(key->encrypted_data, 1, key->encrypted_len, fp) != key->encrypted_len ||
            fread(key->iv, 1, VHSM_GCM_IV_SIZE, fp) != VHSM_GCM_IV_SIZE ||
            fread(key->tag, 1, VHSM_GCM_TAG_SIZE, fp) != VHSM_GCM_TAG_SIZE) {
            free(key->encrypted_data);
            fclose(fp);
            return VHSM_ERROR_INVALID_FORMAT;
        }

        /* Read public key if present */
        if (fread(&key->public_key_len, sizeof(size_t), 1, fp) != 1) {
            free(key->encrypted_data);
            fclose(fp);
            return VHSM_ERROR_INVALID_FORMAT;
        }

        if (key->public_key_len > 0) {
            if (key->public_key_len > MAX_KEY_DATA_SIZE) {
                free(key->encrypted_data);
                fclose(fp);
                return VHSM_ERROR_INVALID_FORMAT;
            }

            key->public_key_data = malloc(key->public_key_len);
            if (!key->public_key_data) {
                free(key->encrypted_data);
                fclose(fp);
                return VHSM_ERROR_OUT_OF_MEMORY;
            }

            if (fread(key->public_key_data, 1, key->public_key_len, fp) != key->public_key_len) {
                free(key->encrypted_data);
                free(key->public_key_data);
                fclose(fp);
                return VHSM_ERROR_INVALID_FORMAT;
            }
        } else {
            key->public_key_data = NULL;
        }

        key->allocated = 1;

        /* Update next_handle */
        if (key->handle >= storage->next_handle) {
            storage->next_handle = key->handle + 1;
        }
    }

    fclose(fp);
    return VHSM_SUCCESS;
}

/* Public API */
vhsm_storage_ctx_t* vhsm_storage_init(const char* storage_path, const uint8_t* master_key) {
    vhsm_storage_ctx_t* storage = calloc(1, sizeof(vhsm_storage_ctx_t));
    if (!storage) {
        return NULL;
    }

    strncpy(storage->storage_path, storage_path, VHSM_MAX_PATH - 1);
    pthread_mutex_init(&storage->lock, NULL);
    storage->next_handle = 1;
    storage->master_key = (uint8_t*)master_key;

    /* Load existing keystore */
    if (load_keystore(storage) != VHSM_SUCCESS) {
        pthread_mutex_destroy(&storage->lock);
        free(storage);
        return NULL;
    }

    return storage;
}

void vhsm_storage_cleanup(vhsm_storage_ctx_t* storage) {
    if (!storage) {
        return;
    }

    /* Free all keys */
    for (int i = 0; i < VHSM_MAX_KEYS; i++) {
        if (storage->keys[i].allocated) {
            if (storage->keys[i].encrypted_data) {
                secure_wipe(storage->keys[i].encrypted_data, storage->keys[i].encrypted_len);
                free(storage->keys[i].encrypted_data);
            }
            if (storage->keys[i].public_key_data) {
                free(storage->keys[i].public_key_data);
            }
        }
    }

    pthread_mutex_destroy(&storage->lock);
    free(storage);
}

vhsm_error_t vhsm_key_generate(vhsm_session_t session, const char* name,
                                vhsm_key_type_t type, vhsm_key_usage_t usage,
                                vhsm_key_handle_t* handle) {
    if (!session || !name || !handle) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    if (!vhsm_session_is_valid(session)) {
        return VHSM_ERROR_SESSION_INVALID;
    }

    vhsm_session_data_t* sess = (vhsm_session_data_t*)session;
    struct vhsm_context* ctx = (struct vhsm_context*)sess->ctx;
    vhsm_storage_ctx_t* storage = (vhsm_storage_ctx_t*)ctx->storage_ctx;

    if (!storage) {
        /* Initialize storage if not already */
        storage = vhsm_storage_init(ctx->storage_path, ctx->master_key);
        if (!storage) {
            return VHSM_ERROR_OUT_OF_MEMORY;
        }
        ctx->storage_ctx = storage;
    }

    pthread_mutex_lock(&storage->lock);

    /* Check if key with name already exists */
    for (int i = 0; i < VHSM_MAX_KEYS; i++) {
        if (storage->keys[i].allocated &&
            strcmp(storage->keys[i].metadata.name, name) == 0 &&
            storage->keys[i].metadata.state != VHSM_KEY_STATE_REVOKED) {
            pthread_mutex_unlock(&storage->lock);
            return VHSM_ERROR_KEY_EXISTS;
        }
    }

    /* Find available slot */
    int slot = -1;
    for (int i = 0; i < VHSM_MAX_KEYS; i++) {
        if (!storage->keys[i].allocated) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        pthread_mutex_unlock(&storage->lock);
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    vhsm_key_entry_t* key = &storage->keys[slot];
    memset(key, 0, sizeof(vhsm_key_entry_t));

    /* Set metadata */
    strncpy(key->metadata.name, name, VHSM_MAX_KEY_NAME - 1);
    key->metadata.type = type;
    key->metadata.usage = usage;
    key->metadata.state = VHSM_KEY_STATE_ACTIVE;
    key->metadata.created = time(NULL);
    key->metadata.expires = 0;
    key->metadata.last_used = 0;
    key->metadata.use_count = 0;
    key->metadata.version = 1;
    key->metadata.is_public = 0;
    key->metadata.exportable = 0;

    /* Generate key based on type */
    uint8_t key_data[MAX_KEY_DATA_SIZE];
    size_t key_data_len = 0;

    vhsm_error_t result = VHSM_SUCCESS;

    switch (type) {
        case VHSM_KEY_TYPE_AES_128:
            if (RAND_bytes(key_data, 16) != 1) {
                result = VHSM_ERROR_CRYPTO_FAILED;
            }
            key_data_len = 16;
            break;

        case VHSM_KEY_TYPE_AES_256:
            if (RAND_bytes(key_data, 32) != 1) {
                result = VHSM_ERROR_CRYPTO_FAILED;
            }
            key_data_len = 32;
            break;

        case VHSM_KEY_TYPE_ED25519: {
            EVP_PKEY* pkey = NULL;
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
            if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
                EVP_PKEY_keygen(pctx, &pkey) <= 0) {
                if (pctx) EVP_PKEY_CTX_free(pctx);
                result = VHSM_ERROR_CRYPTO_FAILED;
                break;
            }
            EVP_PKEY_CTX_free(pctx);

            /* Extract private key */
            size_t priv_len = 32;
            if (EVP_PKEY_get_raw_private_key(pkey, key_data, &priv_len) <= 0) {
                EVP_PKEY_free(pkey);
                result = VHSM_ERROR_CRYPTO_FAILED;
                break;
            }
            key_data_len = priv_len;

            /* Extract public key */
            uint8_t pub_key[32];
            size_t pub_len = 32;
            if (EVP_PKEY_get_raw_public_key(pkey, pub_key, &pub_len) <= 0) {
                EVP_PKEY_free(pkey);
                result = VHSM_ERROR_CRYPTO_FAILED;
                break;
            }

            key->public_key_len = pub_len;
            key->public_key_data = malloc(pub_len);
            if (!key->public_key_data) {
                EVP_PKEY_free(pkey);
                result = VHSM_ERROR_OUT_OF_MEMORY;
                break;
            }
            memcpy(key->public_key_data, pub_key, pub_len);

            EVP_PKEY_free(pkey);
            break;
        }

        case VHSM_KEY_TYPE_HMAC_SHA256:
        case VHSM_KEY_TYPE_HMAC_SHA512:
            if (RAND_bytes(key_data, 64) != 1) {
                result = VHSM_ERROR_CRYPTO_FAILED;
            }
            key_data_len = 64;
            break;

        default:
            result = VHSM_ERROR_NOT_IMPLEMENTED;
            break;
    }

    if (result != VHSM_SUCCESS) {
        pthread_mutex_unlock(&storage->lock);
        return result;
    }

    /* Encrypt key data */
    uint8_t encrypted[MAX_KEY_DATA_SIZE];
    size_t encrypted_len = 0;

    result = encrypt_key_data(storage->master_key, key_data, key_data_len,
                              encrypted, &encrypted_len, key->iv, key->tag);

    /* Wipe plaintext key */
    secure_wipe(key_data, sizeof(key_data));

    if (result != VHSM_SUCCESS) {
        pthread_mutex_unlock(&storage->lock);
        return result;
    }

    /* Store encrypted key */
    key->encrypted_data = malloc(encrypted_len);
    if (!key->encrypted_data) {
        if (key->public_key_data) {
            free(key->public_key_data);
        }
        pthread_mutex_unlock(&storage->lock);
        return VHSM_ERROR_OUT_OF_MEMORY;
    }

    memcpy(key->encrypted_data, encrypted, encrypted_len);
    key->encrypted_len = encrypted_len;

    /* Assign handle */
    key->handle = storage->next_handle++;
    key->allocated = 1;

    storage->key_count++;

    /* Save keystore */
    save_keystore(storage);

    *handle = key->handle;

    pthread_mutex_unlock(&storage->lock);
    return VHSM_SUCCESS;
}

/* Continue in next file due to length... */
