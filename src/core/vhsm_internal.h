#ifndef VHSM_INTERNAL_H
#define VHSM_INTERNAL_H

#include "vhsm.h"
#include <pthread.h>

/* Forward declarations for internal structures */
typedef struct vhsm_key_entry_s vhsm_key_entry_t;
typedef struct vhsm_storage_ctx_s vhsm_storage_ctx_t;
typedef struct vhsm_auth_ctx_s vhsm_auth_ctx_t;
typedef struct vhsm_audit_ctx_s vhsm_audit_ctx_t;
typedef struct vhsm_session_data_s vhsm_session_data_t;

/* Internal context structure */
struct vhsm_context {
    char storage_path[VHSM_MAX_PATH];
    uint8_t master_key[VHSM_AES_256_KEY_SIZE];
    int master_key_set;
    pthread_mutex_t lock;
    vhsm_auth_ctx_t* auth_ctx;
    vhsm_storage_ctx_t* storage_ctx;
    vhsm_audit_ctx_t* audit_ctx;
};

/* Internal session structure */
struct vhsm_session_data_s {
    uint64_t session_id;
    char username[VHSM_MAX_USERNAME];
    vhsm_role_t role;
    time_t created;
    time_t last_activity;
    int active;
    void* ctx;
};

/* Internal helper functions */
vhsm_role_t vhsm_session_get_role(vhsm_session_t session);
const char* vhsm_session_get_username(vhsm_session_t session);
vhsm_error_t vhsm_audit_log(vhsm_audit_ctx_t* audit, vhsm_audit_event_t event,
                             const char* username, const char* details);

/* Storage initialization */
vhsm_storage_ctx_t* vhsm_storage_init(const char* storage_path, const uint8_t* master_key);
void vhsm_storage_cleanup(vhsm_storage_ctx_t* storage);

/* Auth initialization */
vhsm_auth_ctx_t* vhsm_auth_init(const char* storage_path);
void vhsm_auth_cleanup(vhsm_auth_ctx_t* auth);

/* Audit initialization */
vhsm_audit_ctx_t* vhsm_audit_init(const char* log_path);
void vhsm_audit_cleanup(vhsm_audit_ctx_t* audit);

#endif /* VHSM_INTERNAL_H */
