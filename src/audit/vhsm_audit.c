#include "vhsm.h"
#include "../core/vhsm_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

#define MAX_LOG_ENTRY 2048

/* Audit context - matches forward declaration in vhsm_internal.h */
struct vhsm_audit_ctx_s {
    char log_path[VHSM_MAX_PATH];
    FILE* log_file;
    pthread_mutex_t lock;
    int enabled;
};

/* Get event type string */
static const char* event_type_str(vhsm_audit_event_t type) {
    switch (type) {
        case VHSM_AUDIT_LOGIN: return "LOGIN";
        case VHSM_AUDIT_LOGOUT: return "LOGOUT";
        case VHSM_AUDIT_AUTH_FAILED: return "AUTH_FAILED";
        case VHSM_AUDIT_KEY_GENERATED: return "KEY_GENERATED";
        case VHSM_AUDIT_KEY_IMPORTED: return "KEY_IMPORTED";
        case VHSM_AUDIT_KEY_EXPORTED: return "KEY_EXPORTED";
        case VHSM_AUDIT_KEY_DELETED: return "KEY_DELETED";
        case VHSM_AUDIT_KEY_ROTATED: return "KEY_ROTATED";
        case VHSM_AUDIT_KEY_REVOKED: return "KEY_REVOKED";
        case VHSM_AUDIT_ENCRYPT: return "ENCRYPT";
        case VHSM_AUDIT_DECRYPT: return "DECRYPT";
        case VHSM_AUDIT_SIGN: return "SIGN";
        case VHSM_AUDIT_VERIFY: return "VERIFY";
        case VHSM_AUDIT_FILE_STORE: return "FILE_STORE";
        case VHSM_AUDIT_FILE_RETRIEVE: return "FILE_RETRIEVE";
        case VHSM_AUDIT_CONFIG_CHANGED: return "CONFIG_CHANGED";
        case VHSM_AUDIT_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

/* Initialize audit system */
vhsm_audit_ctx_t* vhsm_audit_init(const char* log_path) {
    if (!log_path) {
        return NULL;
    }

    vhsm_audit_ctx_t* audit = calloc(1, sizeof(vhsm_audit_ctx_t));
    if (!audit) {
        return NULL;
    }

    strncpy(audit->log_path, log_path, VHSM_MAX_PATH - 1);
    pthread_mutex_init(&audit->lock, NULL);
    audit->enabled = 0;
    audit->log_file = NULL;

    return audit;
}

/* Cleanup audit system */
void vhsm_audit_cleanup(vhsm_audit_ctx_t* audit) {
    if (!audit) {
        return;
    }

    pthread_mutex_lock(&audit->lock);
    if (audit->log_file) {
        fclose(audit->log_file);
        audit->log_file = NULL;
    }
    audit->enabled = 0;
    pthread_mutex_unlock(&audit->lock);

    pthread_mutex_destroy(&audit->lock);
    free(audit);
}

/* Enable audit logging */
vhsm_error_t vhsm_audit_enable(vhsm_ctx_t ctx, const char* log_path) {
    if (!ctx || !log_path) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;
    vhsm_audit_ctx_t* audit = (vhsm_audit_ctx_t*)context->audit_ctx;

    if (!audit) {
        audit = vhsm_audit_init(log_path);
        if (!audit) {
            return VHSM_ERROR_OUT_OF_MEMORY;
        }
        context->audit_ctx = audit;
    }

    pthread_mutex_lock(&audit->lock);

    /* Close existing log if open */
    if (audit->log_file) {
        fclose(audit->log_file);
    }

    /* Open log file in append mode */
    audit->log_file = fopen(log_path, "a");
    if (!audit->log_file) {
        pthread_mutex_unlock(&audit->lock);
        return VHSM_ERROR_IO_FAILED;
    }

    /* Set restrictive permissions */
    chmod(log_path, 0600);

    audit->enabled = 1;

    pthread_mutex_unlock(&audit->lock);

    return VHSM_SUCCESS;
}

/* Disable audit logging */
void vhsm_audit_disable(vhsm_ctx_t ctx) {
    if (!ctx) {
        return;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;
    vhsm_audit_ctx_t* audit = (vhsm_audit_ctx_t*)context->audit_ctx;

    if (!audit) {
        return;
    }

    pthread_mutex_lock(&audit->lock);
    if (audit->log_file) {
        fclose(audit->log_file);
        audit->log_file = NULL;
    }
    audit->enabled = 0;
    pthread_mutex_unlock(&audit->lock);
}

/* Log an audit event */
vhsm_error_t vhsm_audit_log(vhsm_audit_ctx_t* audit, vhsm_audit_event_t event,
                             const char* username, const char* details) {
    if (!audit || !audit->enabled) {
        return VHSM_SUCCESS;  /* Not an error if audit is disabled */
    }

    pthread_mutex_lock(&audit->lock);

    if (!audit->log_file) {
        pthread_mutex_unlock(&audit->lock);
        return VHSM_ERROR_AUDIT_FAILED;
    }

    /* Get current timestamp */
    time_t now = time(NULL);
    struct tm* tm_info = gmtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC", tm_info);

    /* Format log entry */
    char entry[MAX_LOG_ENTRY];
    snprintf(entry, sizeof(entry), "[%s] %s user=%s %s\n",
             timestamp, event_type_str(event),
             username ? username : "SYSTEM",
             details ? details : "");

    /* Write to log */
    if (fputs(entry, audit->log_file) == EOF) {
        pthread_mutex_unlock(&audit->lock);
        return VHSM_ERROR_AUDIT_FAILED;
    }

    /* Flush to ensure it's written */
    fflush(audit->log_file);

    pthread_mutex_unlock(&audit->lock);
    return VHSM_SUCCESS;
}

/* Query audit log */
vhsm_error_t vhsm_audit_query(vhsm_ctx_t ctx, time_t start_time, time_t end_time,
                               vhsm_audit_event_t event_type, const char* username,
                               void (*callback)(const char* entry, void* user_data),
                               void* user_data) {
    if (!ctx || !callback) {
        return VHSM_ERROR_INVALID_PARAM;
    }

    struct vhsm_context* context = (struct vhsm_context*)ctx;
    vhsm_audit_ctx_t* audit = (vhsm_audit_ctx_t*)context->audit_ctx;

    if (!audit) {
        return VHSM_ERROR_NOT_INITIALIZED;
    }

    pthread_mutex_lock(&audit->lock);

    /* Open log file for reading */
    FILE* fp = fopen(audit->log_path, "r");
    if (!fp) {
        pthread_mutex_unlock(&audit->lock);
        return VHSM_ERROR_IO_FAILED;
    }

    char line[MAX_LOG_ENTRY];
    while (fgets(line, sizeof(line), fp)) {
        /* Simple filtering - could be enhanced with timestamp parsing */

        /* Filter by event type if specified */
        if (event_type != VHSM_AUDIT_NONE) {
            const char* event_str = event_type_str(event_type);
            if (!strstr(line, event_str)) {
                continue;
            }
        }

        /* Filter by username if specified */
        if (username) {
            char user_pattern[128];
            snprintf(user_pattern, sizeof(user_pattern), "user=%s", username);
            if (!strstr(line, user_pattern)) {
                continue;
            }
        }

        /* Call callback with matching entry */
        callback(line, user_data);
    }

    fclose(fp);
    pthread_mutex_unlock(&audit->lock);

    return VHSM_SUCCESS;
}
