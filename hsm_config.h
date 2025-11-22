#ifndef HSM_CONFIG_H
#define HSM_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Default configuration values
#define DEFAULT_CONFIG_FILE "hsm_config.conf"
#define DEFAULT_KEY_ROTATION_DAYS 90
#define DEFAULT_MAX_KEY_AGE_DAYS 365
#define DEFAULT_SESSION_TIMEOUT_SECONDS 3600
#define DEFAULT_MAX_FAILED_AUTH_ATTEMPTS 3
#define DEFAULT_AUDIT_LOG_FILE "hsm_audit.log"
#define DEFAULT_STORAGE_PATH "."

// HSM Configuration Structure
typedef struct {
    // Key rotation settings
    int key_rotation_days;          // Days before automatic key rotation
    int max_key_age_days;            // Maximum key age before forced rotation
    int rotation_enabled;            // Enable/disable automatic rotation

    // Session management
    int session_timeout_seconds;     // Session timeout in seconds
    int max_concurrent_sessions;     // Maximum concurrent sessions (0 = unlimited)

    // Security settings
    int max_failed_auth_attempts;    // Max failed auth before lockout
    int lockout_duration_seconds;    // Account lockout duration
    int require_pin;                 // Require PIN for operations
    int password_min_length;         // Minimum password length

    // Audit settings
    char audit_log_file[256];        // Audit log file path
    int audit_enabled;               // Enable/disable audit logging
    int audit_log_max_size_mb;       // Max audit log size before rotation

    // Storage settings
    char storage_path[256];          // HSM storage directory
    int storage_encryption;          // Encrypt storage at rest

    // Backup settings
    int backup_enabled;              // Enable automatic backups
    int backup_interval_hours;       // Backup interval in hours
    char backup_path[256];           // Backup directory

    // Advanced settings
    int fips_mode;                   // FIPS 140-2 compliance mode
    int hardware_rng;                // Use hardware RNG if available
    int secure_memory;               // Use locked memory for keys
} HSMConfig;

// Global configuration
extern HSMConfig g_hsm_config;

// Configuration management functions

/**
 * Initialize configuration with default values
 */
void hsm_config_init_defaults(HSMConfig *config);

/**
 * Load configuration from file
 *
 * @param config Configuration structure to populate
 * @param filename Configuration file path
 * @return 0 on success, -1 on error
 */
int hsm_config_load(HSMConfig *config, const char *filename);

/**
 * Save configuration to file
 *
 * @param config Configuration structure to save
 * @param filename Configuration file path
 * @return 0 on success, -1 on error
 */
int hsm_config_save(const HSMConfig *config, const char *filename);

/**
 * Set key rotation period
 *
 * @param days Number of days before key rotation
 * @return 0 on success, -1 on error
 */
int hsm_config_set_rotation_period(int days);

/**
 * Get key rotation period
 *
 * @return Number of days before key rotation
 */
int hsm_config_get_rotation_period(void);

/**
 * Enable/disable automatic key rotation
 *
 * @param enabled 1 to enable, 0 to disable
 * @return 0 on success, -1 on error
 */
int hsm_config_set_rotation_enabled(int enabled);

/**
 * Set session timeout
 *
 * @param seconds Timeout in seconds
 * @return 0 on success, -1 on error
 */
int hsm_config_set_session_timeout(int seconds);

/**
 * Set maximum failed authentication attempts
 *
 * @param attempts Maximum attempts before lockout
 * @return 0 on success, -1 on error
 */
int hsm_config_set_max_auth_attempts(int attempts);

/**
 * Enable/disable audit logging
 *
 * @param enabled 1 to enable, 0 to disable
 * @return 0 on success, -1 on error
 */
int hsm_config_set_audit_enabled(int enabled);

/**
 * Set audit log file path
 *
 * @param filepath Path to audit log file
 * @return 0 on success, -1 on error
 */
int hsm_config_set_audit_log_file(const char *filepath);

/**
 * Print current configuration to stream
 *
 * @param config Configuration to print
 * @param stream Output stream (stdout, stderr, file)
 */
void hsm_config_print(const HSMConfig *config, FILE *stream);

/**
 * Validate configuration values
 *
 * @param config Configuration to validate
 * @return 0 if valid, -1 if invalid
 */
int hsm_config_validate(const HSMConfig *config);

/**
 * Create default configuration file
 *
 * @param filename Path to create configuration file
 * @return 0 on success, -1 on error
 */
int hsm_config_create_default(const char *filename);

// Configuration implementation

// Global configuration instance
HSMConfig g_hsm_config;

void hsm_config_init_defaults(HSMConfig *config) {
    memset(config, 0, sizeof(HSMConfig));

    // Key rotation
    config->key_rotation_days = DEFAULT_KEY_ROTATION_DAYS;
    config->max_key_age_days = DEFAULT_MAX_KEY_AGE_DAYS;
    config->rotation_enabled = 1;

    // Session
    config->session_timeout_seconds = DEFAULT_SESSION_TIMEOUT_SECONDS;
    config->max_concurrent_sessions = 0;  // Unlimited

    // Security
    config->max_failed_auth_attempts = DEFAULT_MAX_FAILED_AUTH_ATTEMPTS;
    config->lockout_duration_seconds = 300;  // 5 minutes
    config->require_pin = 0;
    config->password_min_length = 8;

    // Audit
    strncpy(config->audit_log_file, DEFAULT_AUDIT_LOG_FILE, sizeof(config->audit_log_file) - 1);
    config->audit_enabled = 1;
    config->audit_log_max_size_mb = 100;

    // Storage
    strncpy(config->storage_path, DEFAULT_STORAGE_PATH, sizeof(config->storage_path) - 1);
    config->storage_encryption = 1;

    // Backup
    config->backup_enabled = 0;
    config->backup_interval_hours = 24;
    strncpy(config->backup_path, "./backups", sizeof(config->backup_path) - 1);

    // Advanced
    config->fips_mode = 0;
    config->hardware_rng = 1;
    config->secure_memory = 1;
}

int hsm_config_load(HSMConfig *config, const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Warning: Could not open config file %s, using defaults\n", filename);
        hsm_config_init_defaults(config);
        return -1;
    }

    hsm_config_init_defaults(config);

    char line[512];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        // Parse key=value pairs
        char key[128], value[256];
        if (sscanf(line, "%127[^=]=%255[^\n]", key, value) == 2) {
            // Trim whitespace
            char *k = key;
            while (*k == ' ' || *k == '\t') k++;

            // Parse configuration values
            if (strcmp(k, "key_rotation_days") == 0) {
                config->key_rotation_days = atoi(value);
            } else if (strcmp(k, "max_key_age_days") == 0) {
                config->max_key_age_days = atoi(value);
            } else if (strcmp(k, "rotation_enabled") == 0) {
                config->rotation_enabled = atoi(value);
            } else if (strcmp(k, "session_timeout_seconds") == 0) {
                config->session_timeout_seconds = atoi(value);
            } else if (strcmp(k, "max_concurrent_sessions") == 0) {
                config->max_concurrent_sessions = atoi(value);
            } else if (strcmp(k, "max_failed_auth_attempts") == 0) {
                config->max_failed_auth_attempts = atoi(value);
            } else if (strcmp(k, "lockout_duration_seconds") == 0) {
                config->lockout_duration_seconds = atoi(value);
            } else if (strcmp(k, "require_pin") == 0) {
                config->require_pin = atoi(value);
            } else if (strcmp(k, "password_min_length") == 0) {
                config->password_min_length = atoi(value);
            } else if (strcmp(k, "audit_log_file") == 0) {
                strncpy(config->audit_log_file, value, sizeof(config->audit_log_file) - 1);
            } else if (strcmp(k, "audit_enabled") == 0) {
                config->audit_enabled = atoi(value);
            } else if (strcmp(k, "audit_log_max_size_mb") == 0) {
                config->audit_log_max_size_mb = atoi(value);
            } else if (strcmp(k, "storage_path") == 0) {
                strncpy(config->storage_path, value, sizeof(config->storage_path) - 1);
            } else if (strcmp(k, "storage_encryption") == 0) {
                config->storage_encryption = atoi(value);
            } else if (strcmp(k, "backup_enabled") == 0) {
                config->backup_enabled = atoi(value);
            } else if (strcmp(k, "backup_interval_hours") == 0) {
                config->backup_interval_hours = atoi(value);
            } else if (strcmp(k, "backup_path") == 0) {
                strncpy(config->backup_path, value, sizeof(config->backup_path) - 1);
            } else if (strcmp(k, "fips_mode") == 0) {
                config->fips_mode = atoi(value);
            } else if (strcmp(k, "hardware_rng") == 0) {
                config->hardware_rng = atoi(value);
            } else if (strcmp(k, "secure_memory") == 0) {
                config->secure_memory = atoi(value);
            }
        }
    }

    fclose(fp);
    return 0;
}

int hsm_config_save(const HSMConfig *config, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not open config file %s for writing\n", filename);
        return -1;
    }

    fprintf(fp, "# Virtual HSM Configuration File\n");
    fprintf(fp, "# Generated: %s\n", ctime(&(time_t){time(NULL)}));
    fprintf(fp, "\n");

    fprintf(fp, "# Key Rotation Settings\n");
    fprintf(fp, "key_rotation_days=%d\n", config->key_rotation_days);
    fprintf(fp, "max_key_age_days=%d\n", config->max_key_age_days);
    fprintf(fp, "rotation_enabled=%d\n", config->rotation_enabled);
    fprintf(fp, "\n");

    fprintf(fp, "# Session Management\n");
    fprintf(fp, "session_timeout_seconds=%d\n", config->session_timeout_seconds);
    fprintf(fp, "max_concurrent_sessions=%d\n", config->max_concurrent_sessions);
    fprintf(fp, "\n");

    fprintf(fp, "# Security Settings\n");
    fprintf(fp, "max_failed_auth_attempts=%d\n", config->max_failed_auth_attempts);
    fprintf(fp, "lockout_duration_seconds=%d\n", config->lockout_duration_seconds);
    fprintf(fp, "require_pin=%d\n", config->require_pin);
    fprintf(fp, "password_min_length=%d\n", config->password_min_length);
    fprintf(fp, "\n");

    fprintf(fp, "# Audit Settings\n");
    fprintf(fp, "audit_log_file=%s\n", config->audit_log_file);
    fprintf(fp, "audit_enabled=%d\n", config->audit_enabled);
    fprintf(fp, "audit_log_max_size_mb=%d\n", config->audit_log_max_size_mb);
    fprintf(fp, "\n");

    fprintf(fp, "# Storage Settings\n");
    fprintf(fp, "storage_path=%s\n", config->storage_path);
    fprintf(fp, "storage_encryption=%d\n", config->storage_encryption);
    fprintf(fp, "\n");

    fprintf(fp, "# Backup Settings\n");
    fprintf(fp, "backup_enabled=%d\n", config->backup_enabled);
    fprintf(fp, "backup_interval_hours=%d\n", config->backup_interval_hours);
    fprintf(fp, "backup_path=%s\n", config->backup_path);
    fprintf(fp, "\n");

    fprintf(fp, "# Advanced Settings\n");
    fprintf(fp, "fips_mode=%d\n", config->fips_mode);
    fprintf(fp, "hardware_rng=%d\n", config->hardware_rng);
    fprintf(fp, "secure_memory=%d\n", config->secure_memory);

    fclose(fp);
    return 0;
}

int hsm_config_set_rotation_period(int days) {
    if (days < 1 || days > 3650) {  // 1 day to 10 years
        fprintf(stderr, "Error: Rotation period must be between 1 and 3650 days\n");
        return -1;
    }
    g_hsm_config.key_rotation_days = days;
    return 0;
}

int hsm_config_get_rotation_period(void) {
    return g_hsm_config.key_rotation_days;
}

int hsm_config_set_rotation_enabled(int enabled) {
    g_hsm_config.rotation_enabled = enabled ? 1 : 0;
    return 0;
}

int hsm_config_set_session_timeout(int seconds) {
    if (seconds < 60 || seconds > 86400) {  // 1 minute to 24 hours
        fprintf(stderr, "Error: Session timeout must be between 60 and 86400 seconds\n");
        return -1;
    }
    g_hsm_config.session_timeout_seconds = seconds;
    return 0;
}

int hsm_config_set_max_auth_attempts(int attempts) {
    if (attempts < 1 || attempts > 100) {
        fprintf(stderr, "Error: Max auth attempts must be between 1 and 100\n");
        return -1;
    }
    g_hsm_config.max_failed_auth_attempts = attempts;
    return 0;
}

int hsm_config_set_audit_enabled(int enabled) {
    g_hsm_config.audit_enabled = enabled ? 1 : 0;
    return 0;
}

int hsm_config_set_audit_log_file(const char *filepath) {
    if (!filepath) {
        return -1;
    }
    strncpy(g_hsm_config.audit_log_file, filepath, sizeof(g_hsm_config.audit_log_file) - 1);
    return 0;
}

void hsm_config_print(const HSMConfig *config, FILE *stream) {
    fprintf(stream, "=== Virtual HSM Configuration ===\n\n");

    fprintf(stream, "Key Rotation:\n");
    fprintf(stream, "  Rotation period:    %d days\n", config->key_rotation_days);
    fprintf(stream, "  Max key age:        %d days\n", config->max_key_age_days);
    fprintf(stream, "  Rotation enabled:   %s\n", config->rotation_enabled ? "Yes" : "No");
    fprintf(stream, "\n");

    fprintf(stream, "Session Management:\n");
    fprintf(stream, "  Timeout:            %d seconds\n", config->session_timeout_seconds);
    fprintf(stream, "  Max concurrent:     %d\n", config->max_concurrent_sessions);
    fprintf(stream, "\n");

    fprintf(stream, "Security:\n");
    fprintf(stream, "  Max auth attempts:  %d\n", config->max_failed_auth_attempts);
    fprintf(stream, "  Lockout duration:   %d seconds\n", config->lockout_duration_seconds);
    fprintf(stream, "  Require PIN:        %s\n", config->require_pin ? "Yes" : "No");
    fprintf(stream, "  Min password len:   %d\n", config->password_min_length);
    fprintf(stream, "\n");

    fprintf(stream, "Audit:\n");
    fprintf(stream, "  Enabled:            %s\n", config->audit_enabled ? "Yes" : "No");
    fprintf(stream, "  Log file:           %s\n", config->audit_log_file);
    fprintf(stream, "  Max log size:       %d MB\n", config->audit_log_max_size_mb);
    fprintf(stream, "\n");

    fprintf(stream, "Storage:\n");
    fprintf(stream, "  Path:               %s\n", config->storage_path);
    fprintf(stream, "  Encryption:         %s\n", config->storage_encryption ? "Yes" : "No");
    fprintf(stream, "\n");

    fprintf(stream, "Advanced:\n");
    fprintf(stream, "  FIPS mode:          %s\n", config->fips_mode ? "Yes" : "No");
    fprintf(stream, "  Hardware RNG:       %s\n", config->hardware_rng ? "Yes" : "No");
    fprintf(stream, "  Secure memory:      %s\n", config->secure_memory ? "Yes" : "No");
}

int hsm_config_validate(const HSMConfig *config) {
    if (config->key_rotation_days < 1 || config->key_rotation_days > 3650) {
        fprintf(stderr, "Invalid key_rotation_days: %d\n", config->key_rotation_days);
        return -1;
    }

    if (config->max_key_age_days < config->key_rotation_days) {
        fprintf(stderr, "max_key_age_days must be >= key_rotation_days\n");
        return -1;
    }

    if (config->session_timeout_seconds < 60) {
        fprintf(stderr, "session_timeout_seconds must be >= 60\n");
        return -1;
    }

    if (config->password_min_length < 4 || config->password_min_length > 256) {
        fprintf(stderr, "password_min_length must be between 4 and 256\n");
        return -1;
    }

    return 0;
}

int hsm_config_create_default(const char *filename) {
    HSMConfig config;
    hsm_config_init_defaults(&config);
    return hsm_config_save(&config, filename);
}

#endif /* HSM_CONFIG_H */
