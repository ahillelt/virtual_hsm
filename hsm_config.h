#ifndef HSM_CONFIG_H
#define HSM_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Default configuration values
#define DEFAULT_CONFIG_FILE "hsm_config.conf"
#define DEFAULT_KEY_ROTATION_DAYS 90
#define DEFAULT_MAX_KEY_AGE_DAYS 365
#define DEFAULT_SESSION_TIMEOUT_SECONDS 3600
#define DEFAULT_MAX_FAILED_AUTH_ATTEMPTS 3
#define DEFAULT_AUDIT_LOG_FILE "hsm_audit.log"
#define DEFAULT_STORAGE_PATH "."

// Encryption constants for config file
#define CONFIG_IV_SIZE 12
#define CONFIG_TAG_SIZE 16
#define CONFIG_MAGIC "VHSMCFG1"  // Magic number for encrypted config files
#define CONFIG_MAGIC_SIZE 8

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

// Static configuration encryption key (derived from system properties)
static unsigned char config_enc_key[32] = {0};
static int config_enc_key_initialized = 0;

/**
 * Initialize configuration encryption key
 * Derives a key from system properties for config encryption
 */
static void init_config_encryption_key(void) {
    if (config_enc_key_initialized) {
        return;
    }

    // In production, this should derive from:
    // 1. Hardware identifier (CPU ID, MAC address)
    // 2. Installation-specific salt
    // 3. User-provided passphrase
    // For now, use a deterministic key derived from known values
    const char *salt = "VHSM_CONFIG_SALT_V1";
    unsigned char temp[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)salt, strlen(salt), temp);
    memcpy(config_enc_key, temp, 32);

    config_enc_key_initialized = 1;
}

/**
 * Encrypt configuration data
 */
static int encrypt_config_data(const unsigned char *plaintext, size_t plaintext_len,
                               unsigned char *ciphertext, size_t *ciphertext_len,
                               unsigned char *iv, unsigned char *tag) {
    init_config_encryption_key();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    // Generate random IV
    if (RAND_bytes(iv, CONFIG_IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, config_enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    size_t total_len = 0;

    // Encrypt data
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CONFIG_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/**
 * Decrypt configuration data
 */
static int decrypt_config_data(const unsigned char *ciphertext, size_t ciphertext_len,
                               unsigned char *plaintext, size_t *plaintext_len,
                               const unsigned char *iv, const unsigned char *tag) {
    init_config_encryption_key();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, config_enc_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    size_t total_len = 0;

    // Decrypt data
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, CONFIG_TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Finalize decryption (verifies tag)
    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "Error: Configuration file authentication failed (tampered or corrupted)\n");
        return -1;
    }
    total_len += len;

    *plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

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
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Warning: Could not open config file %s, using defaults\n", filename);
        hsm_config_init_defaults(config);
        return -1;
    }

    // Read magic number
    char magic[CONFIG_MAGIC_SIZE];
    if (fread(magic, 1, CONFIG_MAGIC_SIZE, fp) != CONFIG_MAGIC_SIZE ||
        memcmp(magic, CONFIG_MAGIC, CONFIG_MAGIC_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid or corrupted config file (bad magic number)\n");
        fclose(fp);
        hsm_config_init_defaults(config);
        return -1;
    }

    // Read IV
    unsigned char iv[CONFIG_IV_SIZE];
    if (fread(iv, 1, CONFIG_IV_SIZE, fp) != CONFIG_IV_SIZE) {
        fprintf(stderr, "Error: Failed to read IV from config file\n");
        fclose(fp);
        hsm_config_init_defaults(config);
        return -1;
    }

    // Read tag
    unsigned char tag[CONFIG_TAG_SIZE];
    if (fread(tag, 1, CONFIG_TAG_SIZE, fp) != CONFIG_TAG_SIZE) {
        fprintf(stderr, "Error: Failed to read tag from config file\n");
        fclose(fp);
        hsm_config_init_defaults(config);
        return -1;
    }

    // Read encrypted data
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    long ciphertext_len = file_size - CONFIG_MAGIC_SIZE - CONFIG_IV_SIZE - CONFIG_TAG_SIZE;
    fseek(fp, CONFIG_MAGIC_SIZE + CONFIG_IV_SIZE + CONFIG_TAG_SIZE, SEEK_SET);

    if (ciphertext_len <= 0 || ciphertext_len > 4096) {
        fprintf(stderr, "Error: Invalid config file size\n");
        fclose(fp);
        hsm_config_init_defaults(config);
        return -1;
    }

    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Error: Out of memory\n");
        fclose(fp);
        hsm_config_init_defaults(config);
        return -1;
    }

    if (fread(ciphertext, 1, ciphertext_len, fp) != (size_t)ciphertext_len) {
        fprintf(stderr, "Error: Failed to read encrypted config data\n");
        free(ciphertext);
        fclose(fp);
        hsm_config_init_defaults(config);
        return -1;
    }
    fclose(fp);

    // Decrypt configuration
    unsigned char plaintext[sizeof(HSMConfig) + 16];
    size_t plaintext_len = 0;

    if (decrypt_config_data(ciphertext, ciphertext_len, plaintext, &plaintext_len,
                            iv, tag) != 0) {
        fprintf(stderr, "Error: Failed to decrypt config file\n");
        free(ciphertext);
        hsm_config_init_defaults(config);
        return -1;
    }

    free(ciphertext);

    // Validate decrypted size
    if (plaintext_len != sizeof(HSMConfig)) {
        fprintf(stderr, "Error: Decrypted config size mismatch (got %zu, expected %zu)\n",
                plaintext_len, sizeof(HSMConfig));
        hsm_config_init_defaults(config);
        return -1;
    }

    // Copy decrypted config
    memcpy(config, plaintext, sizeof(HSMConfig));

    // Zero out plaintext
    memset(plaintext, 0, sizeof(plaintext));

    return 0;
}

int hsm_config_save(const HSMConfig *config, const char *filename) {
    if (!config || !filename) {
        fprintf(stderr, "Error: Invalid parameters for config save\n");
        return -1;
    }

    // Encrypt configuration data
    unsigned char ciphertext[sizeof(HSMConfig) + 32];
    size_t ciphertext_len = 0;
    unsigned char iv[CONFIG_IV_SIZE];
    unsigned char tag[CONFIG_TAG_SIZE];

    if (encrypt_config_data((const unsigned char*)config, sizeof(HSMConfig),
                            ciphertext, &ciphertext_len, iv, tag) != 0) {
        fprintf(stderr, "Error: Failed to encrypt configuration\n");
        return -1;
    }

    // Write encrypted file
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open config file %s for writing\n", filename);
        return -1;
    }

    // Write magic number
    if (fwrite(CONFIG_MAGIC, 1, CONFIG_MAGIC_SIZE, fp) != CONFIG_MAGIC_SIZE) {
        fprintf(stderr, "Error: Failed to write magic number\n");
        fclose(fp);
        return -1;
    }

    // Write IV
    if (fwrite(iv, 1, CONFIG_IV_SIZE, fp) != CONFIG_IV_SIZE) {
        fprintf(stderr, "Error: Failed to write IV\n");
        fclose(fp);
        return -1;
    }

    // Write tag
    if (fwrite(tag, 1, CONFIG_TAG_SIZE, fp) != CONFIG_TAG_SIZE) {
        fprintf(stderr, "Error: Failed to write tag\n");
        fclose(fp);
        return -1;
    }

    // Write encrypted data
    if (fwrite(ciphertext, 1, ciphertext_len, fp) != ciphertext_len) {
        fprintf(stderr, "Error: Failed to write encrypted data\n");
        fclose(fp);
        return -1;
    }

    fclose(fp);

    // Set secure file permissions
    chmod(filename, 0600);

    // Zero out sensitive data
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(iv, 0, sizeof(iv));
    memset(tag, 0, sizeof(tag));

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
