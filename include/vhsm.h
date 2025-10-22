#ifndef VHSM_H
#define VHSM_H

#include "vhsm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Library Initialization and Configuration
 * ======================================================================== */

/**
 * Initialize the virtual HSM library
 *
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_init(void);

/**
 * Shutdown the virtual HSM library and cleanup resources
 */
void vhsm_cleanup(void);

/**
 * Get library version string
 *
 * @return Version string (e.g., "2.0.0")
 */
const char* vhsm_version(void);

/**
 * Get error string for error code
 *
 * @param error Error code
 * @return Human-readable error message
 */
const char* vhsm_error_string(vhsm_error_t error);

/**
 * Set log callback for library diagnostics
 *
 * @param callback Log callback function
 * @param user_data User data passed to callback
 */
void vhsm_set_log_callback(vhsm_log_callback_t callback, void* user_data);

/* ========================================================================
 * Context Management
 * ======================================================================== */

/**
 * Create a new HSM context
 *
 * @param ctx Pointer to receive context handle
 * @param storage_path Path to HSM storage directory
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_ctx_create(vhsm_ctx_t* ctx, const char* storage_path);

/**
 * Destroy HSM context and free resources
 *
 * @param ctx Context handle
 */
void vhsm_ctx_destroy(vhsm_ctx_t ctx);

/**
 * Set master key for context
 *
 * @param ctx Context handle
 * @param master_key Master key bytes (32 bytes)
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_ctx_set_master_key(vhsm_ctx_t ctx, const uint8_t* master_key);

/**
 * Generate and set a new random master key
 *
 * @param ctx Context handle
 * @param master_key Buffer to receive master key (32 bytes)
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_ctx_generate_master_key(vhsm_ctx_t ctx, uint8_t* master_key);

/* ========================================================================
 * Authentication and Session Management
 * ======================================================================== */

/**
 * Create a new user
 *
 * @param ctx Context handle
 * @param username Username
 * @param password Password
 * @param pin PIN (optional, can be NULL)
 * @param role User role
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_user_create(vhsm_ctx_t ctx, const char* username,
                               const char* password, const char* pin,
                               vhsm_role_t role);

/**
 * Delete a user
 *
 * @param ctx Context handle
 * @param username Username
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_user_delete(vhsm_ctx_t ctx, const char* username);

/**
 * Change user password
 *
 * @param ctx Context handle
 * @param username Username
 * @param old_password Old password
 * @param new_password New password
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_user_change_password(vhsm_ctx_t ctx, const char* username,
                                        const char* old_password,
                                        const char* new_password);

/**
 * Login and create a session
 *
 * @param ctx Context handle
 * @param session Pointer to receive session handle
 * @param username Username
 * @param password Password
 * @param pin PIN (optional, can be NULL)
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_session_login(vhsm_ctx_t ctx, vhsm_session_t* session,
                                 const char* username, const char* password,
                                 const char* pin);

/**
 * Logout and destroy session
 *
 * @param session Session handle
 */
void vhsm_session_logout(vhsm_session_t session);

/**
 * Check if session is valid and active
 *
 * @param session Session handle
 * @return 1 if valid, 0 otherwise
 */
int vhsm_session_is_valid(vhsm_session_t session);

/* ========================================================================
 * Key Management
 * ======================================================================== */

/**
 * Generate a new key
 *
 * @param session Session handle
 * @param name Key name (unique identifier)
 * @param type Key type
 * @param usage Key usage flags
 * @param handle Pointer to receive key handle
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_generate(vhsm_session_t session, const char* name,
                                vhsm_key_type_t type, vhsm_key_usage_t usage,
                                vhsm_key_handle_t* handle);

/**
 * Import an existing key
 *
 * @param session Session handle
 * @param name Key name
 * @param type Key type
 * @param usage Key usage flags
 * @param key_data Key material
 * @param key_len Length of key material
 * @param handle Pointer to receive key handle
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_import(vhsm_session_t session, const char* name,
                              vhsm_key_type_t type, vhsm_key_usage_t usage,
                              const uint8_t* key_data, size_t key_len,
                              vhsm_key_handle_t* handle);

/**
 * Export a key (if exportable)
 *
 * @param session Session handle
 * @param handle Key handle
 * @param key_data Buffer to receive key material
 * @param key_len Pointer to buffer size, updated with actual size
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_export(vhsm_session_t session, vhsm_key_handle_t handle,
                              uint8_t* key_data, size_t* key_len);

/**
 * Delete a key
 *
 * @param session Session handle
 * @param handle Key handle
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_delete(vhsm_session_t session, vhsm_key_handle_t handle);

/**
 * Get key by name
 *
 * @param session Session handle
 * @param name Key name
 * @param handle Pointer to receive key handle
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_get(vhsm_session_t session, const char* name,
                           vhsm_key_handle_t* handle);

/**
 * Get key metadata
 *
 * @param session Session handle
 * @param handle Key handle
 * @param metadata Pointer to receive metadata
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_get_metadata(vhsm_session_t session, vhsm_key_handle_t handle,
                                    vhsm_key_metadata_t* metadata);

/**
 * List all keys accessible to the session
 *
 * @param session Session handle
 * @param metadata Array to receive metadata
 * @param count Pointer to array size, updated with actual count
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_list(vhsm_session_t session, vhsm_key_metadata_t* metadata,
                            size_t* count);

/**
 * Set key expiration
 *
 * @param session Session handle
 * @param handle Key handle
 * @param expires Expiration timestamp (0 for never)
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_set_expiration(vhsm_session_t session, vhsm_key_handle_t handle,
                                      time_t expires);

/**
 * Revoke a key
 *
 * @param session Session handle
 * @param handle Key handle
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_revoke(vhsm_session_t session, vhsm_key_handle_t handle);

/**
 * Rotate a key (generate new version)
 *
 * @param session Session handle
 * @param handle Key handle
 * @param new_handle Pointer to receive new key handle
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_key_rotate(vhsm_session_t session, vhsm_key_handle_t handle,
                              vhsm_key_handle_t* new_handle);

/* ========================================================================
 * Cryptographic Operations
 * ======================================================================== */

/**
 * Encrypt data
 *
 * @param session Session handle
 * @param handle Key handle
 * @param plaintext Plaintext data
 * @param plaintext_len Length of plaintext
 * @param ciphertext Buffer to receive ciphertext
 * @param ciphertext_len Pointer to buffer size, updated with actual size
 * @param iv Initialization vector (optional, generated if NULL)
 * @param iv_len Length of IV
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_encrypt(vhsm_session_t session, vhsm_key_handle_t handle,
                           const uint8_t* plaintext, size_t plaintext_len,
                           uint8_t* ciphertext, size_t* ciphertext_len,
                           uint8_t* iv, size_t iv_len);

/**
 * Decrypt data
 *
 * @param session Session handle
 * @param handle Key handle
 * @param ciphertext Ciphertext data
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Buffer to receive plaintext
 * @param plaintext_len Pointer to buffer size, updated with actual size
 * @param iv Initialization vector
 * @param iv_len Length of IV
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_decrypt(vhsm_session_t session, vhsm_key_handle_t handle,
                           const uint8_t* ciphertext, size_t ciphertext_len,
                           uint8_t* plaintext, size_t* plaintext_len,
                           const uint8_t* iv, size_t iv_len);

/**
 * Sign data
 *
 * @param session Session handle
 * @param handle Key handle
 * @param data Data to sign
 * @param data_len Length of data
 * @param signature Buffer to receive signature
 * @param signature_len Pointer to buffer size, updated with actual size
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_sign(vhsm_session_t session, vhsm_key_handle_t handle,
                        const uint8_t* data, size_t data_len,
                        uint8_t* signature, size_t* signature_len);

/**
 * Verify signature
 *
 * @param session Session handle
 * @param handle Key handle
 * @param data Data that was signed
 * @param data_len Length of data
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @return VHSM_SUCCESS if valid, error code otherwise
 */
vhsm_error_t vhsm_verify(vhsm_session_t session, vhsm_key_handle_t handle,
                          const uint8_t* data, size_t data_len,
                          const uint8_t* signature, size_t signature_len);

/**
 * Generate HMAC
 *
 * @param session Session handle
 * @param handle Key handle
 * @param data Data to authenticate
 * @param data_len Length of data
 * @param hmac Buffer to receive HMAC
 * @param hmac_len Pointer to buffer size, updated with actual size
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_hmac(vhsm_session_t session, vhsm_key_handle_t handle,
                        const uint8_t* data, size_t data_len,
                        uint8_t* hmac, size_t* hmac_len);

/* ========================================================================
 * File Storage with Chunking and Encryption
 * ======================================================================== */

/**
 * Store a file with encryption and chunking
 *
 * @param session Session handle
 * @param key_handle Key handle for encryption
 * @param source_path Path to source file
 * @param compression Compression type
 * @param use_homomorphic Use homomorphic encryption
 * @param token_out Buffer to receive storage token
 * @param token_len Size of token buffer
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_file_store(vhsm_session_t session, vhsm_key_handle_t key_handle,
                              const char* source_path, vhsm_compress_t compression,
                              int use_homomorphic, char* token_out, size_t token_len);

/**
 * Retrieve a stored file
 *
 * @param session Session handle
 * @param key_handle Key handle for decryption
 * @param token Storage token
 * @param dest_path Destination path for retrieved file
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_file_retrieve(vhsm_session_t session, vhsm_key_handle_t key_handle,
                                 const char* token, const char* dest_path);

/**
 * Delete a stored file
 *
 * @param session Session handle
 * @param token Storage token
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_file_delete(vhsm_session_t session, const char* token);

/**
 * List stored files
 *
 * @param session Session handle
 * @param tokens Array to receive tokens
 * @param count Pointer to array size, updated with actual count
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_file_list(vhsm_session_t session, char** tokens, size_t* count);

/* ========================================================================
 * Audit and Logging
 * ======================================================================== */

/**
 * Enable audit logging
 *
 * @param ctx Context handle
 * @param log_path Path to audit log file
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_audit_enable(vhsm_ctx_t ctx, const char* log_path);

/**
 * Disable audit logging
 *
 * @param ctx Context handle
 */
void vhsm_audit_disable(vhsm_ctx_t ctx);

/**
 * Query audit log
 *
 * @param ctx Context handle
 * @param start_time Start timestamp (0 for all)
 * @param end_time End timestamp (0 for all)
 * @param event_type Event type filter (VHSM_AUDIT_NONE for all)
 * @param username Username filter (NULL for all)
 * @param callback Callback for each log entry
 * @param user_data User data for callback
 * @return VHSM_SUCCESS on success, error code on failure
 */
vhsm_error_t vhsm_audit_query(vhsm_ctx_t ctx, time_t start_time, time_t end_time,
                               vhsm_audit_event_t event_type, const char* username,
                               void (*callback)(const char* entry, void* user_data),
                               void* user_data);

#ifdef __cplusplus
}
#endif

#endif /* VHSM_H */
