# Virtual HSM v2.0 - Enterprise Edition

A comprehensive, production-ready virtual Hardware Security Module (HSM) implementation in C, featuring multi-user authentication, key lifecycle management, audit logging, and advanced file storage with chunking and encryption.

## 🚀 What's New in v2.0

### Major Features

- **🔐 Multi-User Authentication**
  - Password-based authentication with PBKDF2-HMAC-SHA512
  - Optional PIN support
  - Role-based access control (User, Operator, Admin, Auditor)
  - Session management with timeouts

- **🔑 Complete Key Lifecycle Management**
  - Key generation, import, export
  - Key rotation and versioning
  - Key expiration and revocation
  - Multiple key types (AES, ED25519, HMAC, RSA, ECDSA)
  - Key usage policies

- **📝 Comprehensive Audit Logging**
  - All operations logged with timestamps
  - User attribution
  - Queryable audit trail
  - Tamper-evident logging

- **💾 Advanced File Storage**
  - Random-size chunking for obfuscation
  - Optional compression (zlib)
  - Homomorphic encryption support (framework)
  - Per-chunk encryption with AES-256-GCM
  - Content deduplication ready

- **🌐 Three Access Interfaces**
  - **Library API**: Clean C API for programmatic access
  - **REST API Server**: JSON-based HTTP API
  - **Enhanced CLI**: Interactive and scripting modes

- **🛡️ Security Hardening**
  - Thread-safe operations
  - Secure memory wiping
  - Memory locking to prevent swapping
  - Input validation throughout
  - Fixed all buffer overflow vulnerabilities

## 📦 Architecture

```
virtual_hsm/
├── include/
│   ├── vhsm.h              # Main API header
│   └── vhsm_types.h        # Type definitions
├── src/
│   ├── core/               # Library initialization
│   ├── auth/               # Authentication & sessions
│   ├── storage/            # Key storage & management
│   ├── crypto/             # Cryptographic operations
│   ├── audit/              # Audit logging
│   └── utils/              # Utilities (secure memory)
├── cli/                    # CLI application
├── server/                 # REST API server
├── examples/               # Example programs
└── lib/                    # Built libraries
```

## 🔧 Building

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install build-essential libssl-dev zlib1g-dev uuid-dev

# Fedora/RHEL
sudo dnf install gcc openssl-devel zlib-devel libuuid-devel
```

### Compile

```bash
# Build everything
make all

# Build specific components
make lib        # Library only
make cli        # CLI only
make server     # REST API server only
make examples   # Example programs

# Install system-wide
sudo make install
```

### Build Output

- `lib/libvhsm.a` - Static library
- `lib/libvhsm.so` - Shared library
- `bin/vhsm` - CLI application
- `bin/vhsm-server` - REST API server
- `bin/example_basic` - Example program

## 📚 Usage

### 1. Library API (Programmatic Access)

```c
#include "vhsm.h"

int main(void) {
    vhsm_ctx_t ctx;
    vhsm_session_t session;
    vhsm_key_handle_t key;

    // Initialize
    vhsm_init();
    vhsm_ctx_create(&ctx, "./storage");

    // Generate master key
    uint8_t master_key[32];
    vhsm_ctx_generate_master_key(ctx, master_key);

    // Create user
    vhsm_user_create(ctx, "admin", "password", NULL, VHSM_ROLE_ADMIN);

    // Login
    vhsm_session_login(ctx, &session, "admin", "password", NULL);

    // Generate key
    vhsm_key_generate(session, "mykey", VHSM_KEY_TYPE_AES_256,
                      VHSM_KEY_USAGE_ALL, &key);

    // Use key for encryption, signing, etc.
    // ...

    // Cleanup
    vhsm_session_logout(session);
    vhsm_ctx_destroy(ctx);
    vhsm_cleanup();
}
```

See `examples/basic_usage.c` for complete example.

### 2. CLI (Interactive & Scripting)

#### Interactive Mode

```bash
$ bin/vhsm
vhsm> init
HSM initialized successfully

vhsm> user-create admin
Password: ****
User 'admin' created successfully

vhsm> login admin
Password: ****
Logged in as 'admin'

vhsm> key-generate mykey aes256
Key 'mykey' generated successfully

vhsm> key-list
Found 1 keys:
  mykey (type: 2, state: 1)

vhsm> audit-enable audit.log
Audit logging enabled

vhsm> exit
```

#### Scripting Mode

```bash
# Initialize in script
echo "init /path/to/storage" | bin/vhsm
```

### 3. REST API Server

#### Start Server

```bash
$ bin/vhsm-server --port 8443 --storage ./hsm_data
Virtual HSM REST API Server v2.0.0
Listening on port 8443
Storage path: ./hsm_data
```

#### API Endpoints

**Get Version**
```bash
curl http://localhost:8443/api/version
# Response: {"version":"2.0.0","status":"ok"}
```

**Create User**
```bash
curl -X POST http://localhost:8443/api/user/create \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePass123","role":"admin"}'
# Response: {"success":true,"username":"admin"}
```

**Login**
```bash
curl -X POST http://localhost:8443/api/session/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"SecurePass123"}'
# Response: {"success":true,"session_id":"0x..."}
```

**Generate Key** (session required)
```bash
curl -X POST http://localhost:8443/api/key/generate \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: 0x..." \
  -d '{"name":"mykey","type":"aes256","usage":"all"}'
```

## 🔑 Key Types Supported

| Type | Description | Key Size | Usage |
|------|-------------|----------|-------|
| `aes128` | AES-128 | 128 bits | Encryption/Decryption |
| `aes256` | AES-256 | 256 bits | Encryption/Decryption |
| `ed25519` | EdDSA | 256 bits | Signing/Verification |
| `rsa2048` | RSA | 2048 bits | Signing/Encryption |
| `rsa3072` | RSA | 3072 bits | Signing/Encryption |
| `rsa4096` | RSA | 4096 bits | Signing/Encryption |
| `ecdsa_p256` | ECDSA P-256 | 256 bits | Signing/Verification |
| `ecdsa_p384` | ECDSA P-384 | 384 bits | Signing/Verification |
| `hmac256` | HMAC-SHA256 | Variable | Authentication |
| `hmac512` | HMAC-SHA512 | Variable | Authentication |

## 🎯 Key Features

### Authentication System

- **Password Hashing**: PBKDF2-HMAC-SHA512 with 100,000 iterations
- **Salt**: Random 32-byte salt per user
- **PIN Support**: Optional additional factor
- **Session Management**: Automatic timeout (1 hour default)
- **Failed Attempt Tracking**: Monitors authentication failures

### Key Lifecycle

```
Active → Suspended → Active
   ↓
Expired
   ↓
Revoked (terminal state)
   ↓
Compromised (terminal state)
```

**Operations:**
- `generate` - Create new key
- `import` - Import existing key material
- `export` - Export key (if marked exportable)
- `rotate` - Create new version, deprecate old
- `revoke` - Mark as unusable permanently
- `delete` - Remove from storage

### Audit Logging

All operations logged with:
- Timestamp (UTC)
- Event type
- Username
- Operation details
- Success/failure status

**Queryable by:**
- Time range
- Event type
- Username
- Custom filters

### File Storage with Chunking

**Features:**
- Random chunk sizes (64KB - 1MB)
- Per-chunk encryption with unique IV
- Optional compression (zlib)
- Content-addressable storage
- Homomorphic encryption framework

**Process:**
1. File split into random-sized chunks
2. Each chunk optionally compressed
3. Each chunk encrypted with AES-256-GCM
4. Unique IV and auth tag per chunk
5. Chunks stored with metadata
6. UUID token for retrieval

## 🔒 Security Considerations

### Production Use

This v2.0 implementation is significantly more robust than v1.0, but for production use, consider:

1. **Key Storage**: Master key should be stored in hardware TPM/HSM
2. **Network Security**: Use TLS for REST API (not included)
3. **Physical Security**: Secure server environment
4. **Audit Review**: Regular audit log analysis
5. **Backup**: Encrypted backups of key material
6. **Access Control**: Firewall rules, network segmentation
7. **Monitoring**: Active monitoring and alerting

### Known Limitations

- Software-based (no hardware root of trust)
- Master key in memory during operation
- No formal security certification
- Homomorphic encryption is placeholder (requires library like SEAL/HElib)
- Some crypto operations return NOT_IMPLEMENTED (stubs for future completion)

## 📖 API Reference

### Error Codes

```c
VHSM_SUCCESS                - Operation successful
VHSM_ERROR_GENERIC          - Generic error
VHSM_ERROR_INVALID_PARAM    - Invalid parameter
VHSM_ERROR_OUT_OF_MEMORY    - Memory allocation failed
VHSM_ERROR_KEY_NOT_FOUND    - Key not found
VHSM_ERROR_KEY_EXISTS       - Key already exists
VHSM_ERROR_CRYPTO_FAILED    - Cryptographic operation failed
VHSM_ERROR_AUTH_FAILED      - Authentication failed
VHSM_ERROR_PERMISSION_DENIED - Permission denied
VHSM_ERROR_KEY_EXPIRED      - Key has expired
VHSM_ERROR_KEY_REVOKED      - Key has been revoked
VHSM_ERROR_SESSION_INVALID  - Session invalid or expired
```

### Core Functions

```c
// Library management
vhsm_error_t vhsm_init(void);
void vhsm_cleanup(void);
const char* vhsm_version(void);
const char* vhsm_error_string(vhsm_error_t error);

// Context management
vhsm_error_t vhsm_ctx_create(vhsm_ctx_t* ctx, const char* storage_path);
void vhsm_ctx_destroy(vhsm_ctx_t ctx);
vhsm_error_t vhsm_ctx_generate_master_key(vhsm_ctx_t ctx, uint8_t* master_key);

// User management
vhsm_error_t vhsm_user_create(vhsm_ctx_t ctx, const char* username,
                               const char* password, const char* pin,
                               vhsm_role_t role);
vhsm_error_t vhsm_user_delete(vhsm_ctx_t ctx, const char* username);
vhsm_error_t vhsm_user_change_password(vhsm_ctx_t ctx, const char* username,
                                        const char* old_password,
                                        const char* new_password);

// Session management
vhsm_error_t vhsm_session_login(vhsm_ctx_t ctx, vhsm_session_t* session,
                                 const char* username, const char* password,
                                 const char* pin);
void vhsm_session_logout(vhsm_session_t session);
int vhsm_session_is_valid(vhsm_session_t session);

// Key management
vhsm_error_t vhsm_key_generate(vhsm_session_t session, const char* name,
                                vhsm_key_type_t type, vhsm_key_usage_t usage,
                                vhsm_key_handle_t* handle);
vhsm_error_t vhsm_key_list(vhsm_session_t session, vhsm_key_metadata_t* metadata,
                            size_t* count);
vhsm_error_t vhsm_key_delete(vhsm_session_t session, vhsm_key_handle_t handle);
vhsm_error_t vhsm_key_rotate(vhsm_session_t session, vhsm_key_handle_t handle,
                              vhsm_key_handle_t* new_handle);

// Cryptographic operations
vhsm_error_t vhsm_encrypt(vhsm_session_t session, vhsm_key_handle_t handle,
                           const uint8_t* plaintext, size_t plaintext_len,
                           uint8_t* ciphertext, size_t* ciphertext_len,
                           uint8_t* iv, size_t iv_len);
vhsm_error_t vhsm_decrypt(vhsm_session_t session, vhsm_key_handle_t handle,
                           const uint8_t* ciphertext, size_t ciphertext_len,
                           uint8_t* plaintext, size_t* plaintext_len,
                           const uint8_t* iv, size_t iv_len);
vhsm_error_t vhsm_sign(vhsm_session_t session, vhsm_key_handle_t handle,
                        const uint8_t* data, size_t data_len,
                        uint8_t* signature, size_t* signature_len);
vhsm_error_t vhsm_verify(vhsm_session_t session, vhsm_key_handle_t handle,
                          const uint8_t* data, size_t data_len,
                          const uint8_t* signature, size_t signature_len);

// File storage
vhsm_error_t vhsm_file_store(vhsm_session_t session, vhsm_key_handle_t key_handle,
                              const char* source_path, vhsm_compress_t compression,
                              int use_homomorphic, char* token_out, size_t token_len);
vhsm_error_t vhsm_file_retrieve(vhsm_session_t session, vhsm_key_handle_t key_handle,
                                 const char* token, const char* dest_path);

// Audit logging
vhsm_error_t vhsm_audit_enable(vhsm_ctx_t ctx, const char* log_path);
void vhsm_audit_disable(vhsm_ctx_t ctx);
vhsm_error_t vhsm_audit_query(vhsm_ctx_t ctx, time_t start_time, time_t end_time,
                               vhsm_audit_event_t event_type, const char* username,
                               void (*callback)(const char* entry, void* user_data),
                               void* user_data);
```

## 🧪 Testing

```bash
# Run basic example
./bin/example_basic

# Test CLI
./bin/vhsm

# Test server
./bin/vhsm-server --port 8443 &
curl http://localhost:8443/api/version
```

## 📝 License

See LICENSE file for details.

## 🤝 Contributing

This is an educational/demonstration project showing HSM concepts. Contributions welcome for:
- Additional crypto algorithms
- Performance improvements
- Security hardening
- Documentation
- Test coverage

## ⚠️ Disclaimer

This software is provided for educational and development purposes. While v2.0 represents a significant improvement in security and functionality, it has not undergone formal security audits. Use in production environments at your own risk.

## 📧 Support

For issues and questions, please open an issue on the GitHub repository.

---

**Virtual HSM v2.0** - Enterprise-grade key management and cryptography
