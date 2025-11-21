# Virtual Hardware Security Module (HSM)

A comprehensive, feature-rich virtual Hardware Security Module implementation providing cryptographic key management, digital signatures, multi-user authentication, audit logging, and secure file storage.

[![CI/CD](https://github.com/ahillelt/virtual_hsm/actions/workflows/test_and_build.yml/badge.svg)](https://github.com/ahillelt/virtual_hsm/actions)

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [Library API](#library-api)
  - [CLI Usage](#cli-usage)
  - [Enhanced HSM](#enhanced-hsm)
  - [REST API Server](#rest-api-server)
- [Key Management](#key-management)
- [Digital Signatures](#digital-signatures)
- [File Storage](#file-storage)
- [Security Features](#security-features)
- [GitHub Actions Integration](#github-actions-integration)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [Documentation](#documentation)
- [Known Limitations](#known-limitations)
- [License](#license)

## Overview

This Virtual HSM provides enterprise-grade cryptographic key management and security services in software. While not providing hardware-level security, it implements comprehensive HSM functionality including:

- Multi-user authentication and authorization
- Complete key lifecycle management
- Audit logging for compliance
- Secure file storage with encryption
- Digital signature operations (ED25519)
- Multiple access interfaces (Library API, CLI, REST API)

**⚠️ Important:** This is a virtualized HSM for educational and development purposes. For production systems, use hardware-backed HSMs or cloud HSM services.

## Features

### 🔐 Authentication & Access Control
- **Multi-user support** with password-based authentication (PBKDF2-HMAC-SHA512)
- **Role-based access control** (User, Operator, Admin, Auditor)
- **Session management** with timeout protection
- **Optional PIN support** for two-factor authentication

### 🔑 Comprehensive Key Management
- **Key generation**: AES-128, AES-256, ED25519, HMAC, RSA, ECDSA
- **Key lifecycle**: Creation, activation, rotation, deprecation, destruction
- **Key versioning** with automatic rotation policies
- **Key import/export** with secure key wrapping
- **Key usage policies** and access controls

### 📝 Audit & Compliance
- **Complete audit trail** of all operations
- **Tamper-evident logging** with timestamps
- **User attribution** for all actions
- **Queryable audit logs** by time range and event type
- **13 tracked event types** including key creation, access, rotation, signing

### 💾 Secure File Storage
- **Chunked encryption** for large files
- **AES-256-GCM encryption** per chunk
- **Token-based retrieval** system
- **Compression support** (zlib)
- **Progress tracking** for file operations

### 🛡️ Enhanced Security
- **Secure memory management** with memory locking
- **Explicit key erasure** from memory
- **Thread-safe operations** throughout
- **Input validation** and bounds checking
- **Hardware security module detection** (TPM, YubiKey, FIDO2, PKCS#11)

### 🌐 Multiple Interfaces
- **Library API**: Clean C API for programmatic access
- **CLI Tool**: Command-line interface for scripting
- **Enhanced CLI**: Interactive mode with extended features
- **REST API Server**: JSON HTTP API for remote access
- **TLS REST Server**: Encrypted remote access

## Architecture

```
virtual_hsm/
├── include/
│   ├── vhsm.h           # Main API header
│   └── vhsm_types.h     # Type definitions and constants
├── src/
│   ├── core/            # Library initialization and context management
│   ├── auth/            # Authentication and session management
│   ├── storage/         # Key storage and file operations
│   ├── crypto/          # Cryptographic primitives
│   ├── audit/           # Audit logging system
│   └── utils/           # Secure memory utilities
├── cli/                 # Command-line interface
├── server/              # REST API servers
├── examples/            # Example applications
├── tests/               # Test suites
├── lib/                 # Built libraries (output)
└── bin/                 # Built executables (output)
```

## Quick Start

### Installation

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libssl-dev zlib1g-dev uuid-dev

# Build everything
make all

# Install system-wide (optional)
sudo make install
```

### Basic Usage (CLI)

```bash
# Initialize HSM and create admin user
bin/vhsm init ./my_hsm

# Create a user (interactive)
bin/vhsm user-create

# Generate an encryption key
bin/vhsm key-generate mykey AES-256 --encrypt

# Encrypt a file
bin/vhsm encrypt mykey input.txt encrypted.bin

# Decrypt the file
bin/vhsm decrypt mykey encrypted.bin output.txt
```

### Basic Usage (Library API)

```c
#include "vhsm.h"

int main() {
    vhsm_ctx_t ctx;
    vhsm_session_t session;

    // Initialize library
    vhsm_init(VHSM_LOG_LEVEL_INFO);

    // Create context
    vhsm_ctx_create(&ctx, "./hsm_storage");

    // Generate master key
    uint8_t master_key[32];
    vhsm_ctx_generate_master_key(ctx, master_key);

    // Create admin user
    vhsm_user_create(ctx, "admin", "password123", NULL, VHSM_ROLE_ADMIN);

    // Login
    vhsm_session_login(ctx, &session, "admin", "password123", NULL);

    // Generate encryption key
    vhsm_key_handle_t key;
    vhsm_key_generate(session, "my_aes_key", VHSM_KEY_TYPE_AES_256,
                      VHSM_KEY_USAGE_ENCRYPT | VHSM_KEY_USAGE_DECRYPT, &key);

    // Encrypt data
    uint8_t plaintext[] = "Secret message";
    uint8_t ciphertext[256];
    size_t ciphertext_len = sizeof(ciphertext);
    vhsm_encrypt(session, key, plaintext, strlen(plaintext),
                 ciphertext, &ciphertext_len);

    // Cleanup
    vhsm_session_logout(session);
    vhsm_ctx_destroy(ctx);
    vhsm_cleanup();

    return 0;
}
```

## Usage

### Library API

The library provides a comprehensive C API for all HSM operations:

**Initialization:**
```c
vhsm_error_t vhsm_init(vhsm_log_level_t log_level);
vhsm_error_t vhsm_ctx_create(vhsm_ctx_t* ctx, const char* storage_path);
vhsm_error_t vhsm_ctx_generate_master_key(vhsm_ctx_t ctx, uint8_t* master_key);
```

**User Management:**
```c
vhsm_error_t vhsm_user_create(vhsm_ctx_t ctx, const char* username,
                               const char* password, const char* pin,
                               vhsm_role_t role);
vhsm_error_t vhsm_session_login(vhsm_ctx_t ctx, vhsm_session_t* session,
                                 const char* username, const char* password,
                                 const char* pin);
```

**Key Operations:**
```c
vhsm_error_t vhsm_key_generate(vhsm_session_t session, const char* name,
                                vhsm_key_type_t type, vhsm_key_usage_t usage,
                                vhsm_key_handle_t* handle);
vhsm_error_t vhsm_encrypt(vhsm_session_t session, vhsm_key_handle_t key,
                          const uint8_t* plaintext, size_t plaintext_len,
                          uint8_t* ciphertext, size_t* ciphertext_len);
vhsm_error_t vhsm_sign(vhsm_session_t session, vhsm_key_handle_t key,
                       const uint8_t* data, size_t data_len,
                       uint8_t* signature, size_t* signature_len);
```

**File Storage:**
```c
vhsm_error_t vhsm_file_store(vhsm_session_t session, vhsm_key_handle_t key,
                              const char* file_path, char* token_out);
vhsm_error_t vhsm_file_retrieve(vhsm_session_t session, vhsm_key_handle_t key,
                                 const char* token, const char* dest_path);
```

See `include/vhsm.h` for complete API documentation.

### CLI Usage

The original `virtual_hsm` binary provides basic command-line operations:

**Compilation:**
```bash
gcc -o virtual_hsm virtual_hsm.c -lcrypto
```

**Master Key Generation:**
```bash
# Generate master key (display only)
./virtual_hsm -generate_master_key

# Generate and store master key
./virtual_hsm -generate_master_key store_key
```

**Key Management:**
```bash
# Store a symmetric key (64 hex characters = 32 bytes)
echo -n "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" | \
  ./virtual_hsm -store mykey

# Generate random key
openssl rand -hex 32 | ./virtual_hsm -store randomkey

# Retrieve a key
./virtual_hsm -retrieve mykey

# List all keys
./virtual_hsm -list
```

**Digital Signatures:**
```bash
# Generate key pair
./virtual_hsm -generate_key_pair signing_key

# Sign data
echo -n "Important message" | ./virtual_hsm -sign signing_key -o signature.bin

# Verify signature
./virtual_hsm -verify signing_key -i message.txt -s signature.bin
```

**Custom Keystore:**
```bash
# Use custom keystore and master key files
./virtual_hsm -keystore custom.dat -master custom.key -list

# Use master key from GitHub Secrets
./virtual_hsm -master_key ${{ secrets.MASTER_KEY }} -store api_key
```

### Enhanced HSM

The enhanced HSM (`hsm_enhanced`) provides additional security features:

**Build:**
```bash
gcc -o hsm_enhanced hsm_enhanced.c -lcrypto -lssl
```

**Features:**
- Key lifecycle management with rotation
- Comprehensive audit logging
- Access control and user identification
- Hardware security module detection
- Secure memory management

**Usage:**
```bash
# Scan for hardware security modules
./hsm_enhanced -scan_hardware

# Set user identity for audit logging
./hsm_enhanced -set_user "admin@example.com"

# View key metadata
./hsm_enhanced -key_info mykey

# Rotate encryption key
./hsm_enhanced -rotate_key mykey

# View audit logs (last 7 days)
./hsm_enhanced -audit_logs 7
```

### REST API Server

Start the REST API server for remote access:

```bash
# Build server
make server

# Run server
bin/vhsm-server --port 8443 --storage ./hsm_data

# Run with TLS
bin/vhsm-server-tls --port 8443 --storage ./hsm_data \
  --cert server.crt --key server.key
```

**API Endpoints:**

```bash
# Get version
curl http://localhost:8443/api/version

# Create user
curl -X POST http://localhost:8443/api/user/create \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass123","role":"admin"}'

# Login
curl -X POST http://localhost:8443/api/session/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"pass123"}'
```

## Key Management

### Key Types Supported

- **AES-128**: 128-bit symmetric encryption
- **AES-256**: 256-bit symmetric encryption (recommended)
- **ED25519**: Edwards-curve digital signatures
- **HMAC**: Message authentication codes
- **RSA**: RSA public-key cryptography (2048-4096 bit)
- **ECDSA**: Elliptic curve digital signatures

### Key Lifecycle States

- **PRE_ACTIVE**: Key created but not yet active
- **ACTIVE**: Key is currently usable
- **DEPRECATED**: Key still usable but scheduled for retirement
- **COMPROMISED**: Key suspected of compromise, should not be used
- **DESTROYED**: Key has been securely erased

### Key Rotation

Automatic key rotation based on policies:

```c
// Rotate key when needed
vhsm_key_rotate(session, key_handle, &new_key_handle);

// Enhanced HSM automatic rotation (90-day default)
./hsm_enhanced -rotate_key encryption_key
```

## Digital Signatures

### ED25519 Signatures

```bash
# Generate signing key pair
./virtual_hsm -generate_key_pair signer

# Sign a file
./virtual_hsm -sign signer -i document.pdf -o document.sig

# Verify signature
./virtual_hsm -verify signer_public -i document.pdf -s document.sig
```

### Public Key Export/Import

```bash
# Export public key
./virtual_hsm -export_public_key signer_public -o public.pem

# Import public key
./virtual_hsm -import_public_key trusted_key -i public.pem
```

## File Storage

The Virtual HSM provides secure file storage with encryption and chunking:

### Using the Library API

```c
// Store a file
char token[128];
vhsm_file_store(session, encryption_key, "sensitive.doc", token);
printf("File stored with token: %s\n", token);

// Retrieve the file
vhsm_file_retrieve(session, encryption_key, token, "./retrieved.doc");
```

### Using the Token Tool

```bash
# Generate encryption key
./token/token generate-key master.key

# Store a file
./token/token store document.pdf --key master.key
# Returns: Token: 550e8400-e29b-41d4-a716-446655440000

# Retrieve file
./token/token retrieve 550e8400-e29b-41d4-a716-446655440000 ./output/ --key master.key
```

**Features:**
- Random-size chunking (4KB-16KB) for obfuscation
- Per-chunk AES-256-GCM encryption
- Optional zlib compression
- Progress tracking for large files
- UUID-based token system

## Security Features

### Secure Memory Management

```c
// Memory is locked to prevent swapping
secure_lock_memory(key_buffer, key_size);

// Keys are explicitly wiped after use
secure_wipe(key_buffer, key_size);
```

### Hardware Security Module Detection

```bash
$ ./hsm_enhanced -scan_hardware

=== Scanning for HSM Hardware ===

1. FIDO2/U2F Devices (YubiKey, etc.):
   ✗ No HID devices found

2. Trusted Platform Module (TPM):
   ✓ TPM device detected at /dev/tpm0

3. PKCS#11 Tokens:
   ✗ No PKCS#11 libraries found

4. Smart Cards (OpenSC):
   ✗ OpenSC not found

=== Software Security Features ===
✓ AES-256-GCM encryption
✓ ED25519 digital signatures
✓ Secure memory management
✓ Audit logging enabled
```

### Audit Logging

All operations are logged with:
- Timestamp
- Event type (13 types tracked)
- Key/resource affected
- User who performed the action
- Operation details
- Success/failure status

**Event Types:**
- KEY_CREATED, KEY_ACCESSED, KEY_ROTATED
- SIGN_OPERATION, VERIFY_OPERATION
- ENCRYPT_OPERATION, DECRYPT_OPERATION
- FILE_STORED, FILE_RETRIEVED
- USER_CREATED, SESSION_LOGIN, SESSION_LOGOUT
- CONFIG_CHANGE

**Query Audit Logs:**
```bash
# View last 30 days
./hsm_enhanced -audit_logs 30

# Example output:
2025-11-21 10:30:45|KEY_CREATED|encryption_key|admin@example.com|AES-256 key generated|SUCCESS
2025-11-21 10:31:12|ENCRYPT_OPERATION|encryption_key|user@example.com|File encrypted|SUCCESS
```

## GitHub Actions Integration

### Using Master Key from Secrets

```yaml
name: HSM Operations
on: [push]

jobs:
  secure-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build HSM
        run: gcc -o virtual_hsm virtual_hsm.c -lcrypto

      - name: Store API Key
        run: |
          echo ${{ secrets.API_KEY }} | ./virtual_hsm \
            -master_key ${{ secrets.MASTER_KEY }} \
            -store service_key

      - name: Sign Release
        run: |
          ./virtual_hsm \
            -master_key ${{ secrets.MASTER_KEY }} \
            -sign release_key \
            -i release.zip \
            -o release.sig
```

### Generating Master Key for Secrets

```bash
# Generate and display master key for GitHub Secrets
./virtual_hsm -generate_master_key

# Output:
# Generated Master Key (hex format for GitHub Secret):
# a1b2c3d4e5f6...
```

Add this value to your repository secrets as `MASTER_KEY`.

## Building from Source

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential libssl-dev zlib1g-dev uuid-dev libsodium-dev
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc openssl-devel zlib-devel libuuid-devel libsodium-devel
```

**Optional (for FIDO2/YubiKey support):**
```bash
sudo apt-get install libfido2-dev libjson-c-dev
```

### Build Commands

```bash
# Build everything
make all

# Build specific components
make lib          # Libraries only
make cli          # CLI binary
make server       # REST API server
make server-tls   # TLS REST API server
make examples     # Example programs

# Build with tests
make test-all     # Build and run all tests

# Clean build
make clean
```

### Build Output

```
lib/libvhsm.a       # Static library
lib/libvhsm.so      # Shared library
bin/vhsm            # CLI application
bin/vhsm-server     # REST API server
bin/vhsm-server-tls # TLS REST server
bin/example_basic   # Example program
```

## Testing

### Run All Tests

```bash
# Run all unit and integration tests
make test-all

# Run specific test suites
make test-crypto        # Cryptographic operations
make test-he            # Homomorphic encryption
make test-integration   # Integration tests
make test-cli           # CLI interface tests
make test-rest          # REST API tests
```

### Test Coverage

- ✅ Cryptographic operations (encryption, signing, verification)
- ✅ Key generation and management
- ✅ User authentication and sessions
- ✅ Audit logging
- ✅ File storage operations
- ✅ CLI interface
- ✅ REST API endpoints

### CI/CD Testing

All tests run automatically on every push via GitHub Actions:
- Unit tests
- Integration tests
- Cross-platform compilation (Linux, Windows)
- Security scanning
- API compliance checks

## Documentation

### API Documentation

Complete API documentation is available in header files:
- `include/vhsm.h` - Main API functions
- `include/vhsm_types.h` - Type definitions and constants

### Examples

See the `examples/` directory for:
- Basic usage examples
- Multi-user scenarios
- File encryption workflows
- Integration examples

### Additional Resources

- [GitHub Actions Workflows](.github/workflows/)
- [Test Suite](tests/)
- [Server Implementation](server/)

## Known Limitations

This is a **virtual HSM** for development and educational purposes. It lacks several features of production HSMs:

### Security Limitations
- ❌ No hardware-backed key storage
- ❌ No tamper-resistant hardware
- ❌ No physical security protections
- ❌ Limited protection against side-channel attacks
- ❌ Keys stored in process memory (though with secure wiping)

### Performance Limitations
- Single-threaded for most operations (though thread-safe)
- No hardware acceleration
- Limited to software cryptography performance

### Feature Limitations
- No PKCS#11 interface (custom API only)
- Limited key types compared to enterprise HSMs
- No clustering or high-availability features
- No backup/restore mechanisms (manual file copy only)

### Recommended Alternatives for Production

For production systems, consider:
- **Hardware HSMs**: Thales, Entrust, Utimaco
- **Cloud HSM**: AWS CloudHSM, Azure Key Vault, Google Cloud KMS
- **TPM**: For device-specific key storage
- **Hardware Security Keys**: YubiKey, SoloKey for authentication

## License

This project is for educational and development purposes. See individual source files for license information.

## Support and Contributing

- **Issues**: Report bugs or request features via GitHub Issues
- **Pull Requests**: Contributions are welcome
- **Testing**: All PRs must pass CI/CD tests

## Version Information

- **Current Version**: 2.0.0
- **API Version**: 2.0
- **Protocol Version**: 2.0

For version history and changelog, see commit history on GitHub.
