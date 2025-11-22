# Virtual HSM Python Library

Python bindings for the Virtual HSM C library, providing enterprise-grade cryptographic key management, digital signatures, and secure storage.

## Features

- **Multi-user authentication** with role-based access control
- **Key management** - Generate, import, export, rotate, and delete cryptographic keys
- **Encryption/Decryption** - AES-256-GCM encryption
- **Digital Signatures** - ED25519, RSA, ECDSA support
- **Audit logging** - Complete audit trail for compliance
- **Session management** - Secure session handling with timeouts
- **Pure Python interface** - Uses ctypes, no compilation required

## Installation

### Prerequisites

1. Build the Virtual HSM C library:
   ```bash
   cd ..  # Go to project root
   make lib
   ```

2. Install the Python package:
   ```bash
   cd python
   pip install -e .
   ```

### Library Path

The Python library will automatically search for `libvhsm.so` in:
- `./lib/libvhsm.so`
- `../lib/libvhsm.so`
- `/usr/local/lib/libvhsm.so`
- `/usr/lib/libvhsm.so`

You can also set the `VHSM_LIB_PATH` environment variable:
```bash
export VHSM_LIB_PATH=/path/to/libvhsm.so
```

## Quick Start

```python
import vhsm

# Initialize HSM
hsm = vhsm.HSM('/tmp/hsm_storage')
hsm.generate_master_key()

# Create a user
hsm.create_user('alice', 'password123', role=vhsm.ROLE_ADMIN)

# Login and use HSM
with hsm.login('alice', 'password123') as session:
    # Generate encryption key
    key_handle = session.generate_key('my_key', vhsm.KEY_TYPE_AES_256)

    # Encrypt data
    ciphertext, iv = session.encrypt(key_handle, b'secret data')

    # Decrypt data
    plaintext = session.decrypt(key_handle, ciphertext, iv)
    print(plaintext)  # b'secret data'
```

## Usage Examples

### User Management

```python
import vhsm

hsm = vhsm.HSM('/tmp/hsm_storage')
hsm.generate_master_key()

# Create users with different roles
hsm.create_user('admin', 'admin_pass', role=vhsm.ROLE_ADMIN)
hsm.create_user('operator', 'op_pass', role=vhsm.ROLE_OPERATOR)
hsm.create_user('auditor', 'audit_pass', role=vhsm.ROLE_AUDITOR)

# Change password
hsm.change_password('admin', 'admin_pass', 'new_secure_pass')

# Delete user
hsm.delete_user('operator')
```

### Encryption and Decryption

```python
with hsm.login('admin', 'password') as session:
    # Generate AES-256 key
    key = session.generate_key('encryption_key', vhsm.KEY_TYPE_AES_256)

    # Encrypt
    plaintext = b'Sensitive information'
    ciphertext, iv = session.encrypt(key, plaintext)
    print(f"Encrypted: {ciphertext.hex()}")

    # Decrypt
    decrypted = session.decrypt(key, ciphertext, iv)
    assert decrypted == plaintext
```

### Digital Signatures

```python
with hsm.login('admin', 'password') as session:
    # Generate signing key
    signing_key = session.generate_key('sign_key', vhsm.KEY_TYPE_ED25519)

    # Sign document
    document = b'Important contract'
    signature = session.sign(signing_key, document)
    print(f"Signature: {signature.hex()}")

    # Verify signature
    try:
        is_valid = session.verify(signing_key, document, signature)
        print(f"Valid: {is_valid}")
    except vhsm.VHSMError as e:
        if e.code == vhsm.ERROR_INVALID_SIGNATURE:
            print("Invalid signature!")
```

### Key Types and Usage

```python
# Available key types
vhsm.KEY_TYPE_AES_128
vhsm.KEY_TYPE_AES_256
vhsm.KEY_TYPE_ED25519       # Digital signatures
vhsm.KEY_TYPE_RSA_2048      # RSA encryption/signing
vhsm.KEY_TYPE_RSA_3072
vhsm.KEY_TYPE_RSA_4096
vhsm.KEY_TYPE_ECDSA_P256    # ECDSA signatures
vhsm.KEY_TYPE_ECDSA_P384
vhsm.KEY_TYPE_ECDSA_P521
vhsm.KEY_TYPE_HMAC_SHA256   # HMAC
vhsm.KEY_TYPE_HMAC_SHA512

# Key usage flags (can be combined with |)
vhsm.KEY_USAGE_ENCRYPT
vhsm.KEY_USAGE_DECRYPT
vhsm.KEY_USAGE_SIGN
vhsm.KEY_USAGE_VERIFY
vhsm.KEY_USAGE_WRAP
vhsm.KEY_USAGE_UNWRAP
vhsm.KEY_USAGE_DERIVE
vhsm.KEY_USAGE_ALL

# Example: Key for signing only
signing_key = session.generate_key(
    'sign_only_key',
    vhsm.KEY_TYPE_ED25519,
    vhsm.KEY_USAGE_SIGN | vhsm.KEY_USAGE_VERIFY
)
```

### Audit Logging

```python
# Enable audit logging
hsm.enable_audit('/var/log/hsm_audit.log')

# All operations are now logged
with hsm.login('admin', 'password') as session:
    key = session.generate_key('audit_test', vhsm.KEY_TYPE_AES_256)
    # ... operations are logged ...

# Disable audit
hsm.disable_audit()
```

### Error Handling

```python
import vhsm

try:
    hsm = vhsm.HSM('/tmp/hsm_storage')
    with hsm.login('admin', 'wrong_password') as session:
        pass
except vhsm.VHSMError as e:
    print(f"Error: {e}")
    print(f"Error code: {e.code}")

    # Check specific errors
    if e.code == vhsm.ERROR_AUTH_FAILED:
        print("Authentication failed!")
    elif e.code == vhsm.ERROR_KEY_NOT_FOUND:
        print("Key not found!")
```

### Context Manager Best Practices

Always use context managers for sessions:

```python
# GOOD - Session automatically closed
with hsm.login('admin', 'password') as session:
    key = session.generate_key('test', vhsm.KEY_TYPE_AES_256)
    # Session closed automatically

# Also works - Manual close
session = hsm.login('admin', 'password')
try:
    key = session.generate_key('test', vhsm.KEY_TYPE_AES_256)
finally:
    session.close()
```

## Complete Example

See `examples/python/hsm_example.py` for a comprehensive example demonstrating:
- HSM initialization
- User management
- Key generation
- Encryption/decryption
- Digital signatures
- Signature verification
- Password changes
- Audit logging

Run the example:
```bash
cd examples/python
python hsm_example.py
```

## API Reference

### HSM Class

#### `HSM(storage_path: str)`
Initialize HSM with storage directory.

#### `generate_master_key() -> bytes`
Generate a new 32-byte master key.

#### `set_master_key(master_key: bytes)`
Set the master key (must be 32 bytes).

#### `create_user(username, password, pin=None, role=ROLE_USER)`
Create a new user.

#### `delete_user(username)`
Delete a user.

#### `change_password(username, old_password, new_password)`
Change user password.

#### `login(username, password, pin=None) -> Session`
Login and create a session.

#### `enable_audit(log_path)`
Enable audit logging to file.

#### `disable_audit()`
Disable audit logging.

#### `version() -> str` (static)
Get library version.

### Session Class

#### `generate_key(name, key_type, usage=KEY_USAGE_ALL) -> int`
Generate a new key, returns key handle.

#### `get_key(name) -> int`
Get existing key by name, returns key handle.

#### `delete_key(handle)`
Delete a key.

#### `encrypt(key_handle, plaintext) -> (ciphertext, iv)`
Encrypt data, returns ciphertext and IV.

#### `decrypt(key_handle, ciphertext, iv) -> bytes`
Decrypt data, returns plaintext.

#### `sign(key_handle, data) -> bytes`
Sign data, returns signature.

#### `verify(key_handle, data, signature) -> bool`
Verify signature, returns True if valid or raises VHSMError.

#### `is_valid() -> bool`
Check if session is still valid.

#### `close()`
Close the session (automatically called with context manager).

## Error Codes

Common error codes:
- `ERROR_AUTH_FAILED` - Authentication failed
- `ERROR_KEY_NOT_FOUND` - Key not found
- `ERROR_KEY_EXISTS` - Key already exists
- `ERROR_CRYPTO_FAILED` - Cryptographic operation failed
- `ERROR_INVALID_SIGNATURE` - Signature verification failed
- `ERROR_PERMISSION_DENIED` - Permission denied
- `ERROR_SESSION_INVALID` - Session invalid or expired
- `ERROR_INVALID_PARAM` - Invalid parameter

See `vhsm.py` for complete error code list.

## Requirements

- Python 3.7+
- Virtual HSM C library (libvhsm.so)
- Linux or Unix-like OS

## License

Same license as the Virtual HSM project (see main repository).

## Contributing

See the main Virtual HSM repository for contribution guidelines.
