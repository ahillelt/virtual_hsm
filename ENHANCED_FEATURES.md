# Enhanced Virtual HSM - Complete Feature Documentation

## Overview
This enhanced Virtual HSM provides production-grade security features including key lifecycle management, audit logging, access control, and hardware integration capabilities.

## Architecture

### Core Components

1. **virtual_hsm** - Original HSM with basic crypto operations
2. **hsm_enhanced** - Enhanced HSM with advanced security features
3. **token/** - Secure file storage system with chunked encryption
4. **passkey.c** - FIDO2/YubiKey integration (requires libfido2-dev)

### Security Frameworks

- **hsm_security.h** - Lifecycle management, audit logging, access control
- **token/security_defs.h** - Secure memory, key derivation, encryption
- **token/crypto_ops.h** - Advanced cryptographic operations

## Enhanced Features

### 1. Key Lifecycle Management

**Automatic Key Rotation**
- Keys tracked with creation, last-used, and last-rotated timestamps
- Configurable rotation policies (default: 90 days)
- Automatic deprecation of old keys
- Version tracking for rotated keys

**Key States**
- `ACTIVE` - Key is in use
- `DEPRECATED` - Key rotated, old version backed up
- `COMPROMISED` - Key marked as potentially compromised
- `DESTROYED` - Key securely wiped
- `PRE_ACTIVE` - Key generated but not yet activated

**Usage**
```bash
# Rotate a key
./hsm_enhanced -rotate_key my_key

# View key metadata
./hsm_enhanced -key_info my_key

# Output shows:
# - Creation date
# - Last used
# - Last rotated
# - Rotation version
# - Use count
# - Days since rotation
# - Rotation warnings
```

### 2. Comprehensive Audit Logging

**Logged Events**
- Key creation, access, modification, deletion
- Key rotation events
- Authentication success/failure
- Sign and verify operations
- Encryption and decryption
- Configuration changes
- Security violations

**Audit Log Format**
```
timestamp|event_type|key_name|user_id|details|success
2025-11-21 10:15:30|KEY_CREATED|test_key|alice@example.com|Symmetric key stored|SUCCESS
2025-11-21 10:16:45|KEY_ROTATED|test_key|alice@example.com|Key rotated to version 2|SUCCESS
```

**Usage**
```bash
# View last 7 days of audit logs (default)
./hsm_enhanced -audit_logs

# View last 30 days
./hsm_enhanced -audit_logs 30

# Parse audit logs
grep "KEY_ROTATED" hsm_audit.log
grep "FAILURE" hsm_audit.log
```

### 3. Access Control and Authentication

**User-Based Access Control**
- Per-user authentication tracking
- User ID set per session
- Access control entries (ACE) support
- Operation-level permissions

**Usage**
```bash
# Set user ID for session
./hsm_enhanced -set_user alice@example.com

# All subsequent operations logged with this user ID
./hsm_enhanced -store my_key
./hsm_enhanced -rotate_key my_key
```

### 4. Secure Memory Management

**Features**
- Secure memory allocation with zeroing
- Memory locking to prevent swapping (platform-dependent)
- Explicit memory wiping after use
- Protection against compiler optimization

**Implementation**
```c
// Allocate secure memory
void* ptr = secure_malloc(KEY_SIZE);

// Wipe before freeing
secure_memzero(ptr, KEY_SIZE);
secure_free(ptr, KEY_SIZE);
```

### 5. Hardware HSM Detection

**Supported Hardware**
- FIDO2/U2F devices (YubiKey, etc.)
- Trusted Platform Module (TPM)
- PKCS#11 tokens
- Smart cards (OpenSC)

**Usage**
```bash
./hsm_enhanced -scan_hardware

# Output shows:
# - Detected FIDO2 devices
# - TPM availability
# - PKCS#11 libraries
# - Smart card support
# - Software security features
```

### 6. Secure File Storage (Token System)

The token system provides chunked file encryption with token-based retrieval.

**Features**
- Chunked encryption (8KB blocks)
- AES-256-GCM encryption
- UUID token generation
- Metadata tracking
- Progress indicators
- Secure key management

**Usage**
```bash
# Generate master key for file encryption
./token/token generate-key file_master.key

# Encrypt a file
./token/token store confidential.pdf --key file_master.key
# Returns: Token: 4297e228-8710-4bf4-b9b7-2981f77570d5

# Decrypt the file
./token/token retrieve 4297e228-8710-4bf4-b9b7-2981f77570d5 output_dir/ --key file_master.key

# Auto-generate key
./token/token store secret.txt
# Automatically creates key file and returns token
```

### 7. FIDO2/YubiKey Support (Optional)

**Requirements**
```bash
sudo apt-get install libfido2-dev libjson-c-dev
gcc -o passkey_tool passkey.c -lfido2 -ljson-c -lcrypto
```

**Features**
- Passkey generation and storage
- FIDO2 authentication
- Credential management
- PIN protection
- Device capabilities checking

**Usage**
```bash
./passkey_tool generate <credential_name>
./passkey_tool authenticate <credential_name>
./passkey_tool list
```

### 8. Protection Against Key Overwriting

**Implementation**
- Duplicate name detection on key creation
- Metadata verification before operations
- Backup creation during rotation
- Checksums for integrity verification

**Example**
```bash
# Attempting to create duplicate key
./hsm_enhanced -store existing_key
# Output: "Duplicate Name, Cannot generate"
```

### 9. Undefined Behavior Protection

**Measures**
- Comprehensive input validation
- Bounds checking on all array access
- Null pointer checks
- Safe string operations (strncpy, snprintf)
- Error handling on all system calls
- Secure cleanup on failure paths

### 10. Data-in-Use Encryption

**Token System Features**
- Memory-resident encryption keys
- Sodium library for secure operations
- Key derivation (PBKDF2, 100,000 iterations)
- Encrypted metadata
- Secure random number generation

## Integration Examples

### GitHub Secrets Integration

```yaml
name: Secure Operations
on: [push]

jobs:
  secure-job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup HSM
        run: |
          gcc -o hsm_enhanced hsm_enhanced.c -lcrypto -lssl

      - name: Generate Keys
        run: |
          ./hsm_enhanced -generate_master_key store_key
          ./hsm_enhanced -generate_key_pair signing_key

      - name: Store Secret
        run: |
          echo ${{ secrets.API_KEY }} | ./hsm_enhanced \
            -master_key ${{ secrets.MASTER_KEY }} \
            -store api_key

      - name: Sign Release
        run: |
          ./hsm_enhanced -master_key ${{ secrets.MASTER_KEY }} \
            -sign signing_key -i release.tar.gz -o release.sig

      - name: View Audit Log
        run: ./hsm_enhanced -audit_logs 1
```

### HashiCorp Vault Integration

```bash
#!/bin/bash
# Store HSM master key in Vault
MASTER_KEY=$(./hsm_enhanced -generate_master_key | grep "hex format" | awk '{print $NF}')
vault kv put secret/hsm/master-key value="$MASTER_KEY"

# Retrieve and use
MASTER_KEY=$(vault kv get -field=value secret/hsm/master-key)
echo "$SECRET_DATA" | ./hsm_enhanced -master_key "$MASTER_KEY" -store my_secret

# Audit logging to Vault
cat hsm_audit.log | vault write secret/hsm/audit-log data=-
```

### AWS Secrets Manager Integration

```bash
#!/bin/bash
# Store master key in AWS Secrets Manager
MASTER_KEY=$(./hsm_enhanced -generate_master_key | grep "hex format" | awk '{print $NF}')
aws secretsmanager create-secret \
    --name hsm-master-key \
    --secret-string "$MASTER_KEY"

# Retrieve and use
MASTER_KEY=$(aws secretsmanager get-secret-value \
    --secret-id hsm-master-key \
    --query SecretString --output text)

./hsm_enhanced -master_key "$MASTER_KEY" -generate_key_pair prod_signing_key
```

## Security Best Practices

### Key Management

1. **Rotate keys regularly** (90-day default, adjust based on risk)
2. **Use separate keystores** for different environments
3. **Monitor audit logs** for suspicious activity
4. **Backup deprecated keys** during rotation
5. **Secure master key** using external secret management

### Access Control

1. **Set user IDs** for all operations
2. **Review audit logs** regularly
3. **Implement least privilege** access
4. **Monitor failed operations**

### Hardware Security

1. **Use TPM** when available
2. **Enable YubiKey** for critical operations
3. **Lock memory pages** to prevent swapping
4. **Use secure hardware** for production keys

### Operational Security

1. **Enable audit logging** for all environments
2. **Monitor key metadata** and rotation schedules
3. **Test backup and recovery** procedures
4. **Implement key destruction** policies
5. **Regular security audits**

## Performance Considerations

### Token File Storage
- Chunked processing: 8KB blocks
- Progress indicators for large files
- Parallel chunk encryption (configurable)
- Memory-efficient streaming

### Key Operations
- Cached metadata for performance
- Lazy loading of keystores
- Optimized crypto operations
- Hardware acceleration when available

## Testing

### Comprehensive Test Suite

```bash
# Test enhanced HSM
bash test_enhanced.sh

# Test token file storage
cd token && bash test_token_storage.sh

# Test original HSM compatibility
bash test_all_readme_features.sh
```

### Continuous Integration

The GitHub Actions workflow tests:
- Basic HSM operations
- Enhanced security features
- Cross-platform compilation
- Token file storage
- Audit logging
- Key rotation

## Migration Guide

### From Basic HSM to Enhanced HSM

1. **Backup existing keystore**
   ```bash
   cp keystore.dat keystore.dat.backup
   cp master.key master.key.backup
   ```

2. **Initialize metadata for existing keys**
   ```bash
   ./hsm_enhanced -list | while read key; do
       ./hsm_enhanced -key_info "$key"
   done
   ```

3. **Start using enhanced features**
   ```bash
   ./hsm_enhanced -set_user youruser@example.com
   ./hsm_enhanced -audit_logs
   ```

4. **Establish rotation schedule**
   ```bash
   # Check all keys for rotation needs
   ./hsm_enhanced -list | while read key; do
       ./hsm_enhanced -key_info "$key" | grep "WARNING"
   done
   ```

## Troubleshooting

### Memory Locking Warnings
```
WARNING: Failed to lock memory pages
```
**Solution**: Run with elevated privileges or adjust ulimit
```bash
ulimit -l unlimited
# or
sudo ./hsm_enhanced <command>
```

### Missing FIDO2 Support
```
fatal error: fido.h: No such file or directory
```
**Solution**: Install FIDO2 library
```bash
sudo apt-get install libfido2-dev libjson-c-dev
```

### Audit Log Permissions
```
Error: Cannot initialize audit log
```
**Solution**: Check file permissions
```bash
chmod 600 hsm_audit.log
```

## Future Enhancements

Planned features:
- Network HSM support (PKCS#11 over network)
- Multi-factor authentication
- Key ceremony support
- Threshold signatures
- Hardware security module clustering
- Real-time monitoring dashboard
- Integration with SIEM systems

## License

See LICENSE file for details.

## Contributing

Contributions welcome! Please ensure:
- All tests pass
- Audit logging for new features
- Security review for crypto changes
- Documentation updates
- Backward compatibility

## Support

For issues, questions, or contributions:
- GitHub Issues
- Security issues: [security@example.com]
- Documentation: This file and README.md
