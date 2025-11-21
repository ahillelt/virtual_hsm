# Virtual HSM - Feature Addendum

## File Operations (Previously Missing from README)

The Virtual HSM includes a comprehensive secure file storage system through the `token` utility, which provides chunked encryption for large files.

### Features

- **Chunked Encryption**: Files are encrypted in 8KB blocks using AES-256-GCM
- **Token-Based Retrieval**: UUID tokens for secure file access
- **Master Key Support**: Custom or auto-generated encryption keys
- **Progress Indicators**: Real-time progress for large files
- **Metadata Preservation**: Original filenames and structure maintained
- **Secure Storage**: Encrypted chunks stored separately

### Token System Usage

#### Generate Master Key
```bash
./token/token generate-key mykey.key
```

#### Encrypt a File
```bash
# With custom key
./token/token store confidential.pdf --key mykey.key

# Returns:
# Token: 4297e228-8710-4bf4-b9b7-2981f77570d5
# Keep this token safe - you'll need it to retrieve your file

# With auto-generated key
./token/token store secret.txt
# Key saved to: auto_generated_key_<uuid>.key
```

#### Decrypt a File
```bash
./token/token retrieve 4297e228-8710-4bf4-b9b7-2981f77570d5 output_directory/ --key mykey.key

# File is decrypted to: output_directory/original_filename.ext
```

### File Storage Architecture

```
Input File → Chunker → AES-256-GCM Encryption → Secure Storage
             (8KB)       (per chunk)              (separate chunks)

Metadata:
- Token (UUID)
- Original filename
- File size
- Chunk count
- Encryption parameters
- Checksum

Retrieval:
Token → Load Metadata → Decrypt Chunks → Reassemble → Verify → Output File
```

### Security Features

1. **Chunk Isolation**: Each chunk encrypted separately
2. **Unique IVs**: Different IV for each chunk
3. **Integrity Verification**: SHA-256 checksums for each chunk
4. **Secure Deletion**: Chunks can be individually wiped
5. **Access Control**: Token required for retrieval
6. **Audit Trail**: Operations logged

### Example: Secure Document Management

```bash
#!/bin/bash
# Secure document management workflow

# Initialize
./token/token generate-key doc_master.key

# Store documents
TOKEN1=$(./token/token store contract.pdf --key doc_master.key | grep "Token:" | awk '{print $2}')
TOKEN2=$(./token/token store financial_report.xlsx --key doc_master.key | grep "Token:" | awk '{print $2}')

# Save tokens securely
echo "$TOKEN1" > .contract_token
echo "$TOKEN2" > .report_token
chmod 600 .contract_token .report_token

# Later retrieval
./token/token retrieve $(cat .contract_token) retrieved_docs/ --key doc_master.key
```

## Enhanced Security Features

### Key Lifecycle Management

**Automatic Rotation**
```bash
# Check if key needs rotation
./hsm_enhanced -key_info my_key

# Rotate key
./hsm_enhanced -rotate_key my_key
```

**Key Metadata**
- Creation timestamp
- Last used timestamp
- Last rotated timestamp
- Rotation version number
- Use count
- State (ACTIVE, DEPRECATED, etc.)

### Audit Logging

**Automatic Logging**
All operations are automatically logged:
```bash
# View recent logs
./hsm_enhanced -audit_logs 7

# View specific events
grep "KEY_ROTATED" hsm_audit.log
grep "FAILURE" hsm_audit.log

# Export for analysis
cat hsm_audit.log | grep -v "^#" > audit_export.csv
```

**Logged Events**
- Key operations (create, access, modify, delete, rotate)
- Authentication attempts
- Signing and verification operations
- Encryption and decryption
- Configuration changes
- Security violations

### Access Control

**User-Based Operations**
```bash
# Set user context
./hsm_enhanced -set_user alice@example.com

# All operations logged with user ID
./hsm_enhanced -generate_key_pair my_signing_key
# Audit: KEY_CREATED|my_signing_key|alice@example.com|...
```

### Hardware Integration

**Detection**
```bash
./hsm_enhanced -scan_hardware
```

Detects:
- FIDO2/YubiKey devices
- TPM (Trusted Platform Module)
- PKCS#11 tokens
- Smart cards (OpenSC)

**YubiKey/FIDO2 Support** (requires libfido2-dev)
```bash
# Install dependencies
sudo apt-get install libfido2-dev libjson-c-dev

# Compile passkey tool
gcc -o passkey_tool passkey.c -lfido2 -ljson-c -lcrypto

# Generate FIDO2 credential
./passkey_tool generate my_credential

# Authenticate
./passkey_tool authenticate my_credential
```

## External Integrations

### GitHub Actions/Secrets

```yaml
# .github/workflows/secure-release.yml
name: Secure Release

on:
  push:
    tags:
      - 'v*'

jobs:
  sign-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup HSM
        run: gcc -o hsm_enhanced hsm_enhanced.c -lcrypto -lssl

      - name: Sign Release
        env:
          MASTER_KEY: ${{ secrets.HSM_MASTER_KEY }}
        run: |
          ./hsm_enhanced -master_key "$MASTER_KEY" \
            -sign release_key -i release.tar.gz -o release.sig

      - name: Upload Signature
        uses: actions/upload-artifact@v4
        with:
          name: release-signature
          path: release.sig
```

### HashiCorp Vault

```bash
#!/bin/bash
# vault_integration.sh

# Initialize Vault
vault kv put secret/hsm/master-key \
    value="$(./hsm_enhanced -generate_master_key | grep hex | awk '{print $NF}')"

# Use HSM with Vault-stored key
MASTER_KEY=$(vault kv get -field=value secret/hsm/master-key)

# Perform operations
./hsm_enhanced -master_key "$MASTER_KEY" -generate_key_pair vault_key

# Store audit logs in Vault
vault kv put secret/hsm/audit-log \
    data="$(base64 < hsm_audit.log)"
```

### AWS Secrets Manager

```bash
#!/bin/bash
# aws_integration.sh

# Store master key
MASTER_KEY=$(./hsm_enhanced -generate_master_key | grep hex | awk '{print $NF}')
aws secretsmanager create-secret \
    --name hsm-master-key \
    --secret-string "$MASTER_KEY" \
    --description "Virtual HSM Master Key"

# Retrieve and use
MASTER_KEY=$(aws secretsmanager get-secret-value \
    --secret-id hsm-master-key \
    --query SecretString --output text)

# Generate production signing key
./hsm_enhanced -master_key "$MASTER_KEY" \
    -set_user "aws-automation@example.com"
./hsm_enhanced -master_key "$MASTER_KEY" \
    -generate_key_pair prod_signing_key

# Export audit logs to CloudWatch
aws logs put-log-events \
    --log-group-name /hsm/audit \
    --log-stream-name $(date +%Y-%m-%d) \
    --log-events file://hsm_audit.log
```

### Azure Key Vault

```bash
#!/bin/bash
# azure_integration.sh

# Store master key in Azure
MASTER_KEY=$(./hsm_enhanced -generate_master_key | grep hex | awk '{print $NF}')
az keyvault secret set \
    --vault-name my-hsm-vault \
    --name hsm-master-key \
    --value "$MASTER_KEY"

# Retrieve and use
MASTER_KEY=$(az keyvault secret show \
    --vault-name my-hsm-vault \
    --name hsm-master-key \
    --query value -o tsv)

# Operations
./hsm_enhanced -master_key "$MASTER_KEY" -generate_key_pair azure_key
```

## Production Deployment

### System Requirements

**Minimum**
- Linux kernel 3.2+
- OpenSSL 1.1.1+
- 512MB RAM
- 100MB disk space

**Recommended**
- Linux kernel 5.0+
- OpenSSL 3.0+
- 2GB RAM
- 1GB disk space
- TPM 2.0
- Hardware security module

**Optional**
- YubiKey/FIDO2 device (libfido2-dev)
- libsodium (for token system)
- PKCS#11 libraries
- Smart card readers

### Security Hardening

```bash
#!/bin/bash
# hardening.sh - Production security setup

# 1. Set strict permissions
chmod 700 /opt/hsm
chmod 600 /opt/hsm/master.key
chmod 600 /opt/hsm/keystore.dat
chmod 600 /opt/hsm/hsm_audit.log

# 2. Create dedicated user
sudo useradd -r -s /bin/false hsm-service
sudo chown -R hsm-service:hsm-service /opt/hsm

# 3. Enable memory locking
echo "hsm-service soft memlock unlimited" >> /etc/security/limits.conf
echo "hsm-service hard memlock unlimited" >> /etc/security/limits.conf

# 4. Setup audit log rotation
cat > /etc/logrotate.d/hsm-audit << 'EOF'
/opt/hsm/hsm_audit.log {
    daily
    rotate 90
    compress
    delaycompress
    notifempty
    create 600 hsm-service hsm-service
}
EOF

# 5. Enable TPM if available
if [ -e /dev/tpm0 ]; then
    sudo apt-get install tpm2-tools
    tpm2_clear
fi

# 6. Configure firewall (if network access needed)
sudo ufw deny 22/tcp  # Disable SSH on HSM server
sudo ufw enable

# 7. Disable unnecessary services
sudo systemctl disable ssh
sudo systemctl disable cups
sudo systemctl disable bluetooth
```

### Monitoring and Alerting

```bash
#!/bin/bash
# monitoring.sh - HSM monitoring

# Check key rotation schedule
./hsm_enhanced -list | while read key; do
    if ./hsm_enhanced -key_info "$key" | grep -q "WARNING.*rotation"; then
        echo "ALERT: Key $key needs rotation" | mail -s "HSM Alert" admin@example.com
    fi
done

# Monitor failed authentications
FAILURES=$(grep "AUTH_FAILURE" hsm_audit.log | wc -l)
if [ "$FAILURES" -gt 5 ]; then
    echo "ALERT: $FAILURES failed authentications" | mail -s "HSM Security Alert" security@example.com
fi

# Check disk space for encrypted files
USAGE=$(df -h /opt/hsm/secure_storage | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$USAGE" -gt 80 ]; then
    echo "ALERT: HSM storage at ${USAGE}%" | mail -s "HSM Storage Alert" ops@example.com
fi

# Verify audit log integrity
if ! grep -q "$(date +%Y-%m-%d)" hsm_audit.log; then
    echo "WARNING: No audit entries today" | mail -s "HSM Audit Warning" security@example.com
fi
```

## Performance Tuning

### Large File Encryption

```bash
# Optimize chunk size for large files
export TOKEN_CHUNK_SIZE=65536  # 64KB for large files

# Parallel processing (if supported)
export TOKEN_PARALLEL_CHUNKS=4

# Encrypt large file
./token/token store large_file.iso --key mykey.key
```

### Batch Operations

```bash
#!/bin/bash
# batch_sign.sh - Sign multiple files efficiently

MASTER_KEY=$(cat master_key.hex)

find ./documents -name "*.pdf" | while read file; do
    ./hsm_enhanced -master_key "$MASTER_KEY" \
        -sign document_key \
        -i "$file" \
        -o "${file}.sig"
done
```

### Key Caching

```bash
# Export master key once
export HSM_MASTER_KEY=$(cat master.key | xxd -p | tr -d '\n')

# Use for multiple operations (same session)
./hsm_enhanced -master_key "$HSM_MASTER_KEY" -generate_key_pair key1
./hsm_enhanced -master_key "$HSM_MASTER_KEY" -generate_key_pair key2
./hsm_enhanced -master_key "$HSM_MASTER_KEY" -generate_key_pair key3

# Clear when done
unset HSM_MASTER_KEY
```

## Compliance and Standards

### FIPS 140-2 Considerations

- Uses FIPS-approved algorithms (AES-256, ED25519)
- Secure key generation (OpenSSL RAND_bytes)
- Key isolation and protection
- Audit logging for compliance
- Secure memory management

### PCI-DSS Requirements

- Strong cryptography (AES-256-GCM)
- Key rotation mechanisms
- Audit trail for key access
- Secure key storage
- Access control implementation

### GDPR Data Protection

- Encryption at rest (token system)
- Data erasure capabilities
- Audit logging for data access
- User identification
- Right to be forgotten support

## Troubleshooting Guide

### Common Issues

**Issue**: Keys not rotating
```bash
# Check metadata
./hsm_enhanced -key_info my_key

# Manual rotation
./hsm_enhanced -rotate_key my_key
```

**Issue**: Audit log not updating
```bash
# Check permissions
ls -l hsm_audit.log

# Reinitialize
rm hsm_audit.log
./hsm_enhanced -generate_master_key
```

**Issue**: Token retrieval fails
```bash
# Verify token
echo "$TOKEN" | grep -E '^[0-9a-f-]{36}$'

# Check metadata
ls -l secure_storage/*.metadata

# Verify key
./token/token retrieve $TOKEN test_output/ --key mykey.key
```

**Issue**: Memory locking warnings
```bash
# Check limits
ulimit -l

# Increase limit
ulimit -l unlimited

# Or run with sudo
sudo ./hsm_enhanced <command>
```

## Migration and Backup

### Backup Strategy

```bash
#!/bin/bash
# backup.sh - Complete HSM backup

BACKUP_DIR="/backup/hsm/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup keystores
cp keystore.dat "$BACKUP_DIR/"
cp master.key "$BACKUP_DIR/"

# Backup metadata
cp .*.metadata "$BACKUP_DIR/"

# Backup audit logs
cp hsm_audit.log "$BACKUP_DIR/"

# Backup encrypted files
tar czf "$BACKUP_DIR/secure_storage.tar.gz" secure_storage/

# Encrypt backup
openssl enc -aes-256-cbc -salt \
    -in "$BACKUP_DIR.tar.gz" \
    -out "$BACKUP_DIR.tar.gz.enc" \
    -pass file:/root/backup_key.txt

# Verify
tar tzf "$BACKUP_DIR/secure_storage.tar.gz" > /dev/null && echo "Backup OK"
```

### Disaster Recovery

```bash
#!/bin/bash
# restore.sh - Restore from backup

BACKUP_DIR="/backup/hsm/20251121"

# Stop HSM operations
systemctl stop hsm-service

# Restore keystores
cp "$BACKUP_DIR/keystore.dat" /opt/hsm/
cp "$BACKUP_DIR/master.key" /opt/hsm/

# Restore metadata
cp "$BACKUP_DIR"/.*.metadata /opt/hsm/

# Restore audit logs
cp "$BACKUP_DIR/hsm_audit.log" /opt/hsm/

# Restore encrypted files
tar xzf "$BACKUP_DIR/secure_storage.tar.gz" -C /opt/hsm/

# Verify
./hsm_enhanced -list
./hsm_enhanced -audit_logs 1

# Restart
systemctl start hsm-service
```

## Support and Resources

- **Documentation**: README.md, ENHANCED_FEATURES.md, this file
- **Examples**: See example scripts in this document
- **Testing**: Run comprehensive tests with `bash test_enhanced.sh`
- **Security**: Report security issues to security@example.com
- **Contributions**: Pull requests welcome on GitHub

## Version History

- **v2.0** - Enhanced HSM with lifecycle management, audit logging
- **v1.5** - Token file storage system
- **v1.0** - Original Virtual HSM with basic crypto operations
