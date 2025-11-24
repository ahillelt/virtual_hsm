# Security Policy and Guidelines

## Table of Contents
- [Security Overview](#security-overview)
- [Security Features](#security-features)
- [Security Fixes (November 2024)](#security-fixes-november-2024)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)
- [Secure Deployment Guide](#secure-deployment-guide)
- [Best Practices](#best-practices)
- [Security Considerations](#security-considerations)

## Security Overview

The Virtual HSM implements multiple layers of security controls to protect cryptographic keys and sensitive data. This document outlines the security features, recent fixes, and deployment best practices.

**IMPORTANT**: This is a virtual HSM intended for development, testing, and educational purposes. For production environments handling sensitive data, use hardware-backed HSMs or cloud HSM services.

## Security Features

### 1. Authentication & Authorization

#### Multi-Factor Authentication
- **Password-based authentication** using PBKDF2-HMAC-SHA512
  - 100,000 iterations for key derivation
  - 32-byte random salt per user
  - Minimum 8-character password requirement
- **Optional PIN support** for two-factor authentication
- **Role-Based Access Control (RBAC)**
  - User: Basic operations
  - Operator: Key management
  - Admin: Full system access
  - Auditor: Read-only audit access

#### Session Management
- **Secure session tokens** (128-bit cryptographically random)
- **Session timeout** (default: 1 hour, configurable)
- **Concurrent session limits** (configurable)
- **Automatic session cleanup** on timeout

#### Account Protection
- **Failed attempt tracking** (default: 3 attempts before lockout)
- **Account lockout mechanism** (configurable duration)
- **Password strength validation**

### 2. Cryptographic Security

#### Encryption
- **AES-256-GCM** for symmetric encryption
  - Authenticated encryption with additional data (AEAD)
  - Random IV generation for each operation
  - 128-bit authentication tags
- **Per-key encryption** for key storage
- **Per-chunk encryption** for file storage

#### Key Derivation
- **PBKDF2-HMAC-SHA256** for system keys
  - 100,000 iterations
  - Random 32-byte salts stored securely
  - Separate salts for audit and metadata encryption

#### Digital Signatures
- **ED25519** (Edwards-curve, 256-bit security)
- **RSA-2048/3072/4096** (configurable)
- **ECDSA P-256/P-384/P-521**

#### Random Number Generation
- **OpenSSL RAND_bytes** for all random generation
- **Cryptographically secure** random number generator
- **No predictable patterns** in IVs, salts, or session IDs

### 3. Key Management

#### Key Lifecycle
- **Five states**: Pre-active, Active, Deprecated, Compromised, Destroyed
- **Automatic rotation** (default: 90 days, configurable)
- **Key versioning** for rotation tracking
- **Secure key destruction** (cryptographic erasure)

#### Key Storage
- **Encrypted at rest** using master key
- **File permissions**: 0600 (owner read/write only)
- **No plaintext key material** in storage
- **Secure key wiping** before deallocation

#### Key Access Controls
- **Per-key usage policies** (encrypt, decrypt, sign, verify)
- **User-based access control** for keys
- **Audit logging** for all key operations

### 4. Memory Security

#### Secure Memory Management
```c
// Keys locked in memory (mlock)
// Prevents swapping to disk
secure_lock_memory(key_buffer, key_size);

// Volatile wiping (resistant to compiler optimization)
secure_wipe(key_buffer, key_size);
```

#### Features
- **Memory locking** (mlock) to prevent swapping
- **Explicit zeroing** using volatile pointers
- **Immediate wiping** after key use
- **No key material in core dumps**

### 5. Audit Logging

#### Comprehensive Event Tracking
- **17 event types** tracked:
  - Authentication: LOGIN, LOGOUT, AUTH_FAILED
  - Key operations: KEY_GENERATED, KEY_IMPORTED, KEY_EXPORTED, KEY_DELETED, KEY_ROTATED
  - Cryptographic: ENCRYPT, DECRYPT, SIGN, VERIFY
  - File operations: FILE_STORE, FILE_RETRIEVE
  - Administrative: CONFIG_CHANGED, ERROR

#### Audit Security
- **Encrypted audit logs** (AES-256-GCM)
- **Tamper-evident** through encryption
- **User attribution** for all operations
- **Timestamps** for compliance
- **Success/failure** tracking

#### Audit Log Format
```
timestamp|event_type|resource|user|details|status
2024-11-24 10:30:45|KEY_CREATED|encryption_key|admin@example.com|AES-256|SUCCESS
```

### 6. Network Security

#### TLS Configuration
- **TLS 1.2+ only** (no SSL, TLS 1.0/1.1)
- **Strong cipher suites**:
  ```
  ECDHE-ECDSA-AES256-GCM-SHA384
  ECDHE-RSA-AES256-GCM-SHA384
  ECDHE-ECDSA-AES128-GCM-SHA256
  ECDHE-RSA-AES128-GCM-SHA256
  ```
- **Perfect Forward Secrecy** (PFS) with ECDHE
- **No weak ciphers** (RC4, DES, 3DES, MD5, SHA1)

#### HTTP Security Headers
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
```

#### CORS Protection
- **Configurable allowed origins** (no wildcard `*`)
- **Environment-based configuration**
- **Default**: localhost only in development

### 7. Input Validation

#### Protection Against
- **Buffer overflows**: Bounded string operations
- **SQL injection**: Parameterized queries (if using SQL)
- **Command injection**: No system() calls with user input
- **Path traversal**: Path sanitization
- **Integer overflow**: Range validation

#### Validation Examples
```c
// Port validation
if (port < 1 || port > 65535) {
    return error;
}

// String copying with bounds
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';
```

## Security Fixes (November 2024)

### Critical Fixes

#### 1. Hardcoded Secrets Removed
**Issue**: GitHub Actions workflows contained hardcoded cryptographic keys
**Fix**: Migrated to GitHub Secrets with fallback for testing
```yaml
env:
  SECRETS_TEST: ${{ secrets.SECRETS_TEST || 'test-value' }}
```

#### 2. Weak Key Derivation Fixed
**Issue**: Used single SHA256 hash for key derivation
**Fix**: Implemented PBKDF2-HMAC-SHA256 with 100k iterations
```c
PKCS5_PBKDF2_HMAC(password, strlen(password),
                  salt, sizeof(salt),
                  100000,  // 100k iterations
                  EVP_sha256(),
                  32, derived_key);
```

#### 3. Test Keys in Production Code
**Issue**: Fallback to hardcoded test keys when storage fails
**Fix**: Fail securely instead of using test keys
```c
if (err != VHSM_SUCCESS) {
    secure_wipe(key_material, sizeof(key_material));
    return VHSM_ERROR_KEY_NOT_FOUND;  // No fallback
}
```

#### 4. CORS Wildcard Vulnerability
**Issue**: `Access-Control-Allow-Origin: *` allowed any origin
**Fix**: Configurable allowed origins with secure default
```c
const char* allowed_origin = getenv("VHSM_ALLOWED_ORIGIN");
if (!allowed_origin) {
    allowed_origin = "http://localhost:3000";  // Secure default
}
```

#### 5. Session ID Predictability
**Issue**: Session IDs were memory addresses (`%p`)
**Fix**: Cryptographically random 128-bit session IDs
```c
uint8_t session_id_bytes[16];
RAND_bytes(session_id_bytes, sizeof(session_id_bytes));
```

#### 6. Command Injection
**Issue**: `system()` calls with unsanitized paths
**Fix**: Replaced with safe execve() or removed

### High Severity Fixes

#### 7. Unsafe String Functions
**Issue**: `strcpy()`, `sprintf()` used without bounds
**Fix**: Replaced with `strncpy()`, `snprintf()`

#### 8. Information Disclosure
**Issue**: Verbose error messages exposed internal details
**Fix**: Generic error messages for external responses
```c
// Before: "{\"error\":\"Key not found in storage\"}"
// After:  "{\"error\":\"Internal server error\"}"
```

#### 9. Port Validation
**Issue**: No validation of port range
**Fix**: Validate port is 1-65535

#### 10. Enhanced TLS Cipher Suites
**Issue**: No cipher suite restrictions
**Fix**: Limited to strong, modern ciphers

### Medium Severity Fixes

#### 11. Missing Security Headers
**Fix**: Added all OWASP recommended headers

#### 12. File Permission Race Conditions
**Issue**: File created then chmod'd (TOCTOU)
**Fix**: Set umask before file creation

## Reporting Vulnerabilities

### Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

### How to Report

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email security contact (configure in your deployment)
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline
- **24 hours**: Initial response
- **7 days**: Severity assessment
- **30 days**: Fix for critical issues
- **90 days**: Fix for non-critical issues

## Secure Deployment Guide

### Docker Deployment

```bash
# Build image
docker build -t virtual-hsm:latest .

# Run with secrets
docker run -d \
  --name vhsm \
  -p 8443:8443 \
  -e VHSM_ALLOWED_ORIGIN=https://your-domain.com \
  --secret vhsm_master_key \
  --secret vhsm_admin_password \
  -v vhsm-storage:/app/storage \
  virtual-hsm:latest
```

### Kubernetes Deployment

```bash
# Deploy with secrets
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml  # Use Vault in production
kubectl apply -f k8s/deployment.yaml
```

### Minikube Quick Start

```bash
cd k8s
./minikube-setup.sh
```

### Production Checklist

- [ ] Use hardware HSM or cloud HSM for production
- [ ] Enable TLS/HTTPS for all communications
- [ ] Use external secrets management (Vault, AWS Secrets Manager)
- [ ] Enable audit logging
- [ ] Configure appropriate session timeouts
- [ ] Implement rate limiting
- [ ] Set up monitoring and alerting
- [ ] Regular security updates
- [ ] Perform security audits
- [ ] Implement backup and disaster recovery
- [ ] Use network policies to restrict traffic
- [ ] Enable pod security policies
- [ ] Run as non-root user
- [ ] Use read-only filesystem
- [ ] Implement resource limits

## Best Practices

### Key Management
1. **Rotate keys regularly** (default: 90 days)
2. **Use strong key types**: AES-256, ED25519, RSA-3072+
3. **Separate keys by purpose**: Encryption, signing, authentication
4. **Backup keys securely**: Encrypted backups only
5. **Destroy compromised keys immediately**

### Password Management
1. **Minimum 12 characters** (configurable, default 8)
2. **Use password managers** for generation
3. **Never hardcode passwords** in code
4. **Change default passwords** immediately
5. **Implement password rotation** policies

### Network Security
1. **Always use TLS** in production
2. **Use mutual TLS (mTLS)** when possible
3. **Restrict CORS** to specific origins
4. **Implement rate limiting** on APIs
5. **Use network segmentation**

### Access Control
1. **Principle of least privilege**
2. **Separate user and admin accounts**
3. **Regular access reviews**
4. **Revoke unused accounts**
5. **Monitor failed login attempts**

### Monitoring & Auditing
1. **Enable audit logging** (default: enabled)
2. **Monitor audit logs** regularly
3. **Alert on suspicious activity**
4. **Review logs for compliance**
5. **Retain logs** per policy (default: unlimited)

### Container Security
1. **Use official base images**
2. **Run as non-root user**
3. **Read-only root filesystem**
4. **Drop all capabilities** except required
5. **Use security profiles** (AppArmor, SELinux)

### Secrets Management
1. **Never commit secrets** to version control
2. **Use secrets management tools** (Vault, AWS Secrets Manager)
3. **Rotate secrets regularly**
4. **Limit secret access** to required services only
5. **Audit secret access**

## Security Considerations

### Threat Model

#### In Scope
- Software vulnerabilities (buffer overflows, injection, etc.)
- Network attacks (MitM, replay, etc.)
- Authentication/authorization bypass
- Data exposure through logs or errors
- Key exposure through memory dumps

#### Out of Scope
- Physical access to server
- Side-channel attacks (timing, power, etc.)
- Hardware-level attacks
- Social engineering
- Insider threats with root access

### Known Limitations

#### What This IS
- ✅ Secure key storage for development
- ✅ Educational HSM implementation
- ✅ Testing cryptographic workflows
- ✅ API prototyping

#### What This IS NOT
- ❌ FIPS 140-2/140-3 certified
- ❌ Production-ready for sensitive data
- ❌ Hardware-backed security
- ❌ Tamper-resistant
- ❌ Side-channel attack resistant

### Compliance

#### Supported Standards
- **NIST Guidelines**: SP 800-57 (Key Management)
- **OWASP**: Top 10 protections implemented
- **CWE**: Common Weakness Enumeration mitigations

#### Not Certified For
- **PCI-DSS**: Use hardware HSM for payment cards
- **HIPAA**: Additional controls required
- **FedRAMP**: Use approved cloud HSM
- **FIPS 140-2/3**: No hardware certification

### Recommendations for Production

For production environments, use:

1. **Hardware HSMs**
   - Thales Luna HSM
   - Entrust nShield
   - Utimaco HSM

2. **Cloud HSM Services**
   - AWS CloudHSM / KMS
   - Azure Key Vault / Managed HSM
   - Google Cloud KMS / HSM
   - IBM Cloud HSM

3. **Open Source Alternatives**
   - SoftHSM2 (PKCS#11)
   - OpenSC (smart card)

## Additional Resources

- [NIST Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/security-best-practices/)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)

## Version History

- **2.0.0** (November 2024): Major security fixes and enhancements
  - Fixed 6 critical vulnerabilities
  - Fixed 20 high severity issues
  - Added Docker and Kubernetes support
  - Improved cryptographic key derivation
  - Enhanced TLS security

---

**Last Updated**: November 24, 2024
**Security Contact**: Configure per deployment
**Version**: 2.0.0
