"""
Virtual HSM Python Library

A Python wrapper for the Virtual HSM C library, providing cryptographic key management,
digital signatures, multi-user authentication, and audit logging.

Example:
    >>> import vhsm
    >>> hsm = vhsm.HSM('/tmp/hsm_storage')
    >>> hsm.generate_master_key()
    >>> hsm.create_user('admin', 'password123', role=vhsm.ROLE_ADMIN)
    >>> with hsm.login('admin', 'password123') as session:
    ...     key_handle = session.generate_key('encryption_key', vhsm.KEY_TYPE_AES_256)
    ...     ciphertext = session.encrypt(key_handle, b'secret data')
    ...     plaintext = session.decrypt(key_handle, ciphertext)
"""

from .vhsm import (
    HSM,
    Session,
    VHSMError,
    # Error codes
    SUCCESS,
    ERROR_GENERIC,
    ERROR_INVALID_PARAM,
    ERROR_OUT_OF_MEMORY,
    ERROR_KEY_NOT_FOUND,
    ERROR_KEY_EXISTS,
    ERROR_CRYPTO_FAILED,
    ERROR_IO_FAILED,
    ERROR_AUTH_FAILED,
    ERROR_PERMISSION_DENIED,
    ERROR_INVALID_STATE,
    ERROR_BUFFER_TOO_SMALL,
    ERROR_NOT_IMPLEMENTED,
    ERROR_KEY_EXPIRED,
    ERROR_KEY_REVOKED,
    ERROR_SESSION_INVALID,
    ERROR_RATE_LIMIT,
    ERROR_AUDIT_FAILED,
    ERROR_COMPRESSION_FAILED,
    ERROR_DECOMPRESSION_FAILED,
    ERROR_INVALID_SIGNATURE,
    ERROR_INVALID_FORMAT,
    ERROR_NOT_INITIALIZED,
    ERROR_ALREADY_INITIALIZED,
    # Key types
    KEY_TYPE_INVALID,
    KEY_TYPE_AES_128,
    KEY_TYPE_AES_256,
    KEY_TYPE_ED25519,
    KEY_TYPE_RSA_2048,
    KEY_TYPE_RSA_3072,
    KEY_TYPE_RSA_4096,
    KEY_TYPE_ECDSA_P256,
    KEY_TYPE_ECDSA_P384,
    KEY_TYPE_ECDSA_P521,
    KEY_TYPE_HMAC_SHA256,
    KEY_TYPE_HMAC_SHA512,
    # Key usage flags
    KEY_USAGE_NONE,
    KEY_USAGE_ENCRYPT,
    KEY_USAGE_DECRYPT,
    KEY_USAGE_SIGN,
    KEY_USAGE_VERIFY,
    KEY_USAGE_WRAP,
    KEY_USAGE_UNWRAP,
    KEY_USAGE_DERIVE,
    KEY_USAGE_ALL,
    # Roles
    ROLE_NONE,
    ROLE_USER,
    ROLE_OPERATOR,
    ROLE_ADMIN,
    ROLE_AUDITOR,
    # Compression
    COMPRESS_NONE,
    COMPRESS_ZLIB,
    COMPRESS_LZ4,
)

__version__ = '2.0.0'
__all__ = [
    'HSM',
    'Session',
    'VHSMError',
    '__version__',
]
