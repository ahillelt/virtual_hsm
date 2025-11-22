"""
Virtual HSM Python bindings using ctypes
"""

import ctypes
import os
import platform
from ctypes import (
    c_void_p, c_char_p, c_uint8, c_uint64, c_int, c_size_t,
    c_uint32, c_int64, POINTER, Structure, create_string_buffer
)
from typing import Optional, Tuple, List


# Find the shared library
def _find_library():
    """Locate the VHSM shared library"""
    # Try common locations
    locations = [
        './lib/libvhsm.so',
        '../lib/libvhsm.so',
        '/usr/local/lib/libvhsm.so',
        '/usr/lib/libvhsm.so',
        os.path.join(os.path.dirname(__file__), '../../lib/libvhsm.so'),
    ]

    # Add VHSM_LIB_PATH environment variable
    if 'VHSM_LIB_PATH' in os.environ:
        locations.insert(0, os.environ['VHSM_LIB_PATH'])

    for path in locations:
        if os.path.exists(path):
            return path

    raise RuntimeError(
        "Could not find libvhsm.so. Please build the library or set VHSM_LIB_PATH"
    )


# Load the library
_lib_path = _find_library()
_lib = ctypes.CDLL(_lib_path)


# Error codes
SUCCESS = 0
ERROR_GENERIC = -1
ERROR_INVALID_PARAM = -2
ERROR_OUT_OF_MEMORY = -3
ERROR_KEY_NOT_FOUND = -4
ERROR_KEY_EXISTS = -5
ERROR_CRYPTO_FAILED = -6
ERROR_IO_FAILED = -7
ERROR_AUTH_FAILED = -8
ERROR_PERMISSION_DENIED = -9
ERROR_INVALID_STATE = -10
ERROR_BUFFER_TOO_SMALL = -11
ERROR_NOT_IMPLEMENTED = -12
ERROR_KEY_EXPIRED = -13
ERROR_KEY_REVOKED = -14
ERROR_SESSION_INVALID = -15
ERROR_RATE_LIMIT = -16
ERROR_AUDIT_FAILED = -17
ERROR_COMPRESSION_FAILED = -18
ERROR_DECOMPRESSION_FAILED = -19
ERROR_INVALID_SIGNATURE = -20
ERROR_INVALID_FORMAT = -21
ERROR_NOT_INITIALIZED = -22
ERROR_ALREADY_INITIALIZED = -23

# Key types
KEY_TYPE_INVALID = 0
KEY_TYPE_AES_128 = 1
KEY_TYPE_AES_256 = 2
KEY_TYPE_ED25519 = 3
KEY_TYPE_RSA_2048 = 4
KEY_TYPE_RSA_3072 = 5
KEY_TYPE_RSA_4096 = 6
KEY_TYPE_ECDSA_P256 = 7
KEY_TYPE_ECDSA_P384 = 8
KEY_TYPE_ECDSA_P521 = 9
KEY_TYPE_HMAC_SHA256 = 10
KEY_TYPE_HMAC_SHA512 = 11

# Key usage flags
KEY_USAGE_NONE = 0
KEY_USAGE_ENCRYPT = (1 << 0)
KEY_USAGE_DECRYPT = (1 << 1)
KEY_USAGE_SIGN = (1 << 2)
KEY_USAGE_VERIFY = (1 << 3)
KEY_USAGE_WRAP = (1 << 4)
KEY_USAGE_UNWRAP = (1 << 5)
KEY_USAGE_DERIVE = (1 << 6)
KEY_USAGE_ALL = 0xFF

# Roles
ROLE_NONE = 0
ROLE_USER = 1
ROLE_OPERATOR = 2
ROLE_ADMIN = 3
ROLE_AUDITOR = 4

# Compression
COMPRESS_NONE = 0
COMPRESS_ZLIB = 1
COMPRESS_LZ4 = 2

# Constants
VHSM_GCM_IV_SIZE = 12
VHSM_GCM_TAG_SIZE = 16
VHSM_ED25519_SIG_SIZE = 64


class VHSMError(Exception):
    """Virtual HSM error"""

    ERROR_MESSAGES = {
        ERROR_GENERIC: "Generic error",
        ERROR_INVALID_PARAM: "Invalid parameter",
        ERROR_OUT_OF_MEMORY: "Out of memory",
        ERROR_KEY_NOT_FOUND: "Key not found",
        ERROR_KEY_EXISTS: "Key already exists",
        ERROR_CRYPTO_FAILED: "Cryptographic operation failed",
        ERROR_IO_FAILED: "I/O operation failed",
        ERROR_AUTH_FAILED: "Authentication failed",
        ERROR_PERMISSION_DENIED: "Permission denied",
        ERROR_INVALID_STATE: "Invalid state",
        ERROR_BUFFER_TOO_SMALL: "Buffer too small",
        ERROR_NOT_IMPLEMENTED: "Not implemented",
        ERROR_KEY_EXPIRED: "Key expired",
        ERROR_KEY_REVOKED: "Key revoked",
        ERROR_SESSION_INVALID: "Session invalid",
        ERROR_RATE_LIMIT: "Rate limit exceeded",
        ERROR_AUDIT_FAILED: "Audit operation failed",
        ERROR_COMPRESSION_FAILED: "Compression failed",
        ERROR_DECOMPRESSION_FAILED: "Decompression failed",
        ERROR_INVALID_SIGNATURE: "Invalid signature",
        ERROR_INVALID_FORMAT: "Invalid format",
        ERROR_NOT_INITIALIZED: "Not initialized",
        ERROR_ALREADY_INITIALIZED: "Already initialized",
    }

    def __init__(self, code: int, message: str = None):
        self.code = code
        if message is None:
            message = self.ERROR_MESSAGES.get(code, f"Unknown error: {code}")
        super().__init__(message)


def _check_error(result: int) -> None:
    """Check error code and raise exception if not SUCCESS"""
    if result != SUCCESS:
        raise VHSMError(result)


# Define C function signatures

# Library init
_lib.vhsm_init.argtypes = []
_lib.vhsm_init.restype = c_int

_lib.vhsm_cleanup.argtypes = []
_lib.vhsm_cleanup.restype = None

_lib.vhsm_version.argtypes = []
_lib.vhsm_version.restype = c_char_p

_lib.vhsm_error_string.argtypes = [c_int]
_lib.vhsm_error_string.restype = c_char_p

# Context management
_lib.vhsm_ctx_create.argtypes = [POINTER(c_void_p), c_char_p]
_lib.vhsm_ctx_create.restype = c_int

_lib.vhsm_ctx_destroy.argtypes = [c_void_p]
_lib.vhsm_ctx_destroy.restype = None

_lib.vhsm_ctx_generate_master_key.argtypes = [c_void_p, POINTER(c_uint8)]
_lib.vhsm_ctx_generate_master_key.restype = c_int

_lib.vhsm_ctx_set_master_key.argtypes = [c_void_p, POINTER(c_uint8)]
_lib.vhsm_ctx_set_master_key.restype = c_int

# User management
_lib.vhsm_user_create.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p, c_int]
_lib.vhsm_user_create.restype = c_int

_lib.vhsm_user_delete.argtypes = [c_void_p, c_char_p]
_lib.vhsm_user_delete.restype = c_int

_lib.vhsm_user_change_password.argtypes = [c_void_p, c_char_p, c_char_p, c_char_p]
_lib.vhsm_user_change_password.restype = c_int

# Session management
_lib.vhsm_session_login.argtypes = [c_void_p, POINTER(c_void_p), c_char_p, c_char_p, c_char_p]
_lib.vhsm_session_login.restype = c_int

_lib.vhsm_session_logout.argtypes = [c_void_p]
_lib.vhsm_session_logout.restype = None

_lib.vhsm_session_is_valid.argtypes = [c_void_p]
_lib.vhsm_session_is_valid.restype = c_int

# Key management
_lib.vhsm_key_generate.argtypes = [c_void_p, c_char_p, c_int, c_int, POINTER(c_uint64)]
_lib.vhsm_key_generate.restype = c_int

_lib.vhsm_key_get.argtypes = [c_void_p, c_char_p, POINTER(c_uint64)]
_lib.vhsm_key_get.restype = c_int

_lib.vhsm_key_delete.argtypes = [c_void_p, c_uint64]
_lib.vhsm_key_delete.restype = c_int

# Crypto operations
_lib.vhsm_encrypt.argtypes = [
    c_void_p, c_uint64,
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), POINTER(c_size_t),
    POINTER(c_uint8), c_size_t
]
_lib.vhsm_encrypt.restype = c_int

_lib.vhsm_decrypt.argtypes = [
    c_void_p, c_uint64,
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), POINTER(c_size_t),
    POINTER(c_uint8), c_size_t
]
_lib.vhsm_decrypt.restype = c_int

_lib.vhsm_sign.argtypes = [
    c_void_p, c_uint64,
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), POINTER(c_size_t)
]
_lib.vhsm_sign.restype = c_int

_lib.vhsm_verify.argtypes = [
    c_void_p, c_uint64,
    POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t
]
_lib.vhsm_verify.restype = c_int

# Audit
_lib.vhsm_audit_enable.argtypes = [c_void_p, c_char_p]
_lib.vhsm_audit_enable.restype = c_int

_lib.vhsm_audit_disable.argtypes = [c_void_p]
_lib.vhsm_audit_disable.restype = None


class Session:
    """HSM Session - provides authenticated access to cryptographic operations"""

    def __init__(self, session_handle: c_void_p):
        self._handle = session_handle
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Close the session"""
        if not self._closed:
            _lib.vhsm_session_logout(self._handle)
            self._closed = True

    def is_valid(self) -> bool:
        """Check if session is still valid"""
        return _lib.vhsm_session_is_valid(self._handle) == 1

    def generate_key(self, name: str, key_type: int,
                     usage: int = KEY_USAGE_ALL) -> int:
        """
        Generate a new cryptographic key

        Args:
            name: Unique key name
            key_type: Key type (KEY_TYPE_AES_256, KEY_TYPE_ED25519, etc.)
            usage: Key usage flags (default: KEY_USAGE_ALL)

        Returns:
            Key handle
        """
        handle = c_uint64()
        result = _lib.vhsm_key_generate(
            self._handle,
            name.encode('utf-8'),
            key_type,
            usage,
            ctypes.byref(handle)
        )
        _check_error(result)
        return handle.value

    def get_key(self, name: str) -> int:
        """
        Get key handle by name

        Args:
            name: Key name

        Returns:
            Key handle
        """
        handle = c_uint64()
        result = _lib.vhsm_key_get(
            self._handle,
            name.encode('utf-8'),
            ctypes.byref(handle)
        )
        _check_error(result)
        return handle.value

    def delete_key(self, handle: int) -> None:
        """Delete a key"""
        result = _lib.vhsm_key_delete(self._handle, handle)
        _check_error(result)

    def encrypt(self, key_handle: int, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data

        Args:
            key_handle: Key handle
            plaintext: Data to encrypt

        Returns:
            Tuple of (ciphertext, iv)
        """
        # Allocate buffers
        plaintext_len = len(plaintext)
        ciphertext_len = c_size_t(plaintext_len + VHSM_GCM_TAG_SIZE + 1024)
        ciphertext = create_string_buffer(ciphertext_len.value)
        iv = create_string_buffer(VHSM_GCM_IV_SIZE)

        # Convert plaintext to ctypes
        plaintext_buf = (c_uint8 * plaintext_len)(*plaintext)

        result = _lib.vhsm_encrypt(
            self._handle,
            key_handle,
            plaintext_buf,
            plaintext_len,
            ctypes.cast(ciphertext, POINTER(c_uint8)),
            ctypes.byref(ciphertext_len),
            ctypes.cast(iv, POINTER(c_uint8)),
            VHSM_GCM_IV_SIZE
        )
        _check_error(result)

        return bytes(ciphertext[:ciphertext_len.value]), bytes(iv[:VHSM_GCM_IV_SIZE])

    def decrypt(self, key_handle: int, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt data

        Args:
            key_handle: Key handle
            ciphertext: Encrypted data
            iv: Initialization vector

        Returns:
            Decrypted plaintext
        """
        ciphertext_len = len(ciphertext)
        plaintext_len = c_size_t(ciphertext_len + 1024)
        plaintext = create_string_buffer(plaintext_len.value)

        ciphertext_buf = (c_uint8 * ciphertext_len)(*ciphertext)
        iv_buf = (c_uint8 * len(iv))(*iv)

        result = _lib.vhsm_decrypt(
            self._handle,
            key_handle,
            ciphertext_buf,
            ciphertext_len,
            ctypes.cast(plaintext, POINTER(c_uint8)),
            ctypes.byref(plaintext_len),
            iv_buf,
            len(iv)
        )
        _check_error(result)

        return bytes(plaintext[:plaintext_len.value])

    def sign(self, key_handle: int, data: bytes) -> bytes:
        """
        Sign data

        Args:
            key_handle: Signing key handle
            data: Data to sign

        Returns:
            Signature
        """
        data_len = len(data)
        sig_len = c_size_t(256)  # Max signature size
        signature = create_string_buffer(sig_len.value)

        data_buf = (c_uint8 * data_len)(*data)

        result = _lib.vhsm_sign(
            self._handle,
            key_handle,
            data_buf,
            data_len,
            ctypes.cast(signature, POINTER(c_uint8)),
            ctypes.byref(sig_len)
        )
        _check_error(result)

        return bytes(signature[:sig_len.value])

    def verify(self, key_handle: int, data: bytes, signature: bytes) -> bool:
        """
        Verify signature

        Args:
            key_handle: Verification key handle
            data: Original data
            signature: Signature to verify

        Returns:
            True if signature is valid

        Raises:
            VHSMError: If signature is invalid
        """
        data_len = len(data)
        sig_len = len(signature)

        data_buf = (c_uint8 * data_len)(*data)
        sig_buf = (c_uint8 * sig_len)(*signature)

        result = _lib.vhsm_verify(
            self._handle,
            key_handle,
            data_buf,
            data_len,
            sig_buf,
            sig_len
        )

        if result == SUCCESS:
            return True
        elif result == ERROR_INVALID_SIGNATURE:
            raise VHSMError(result, "Signature verification failed")
        else:
            _check_error(result)


class HSM:
    """Virtual HSM - Main interface to the HSM"""

    def __init__(self, storage_path: str):
        """
        Initialize HSM

        Args:
            storage_path: Path to HSM storage directory
        """
        self.storage_path = storage_path
        self._ctx = None
        self._initialized = False

        # Initialize library
        result = _lib.vhsm_init()
        _check_error(result)
        self._initialized = True

        # Create context
        ctx = c_void_p()
        result = _lib.vhsm_ctx_create(
            ctypes.byref(ctx),
            storage_path.encode('utf-8')
        )
        _check_error(result)
        self._ctx = ctx

    def __del__(self):
        """Cleanup on deletion"""
        self.cleanup()

    def cleanup(self):
        """Cleanup HSM resources"""
        if self._ctx:
            _lib.vhsm_ctx_destroy(self._ctx)
            self._ctx = None
        if self._initialized:
            _lib.vhsm_cleanup()
            self._initialized = False

    def generate_master_key(self) -> bytes:
        """
        Generate a new master key

        Returns:
            32-byte master key
        """
        master_key = (c_uint8 * 32)()
        result = _lib.vhsm_ctx_generate_master_key(
            self._ctx,
            master_key
        )
        _check_error(result)
        return bytes(master_key)

    def set_master_key(self, master_key: bytes) -> None:
        """
        Set the master key

        Args:
            master_key: 32-byte master key
        """
        if len(master_key) != 32:
            raise ValueError("Master key must be 32 bytes")

        key_buf = (c_uint8 * 32)(*master_key)
        result = _lib.vhsm_ctx_set_master_key(self._ctx, key_buf)
        _check_error(result)

    def create_user(self, username: str, password: str,
                    pin: Optional[str] = None, role: int = ROLE_USER) -> None:
        """
        Create a new user

        Args:
            username: Username
            password: Password
            pin: Optional PIN
            role: User role (default: ROLE_USER)
        """
        result = _lib.vhsm_user_create(
            self._ctx,
            username.encode('utf-8'),
            password.encode('utf-8'),
            pin.encode('utf-8') if pin else None,
            role
        )
        _check_error(result)

    def delete_user(self, username: str) -> None:
        """Delete a user"""
        result = _lib.vhsm_user_delete(
            self._ctx,
            username.encode('utf-8')
        )
        _check_error(result)

    def change_password(self, username: str, old_password: str,
                       new_password: str) -> None:
        """Change user password"""
        result = _lib.vhsm_user_change_password(
            self._ctx,
            username.encode('utf-8'),
            old_password.encode('utf-8'),
            new_password.encode('utf-8')
        )
        _check_error(result)

    def login(self, username: str, password: str,
              pin: Optional[str] = None) -> Session:
        """
        Login and create a session

        Args:
            username: Username
            password: Password
            pin: Optional PIN

        Returns:
            Session object
        """
        session = c_void_p()
        result = _lib.vhsm_session_login(
            self._ctx,
            ctypes.byref(session),
            username.encode('utf-8'),
            password.encode('utf-8'),
            pin.encode('utf-8') if pin else None
        )
        _check_error(result)
        return Session(session)

    def enable_audit(self, log_path: str) -> None:
        """Enable audit logging"""
        result = _lib.vhsm_audit_enable(
            self._ctx,
            log_path.encode('utf-8')
        )
        _check_error(result)

    def disable_audit(self) -> None:
        """Disable audit logging"""
        _lib.vhsm_audit_disable(self._ctx)

    @staticmethod
    def version() -> str:
        """Get library version"""
        return _lib.vhsm_version().decode('utf-8')
