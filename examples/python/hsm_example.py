#!/usr/bin/env python3
"""
Virtual HSM Python Example

This example demonstrates how to use the Virtual HSM Python library for:
- User management
- Key generation
- Data encryption/decryption
- Digital signatures
- Audit logging
"""

import sys
import os

# Add python directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../python'))

import vhsm


def main():
    print("=== Virtual HSM Python Example ===\n")

    # 1. Initialize HSM
    print("1. Initializing HSM...")
    hsm = vhsm.HSM('/tmp/python_hsm_storage')
    print(f"   Library version: {vhsm.HSM.version()}")

    # 2. Generate master key
    print("\n2. Generating master key...")
    master_key = hsm.generate_master_key()
    print(f"   Master key: {master_key.hex()[:32]}...")

    # 3. Enable audit logging
    print("\n3. Enabling audit logging...")
    hsm.enable_audit('/tmp/python_hsm_audit.log')
    print("   Audit logging enabled")

    # 4. Create users
    print("\n4. Creating users...")
    try:
        hsm.create_user('admin', 'admin_password_123', role=vhsm.ROLE_ADMIN)
        print("   ✓ Admin user created")
    except vhsm.VHSMError as e:
        if e.code == vhsm.ERROR_KEY_EXISTS:
            print("   ✓ Admin user already exists")
        else:
            raise

    try:
        hsm.create_user('alice', 'alice_password_456', role=vhsm.ROLE_USER)
        print("   ✓ User 'alice' created")
    except vhsm.VHSMError as e:
        if e.code == vhsm.ERROR_KEY_EXISTS:
            print("   ✓ User 'alice' already exists")
        else:
            raise

    # 5. Login as admin
    print("\n5. Logging in as admin...")
    with hsm.login('admin', 'admin_password_123') as session:
        print("   ✓ Login successful")
        print(f"   Session valid: {session.is_valid()}")

        # 6. Generate encryption key
        print("\n6. Generating AES-256 encryption key...")
        enc_key_handle = session.generate_key(
            'encryption_key',
            vhsm.KEY_TYPE_AES_256,
            vhsm.KEY_USAGE_ENCRYPT | vhsm.KEY_USAGE_DECRYPT
        )
        print(f"   ✓ Key generated (handle: {enc_key_handle})")

        # 7. Encrypt data
        print("\n7. Encrypting sensitive data...")
        secret_data = b"This is a secret message from Python!"
        print(f"   Original: {secret_data.decode()}")

        ciphertext, iv = session.encrypt(enc_key_handle, secret_data)
        print(f"   ✓ Encrypted ({len(ciphertext)} bytes)")
        print(f"   IV: {iv.hex()}")
        print(f"   Ciphertext: {ciphertext.hex()[:64]}...")

        # 8. Decrypt data
        print("\n8. Decrypting data...")
        plaintext = session.decrypt(enc_key_handle, ciphertext, iv)
        print(f"   Decrypted: {plaintext.decode()}")
        print(f"   ✓ Match: {plaintext == secret_data}")

        # 9. Generate signing key
        print("\n9. Generating ED25519 signing key...")
        sign_key_handle = session.generate_key(
            'signing_key',
            vhsm.KEY_TYPE_ED25519,
            vhsm.KEY_USAGE_SIGN | vhsm.KEY_USAGE_VERIFY
        )
        print(f"   ✓ Signing key generated (handle: {sign_key_handle})")

        # 10. Sign data
        print("\n10. Signing document...")
        document = b"Important contract: Transfer $1000 from Alice to Bob"
        print(f"   Document: {document.decode()}")

        signature = session.sign(sign_key_handle, document)
        print(f"   ✓ Signed ({len(signature)} bytes)")
        print(f"   Signature: {signature.hex()}")

        # 11. Verify signature
        print("\n11. Verifying signature...")
        try:
            is_valid = session.verify(sign_key_handle, document, signature)
            print(f"   ✓ Signature is valid: {is_valid}")
        except vhsm.VHSMError as e:
            print(f"   ✗ Signature verification failed: {e}")

        # 12. Verify with tampered data
        print("\n12. Verifying with tampered document...")
        tampered = b"Important contract: Transfer $9999 from Alice to Bob"
        try:
            session.verify(sign_key_handle, tampered, signature)
            print("   ✗ ERROR: Tampered document verified!")
        except vhsm.VHSMError as e:
            if e.code == vhsm.ERROR_INVALID_SIGNATURE:
                print("   ✓ Signature correctly rejected for tampered data")
            else:
                raise

        print("\n13. Logging out...")
        # Session will auto-close via context manager

    print("   ✓ Session closed")

    # 14. Test password change
    print("\n14. Testing password change...")
    hsm.change_password('alice', 'alice_password_456', 'new_secure_password_789')
    print("   ✓ Password changed for alice")

    # 15. Login with new password
    print("\n15. Logging in with new password...")
    with hsm.login('alice', 'new_secure_password_789') as session:
        print("   ✓ Login successful with new password")

        # Alice can retrieve existing keys
        print("\n16. Alice retrieving encryption key...")
        try:
            enc_key = session.get_key('encryption_key')
            print(f"   ✓ Retrieved key (handle: {enc_key})")

            # Test encryption with retrieved key
            test_data = b"Alice's secret data"
            ciphertext, iv = session.encrypt(enc_key, test_data)
            plaintext = session.decrypt(enc_key, ciphertext, iv)
            print(f"   ✓ Encrypt/decrypt test passed: {plaintext == test_data}")
        except vhsm.VHSMError as e:
            print(f"   ! Note: {e} (expected if key access control is enforced)")

    # Cleanup
    print("\n17. Cleanup...")
    hsm.disable_audit()
    hsm.cleanup()
    print("   ✓ HSM cleanup complete")

    print("\n=== Example completed successfully! ===\n")


if __name__ == '__main__':
    try:
        main()
    except vhsm.VHSMError as e:
        print(f"\nVHSM Error: {e}")
        print(f"Error code: {e.code}")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
