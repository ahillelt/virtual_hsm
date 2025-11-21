#!/bin/bash
set -e
echo "===== README FUNCTIONALITY TEST ====="
gcc -o vhsm ../virtual_hsm.c -lcrypto -lssl 2>&1 | head -1 || true

# Test 1: Master key generation
./vhsm -generate_master_key store_key >/dev/null 2>&1
[ -f master.key ] || exit 1
echo "✓ 1. Master key generation"

# Test 2-3: Store and retrieve
echo -n "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" | ./vhsm -store key1 >/dev/null 2>&1
[ "$(./vhsm -retrieve key1 2>/dev/null)" = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ] || exit 1
echo "✓ 2. Store and retrieve symmetric key"

# Test 4: List keys
./vhsm -list 2>/dev/null | grep -q "key1" || exit 1
echo "✓ 3. List keys"

# Test 5-6: ED25519 signing
./vhsm -generate_key_pair signing_key >/dev/null 2>&1
echo "Test data" > data.txt
./vhsm -sign signing_key -i data.txt -o sig.bin 2>/dev/null
[ $(wc -c < sig.bin) -eq 64 ] || exit 1
echo "✓ 4. Generate key pair and sign (64-byte signature)"

# Test 7: Verify
./vhsm -verify signing_key -i data.txt -s sig.bin 2>&1 | grep -q "Signature verified successfully" || exit 1
echo "✓ 5. Verify signature"

# Test 8-9: Public key export/import
./vhsm -export_public_key signing_key 2>/dev/null > pub.pem
grep -q "BEGIN PUBLIC KEY" pub.pem || exit 1
./vhsm -import_public_key imported_key -i pub.pem 2>/dev/null
./vhsm -verify imported_key -i data.txt -s sig.bin 2>&1 | grep -q "Signature verified successfully" || exit 1
echo "✓ 6. Export and import public key (PEM)"

# Test 10: New syntax (-i, -o, -is, -s)
./vhsm -sign signing_key -is "Hello World" -o sig2.bin 2>/dev/null
[ $(wc -c < sig2.bin) -eq 64 ] || exit 1
./vhsm -verify signing_key -is "Hello World" -s sig2.bin 2>&1 | grep -q "Signature verified successfully" || exit 1
echo "✓ 7. New command syntax (-i, -o, -is, -s)"

# Test 11: Custom keystore files
./vhsm -keystore custom.dat -master custom.key -generate_master_key store_key >/dev/null 2>&1
[ -f custom.key ] || exit 1
echo -n "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" | ./vhsm -keystore custom.dat -master custom.key -store ckey >/dev/null 2>&1
[ "$(./vhsm -keystore custom.dat -master custom.key -retrieve ckey 2>/dev/null)" = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" ] || exit 1
echo "✓ 8. Custom keystore and master key files"

# Test 12: Master key via command line
MASTER_HEX=$(od -An -tx1 master.key | tr -d ' \n')
echo -n "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" | ./vhsm -master_key "$MASTER_HEX" -store cmdkey >/dev/null 2>&1
[ "$(./vhsm -master_key "$MASTER_HEX" -retrieve cmdkey 2>/dev/null)" = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" ] || exit 1
echo "✓ 9. Master key via command line argument"

echo ""
echo "=========================================="
echo "ALL README FUNCTIONALITY TESTS PASSED!"
echo "=========================================="
echo "9/9 tests passed - All features working correctly"
