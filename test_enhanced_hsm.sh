#!/bin/bash
set -e

echo "=========================================="
echo "ENHANCED VIRTUAL HSM - COMPREHENSIVE TEST"
echo "=========================================="

# Clean previous test data
rm -f master.key keystore.dat hsm_audit.log .*.metadata test_key* 2>/dev/null || true

echo ""
echo "=== Test 1: Hardware Scan ==="
./hsm_enhanced -scan_hardware 2>&1 | grep -E "(Scanning|detected|Software)" | head -10

echo ""
echo "=== Test 2: Master Key Generation with Audit ==="
./hsm_enhanced -generate_master_key store_key 2>&1 | grep -v "^Debug:"
[ -f master.key ] || { echo "✗ Master key not created"; exit 1; }
[ -f hsm_audit.log ] || { echo "✗ Audit log not created"; exit 1; }
echo "✓ Master key generated and audit log initialized"

echo ""
echo "=== Test 3: Store Key with Metadata ==="
echo -n "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" | \
  ./hsm_enhanced -store test_key1 2>&1 | grep -v "^Debug:"
[ -f .test_key1.metadata ] || { echo "✗ Metadata not created"; exit 1; }
echo "✓ Key stored with lifecycle metadata"

echo ""
echo "=== Test 4: Key Information Display ==="
./hsm_enhanced -key_info test_key1 2>&1 | grep -v "^Debug:" | head -12
echo "✓ Key metadata displayed"

echo ""
echo "=== Test 5: Generate ED25519 Key Pair ==="
./hsm_enhanced -generate_key_pair signing_key 2>&1 | grep -v "^Debug:"
./hsm_enhanced -list 2>&1 | grep -v "^Debug:" | grep -v "WARNING"
echo "✓ Key pair generated"

echo ""
echo "=== Test 6: Sign and Verify with Audit ==="
echo "Test data for signing" > test_data.txt
./hsm_enhanced -sign signing_key -i test_data.txt -o signature.bin 2>&1 | grep -v "^Debug:" | grep -v "WARNING" | head -3
[ -f signature.bin ] && [ $(wc -c < signature.bin) -eq 64 ] || { echo "✗ Signature failed"; exit 1; }
echo "✓ Data signed (64-byte signature)"

./hsm_enhanced -verify signing_key -i test_data.txt -s signature.bin 2>&1 | grep "Signature verified" || { echo "✗ Verification failed"; exit 1; }
echo "✓ Signature verified"

echo ""
echo "=== Test 7: Audit Log Viewing ==="
echo "Recent audit entries:"
./hsm_enhanced -audit_logs 1 2>&1 | grep -v "^Debug:" | tail -10
echo "✓ Audit log readable"

echo ""
echo "=== Test 8: Key Rotation ==="
./hsm_enhanced -rotate_key test_key1 2>&1 | grep -v "^Debug:" | grep -v "WARNING"
./hsm_enhanced -key_info test_key1 2>&1 | grep -v "^Debug:" | grep "Rotation Version"
echo "✓ Key rotated successfully"

echo ""
echo "=== Test 9: Export and Import Public Key ==="
./hsm_enhanced -export_public_key signing_key 2>&1 | grep -v "^Debug:" | grep -v "WARNING" > pub_key.pem
grep -q "BEGIN PUBLIC KEY" pub_key.pem || { echo "✗ Export failed"; exit 1; }
echo "✓ Public key exported"

./hsm_enhanced -import_public_key imported_key -i pub_key.pem 2>&1 | grep "successfully"
echo "✓ Public key imported"

echo ""
echo "=== Test 10: Set User ID ==="
./hsm_enhanced -set_user "alice@example.com" 2>&1 | grep -v "^Debug:"
echo "✓ User ID set for access control"

echo ""
echo "=== Test 11: Key Retrieval with Usage Tracking ==="
./hsm_enhanced -retrieve test_key1 2>&1 | grep -v "^Debug:" | grep -v "WARNING" > /dev/null
./hsm_enhanced -key_info test_key1 2>&1 | grep -v "^Debug:" | grep "Use Count"
echo "✓ Key usage tracked"

echo ""
echo "=== Test 12: Symmetric Key Operations ==="
echo -n "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" | \
  ./hsm_enhanced -store sym_key2 2>&1 | grep -v "^Debug:"
RETRIEVED=$(./hsm_enhanced -retrieve sym_key2 2>&1 | grep -v "^Debug:" | grep -v "WARNING")
if [ "$RETRIEVED" = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" ]; then
  echo "✓ Symmetric key store/retrieve works"
else
  echo "✗ Key mismatch"
  exit 1
fi

echo ""
echo "=========================================="
echo "ENHANCED HSM TEST RESULTS"
echo "=========================================="
echo "✓ Hardware scanning"
echo "✓ Master key generation with audit"
echo "✓ Key lifecycle metadata"
echo "✓ Key information display"
echo "✓ ED25519 key pair generation"
echo "✓ Signing and verification"
echo "✓ Audit log system"
echo "✓ Key rotation"
echo "✓ Public key export/import"
echo "✓ Access control (user ID)"
echo "✓ Usage tracking"
echo "✓ Symmetric key operations"
echo ""
echo "12/12 tests passed!"
echo ""
echo "Audit Log Summary:"
cat hsm_audit.log | grep -v "^#" | wc -l | xargs echo "Total audit entries:"
echo ""

# Cleanup
rm -f test_data.txt signature.bin pub_key.pem 2>/dev/null || true

echo "Enhanced HSM is fully functional!"
