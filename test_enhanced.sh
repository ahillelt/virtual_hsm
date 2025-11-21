#!/bin/bash
echo "=== ENHANCED HSM COMPREHENSIVE TEST ==="
rm -f master.key keystore.dat hsm_audit.log .*.metadata 2>/dev/null || true

echo ""
echo "Test 1: Hardware Scan"
./hsm_enhanced -scan_hardware 2>&1 | grep -E "(Scanning|detected|Software)" | head -5

echo ""
echo "Test 2: Master Key Generation"
./hsm_enhanced -generate_master_key store_key 2>&1 | grep -v "^Debug:"
[ -f master.key ] && echo "✓ Master key created"
[ -f hsm_audit.log ] && echo "✓ Audit log created"

echo ""
echo "Test 3: Store Key with Metadata"
echo -n "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" | ./hsm_enhanced -store test_key1 2>&1 | grep -v "^Debug:"
[ -f .test_key1.metadata ] && echo "✓ Metadata created"

echo ""
echo "Test 4: Key Information"
./hsm_enhanced -key_info test_key1 2>&1 | grep -v "^Debug:" | head -10

echo ""
echo "Test 5: Generate Key Pair"
./hsm_enhanced -generate_key_pair signing_key 2>&1 | grep -v "^Debug:"

echo ""
echo "Test 6: Sign and Verify"
echo "Test data" > test_data.txt
./hsm_enhanced -sign signing_key -i test_data.txt -o signature.bin 2>/dev/null
[ -f signature.bin ] && [ $(wc -c < signature.bin) -eq 64 ] && echo "✓ Signature created (64 bytes)"
./hsm_enhanced -verify signing_key -i test_data.txt -s signature.bin 2>&1 | grep "verified" && echo "✓ Verification passed"

echo ""
echo "Test 7: Audit Log"
./hsm_enhanced -audit_logs 1 2>&1 | grep -v "^Debug:" | tail -5

echo ""
echo "Test 8: Key Rotation"
./hsm_enhanced -rotate_key test_key1 2>&1 | grep -v "^Debug:" | grep -v "WARNING" | head -3

echo ""
echo "Test 9: List All Keys"
./hsm_enhanced -list 2>&1 | grep -v "^Debug:" | grep -v "WARNING"

echo ""
echo "=== ALL ENHANCED HSM TESTS COMPLETED ==="

# Show audit log summary
echo ""
echo "Audit Log Entries:"
cat hsm_audit.log | grep -v "^#" | wc -l

rm -f test_data.txt signature.bin 2>/dev/null || true
