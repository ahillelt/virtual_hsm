# Virtual Hardware Security Management (HSM) Program

A virtualized hardware security management tool.

## Table of Contents
- [Overview](#overview)
- [Design Notes](#design-notes)
- [Operation Notes](#operation-notes)
- [Usage](#usage)
  - [Compilation](#compilation)
  - [Command-line Options](#command-line-options)
  - [Key Management](#key-management)
  - [Digital Signatures](#digital-signatures)
  - [Public Key Operations](#public-key-operations)
  - [File Operations](#file-operations)
  - [Custom Keystore and Master Key Files](#custom-keystore-and-master-key-files)
- [GitHub Secrets and Actions Workflow](#github-secrets-and-actions-workflow)
- [Generating a Master Key for GitHub Secrets](#generating-a-master-key-for-github-secrets)
- [Debug Output](#debug-output)
- [Known Limitations](#known-limitations)
- [Common Use Cases](#common-use-cases)

## Overview

This virtual HSM is relatively simple and is not meant to be a true HSM, there is no actual hardware management platform in use. This is a virtualized expression of an HSM that can be addressed via terminal commands. The purpose of the program is to assist those in learning how to interact with HSMs and their functionality. It does provide encryption services, key storage, and ED25519 digital signatures. However, it's all done without storage in a secure hardware environment.

**Warning: Do not use in production environments**

## Design Notes

- Uses the EVP (Envelope) interface for encryption and decryption, with Ed25519 signing
- Implements error handling using OpenSSL's error reporting functions
- Employs AES-256-GCM encryption with a unique IV for each key
- Uses 32-byte (256-bit) keys and supports Ed25519 digital signatures
- Provides persistent storage through `keystore.dat` and `master.key` split-paired files
- Fully supports GitHub Secrets and Actions Workflow passing as Hexadecimal via command line
- Allows generation, storage, and management of public/private key pairs
- Includes comprehensive error handling and debug output to learn more about HSM internals
- Supports both file-based and stdin/stdout operations

## Operation Notes

Upon execution, the program generates two files:

1. `keystore.dat`: An encrypted database file storing the key information
2. `master.key`: The master key file required to access the HSM (paired with `keystore.dat`)

Input/Output:
- Key storage: Reads 64 hexadecimal characters (representing 32 bytes) from stdin or file
- Key retrieval: Prints the key in hexadecimal format (64 characters) to stdout or file
- Digital signatures: Reads data from stdin or file, outputs signature to stdout or file
- Public key export: Outputs public key in PEM format to stdout or file
- Public key import: Reads PEM formatted public key from stdin or file
- The program exits with a non-zero status code on errors

### Keystore Structure
The keystore.dat file stores keys in a binary format, with each key entry containing:
- Key name (up to 49 characters)
- Key data (32 bytes)
- Initialization Vector (12 bytes)
- GCM Tag (16 bytes)
- Encrypted data length
- A flag indicating if it's a public key

### Hexadecimal Representation
Why is a 64 character Hexadecimal output representative of 256 bits?:
Each hexadecimal character represents 4 bits. Since there are 64 hexadecimal characters, they represent a total of 64 * 4 = 256 bits (or 32 bytes).

Example:
```
Hex character '0' = 0000 in binary (4 bits)
Hex character 'F' = 1111 in binary (4 bits)

So a key like:
"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
                            |
                    64 hex characters
                            |
                    64 * 4 = 256 bits
                            |
                    256 / 8 = 32 bytes
```

Therefore, keep the following in mind:
1. All keys must be exactly 64 hexadecimal characters when stored
2. The key data field is 32 bytes in the keystore
3. Ed25519 keys are 256 bits (32 bytes)
   
## Usage

### Compilation

```bash
gcc -o virtual_hsm virtual_hsm.c -lcrypto
```

### Command-line Options

Global Options:
```bash
-keystore <file>      # Specify custom keystore file (default: keystore.dat)
-master <file>        # Specify custom master key file (default: master.key)
-master_key <hex>     # Provide master key directly as hex string
```

Key Management Commands:
```bash
-store <key_name>           # Store a symmetric key
-retrieve <key_name>        # Retrieve a stored key
-list                      # List all stored keys
-generate_master_key       # Generate a new master key
-generate_key_pair <name>  # Generate ED25519 key pair
```

Digital Signature Commands:
```bash
-sign <key_name>           # Sign data using private key
-verify <key_name>         # Verify signature
-export_public_key <name>  # Export public key in PEM format
-import_public_key <name>  # Import public key from PEM format

### Key Management

Store a key (must be exactly 64 hexadecimal characters):
```bash
echo -n "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF" | ./virtual_hsm -store mykey
```

Generate and store a random key:
```bash
openssl rand -hex 32 | ./virtual_hsm -store randomkey
```

Retrieve a key:
```bash
./virtual_hsm -retrieve mykey
```

List all keys:
```bash
./virtual_hsm -list
```

### Digital Signatures

Complete signature workflow:

1. Generate a key pair:
```bash
./virtual_hsm -generate_key_pair signing_key
```

2. Sign a file:
```bash
# Sign a file and save signature
cat myfile.txt | ./virtual_hsm -sign signing_key > signature.bin

# Sign string data
echo -n "Hello, World!" | ./virtual_hsm -sign signing_key > signature.bin
```

3. Verify a signature:
```bash
# Using concatenated input
(cat myfile.txt; cat signature.bin) | ./virtual_hsm -verify signing_key_public

# Using separate files
./virtual_hsm -verify signing_key_public -in myfile.txt -sig signature.bin
```

### Public Key Operations

Export public key:
```bash
# Export to file
./virtual_hsm -export_public_key signing_key_public > public_key.pem

# View public key
./virtual_hsm -export_public_key signing_key_public
```

Import public key:
```bash
# Import from file
cat public_key.pem | ./virtual_hsm -import_public_key imported_key

# Import directly
echo "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----" | ./virtual_hsm -import_public_key imported_key
```
Note: Public keys are stored unencrypted in the keystore.

### Common Use Cases

1. Secure File Signing System:
```bash
# Setup
./virtual_hsm -generate_key_pair document_signer

# Sign a document
cat important.pdf | ./virtual_hsm -sign document_signer > important.pdf.sig

# Verify the document
(cat important.pdf; cat important.pdf.sig) | ./virtual_hsm -verify document_signer_public
```

2. Key Distribution System:
```bash
# Generate and store a secure key
openssl rand -hex 32 | ./virtual_hsm -store encryption_key

# Export the key for backup
./virtual_hsm -retrieve encryption_key > backup_key.hex

# Import the key on another system
cat backup_key.hex | ./virtual_hsm -store encryption_key
```

3. Multi-Environment Key Management:
```bash
# Development environment
./virtual_hsm -keystore dev_keystore.dat -master dev_master.key -store api_key

# Production environment
./virtual_hsm -keystore prod_keystore.dat -master prod_master.key -store api_key
```
## GitHub Secrets and Actions Workflow

You can pass the master key directly as a command-line argument using the `-master_key` option:

```yaml
name: HSM Operations
on: [push]

jobs:
  hsm-job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup HSM
        run: |
          gcc -o virtual_hsm virtual_hsm.c -lcrypto
          
      - name: Store Key
        run: |
          echo ${{ secrets.API_KEY }} | ./virtual_hsm \
            -master_key ${{ secrets.MASTER_KEY }} \
            -store service_key
            
      - name: Sign Data
        run: |
          echo "Important data" | ./virtual_hsm \
            -master_key ${{ secrets.MASTER_KEY }} \
            -sign signing_key > signature.bin
```

## Debug Output

The program includes detailed debug output prefixed with "Debug:". To capture debug messages:

```bash
# Log to file
./virtual_hsm -list 2>debug.log

# View debug output
./virtual_hsm -list 2>&1

# Suppress debug output
./virtual_hsm -list 2>/dev/null
```

## Known Limitations

This implementation is for educational purposes and lacks several security features found in production HSMs:

- Secure memory management
- Access controls and authentication
- Audit logging
- Proper key lifecycle management
- Protection against side-channel attacks
- Undefined behavior protection
- No secure key erasure from memory
- Limited error handling for some operations
- No protection against key overwriting
- No built-in key rotation mechanism
