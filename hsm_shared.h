#ifndef HSM_SHARED_H
#define HSM_SHARED_H

#include "common_defs.h"

// Forward declarations of shared structures
typedef struct {
    char name[MAX_NAME_LENGTH + 1];
    unsigned char key_data[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    int encrypted_len;
    int is_public_key;
	unsigned char master_key_hash[MASTER_KEY_HASH_SIZE];
} KeyEntry;

// External declarations for shared variables
extern KeyEntry keystore[MAX_KEYS];
extern int key_count;

// Function declarations shared between files
void store_key(const char *name, const unsigned char *key, int is_public_key);
int decrypt_key(const unsigned char *ciphertext, int ciphertext_len,
               unsigned char *plaintext, const unsigned char *iv,
               const unsigned char *tag);

#endif // HSM_SHARED_H
