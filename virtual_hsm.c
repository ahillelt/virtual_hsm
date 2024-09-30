#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>

#define MAX_KEYS 100
#define KEY_SIZE 32
#define IV_SIZE 16
#define KEYSTORE_FILE "keystore.dat"
#define MASTER_KEY_FILE "master.key"

typedef struct {
    char name[50];
    unsigned char encrypted_key[KEY_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char iv[IV_SIZE];
    int encrypted_len;
} KeyEntry;

KeyEntry keystore[MAX_KEYS];
int key_count = 0;
unsigned char master_key[KEY_SIZE];

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void load_master_key() {
    FILE *file = fopen(MASTER_KEY_FILE, "rb");
    if (file == NULL) {
        if (RAND_bytes(master_key, KEY_SIZE) != 1) {
            handle_errors();
        }
        file = fopen(MASTER_KEY_FILE, "wb");
        fwrite(master_key, 1, KEY_SIZE, file);
    } else {
        fread(master_key, 1, KEY_SIZE, file);
    }
    fclose(file);
}

void save_keystore() {
    FILE *file = fopen(KEYSTORE_FILE, "wb");
    fwrite(&key_count, sizeof(int), 1, file);
    fwrite(keystore, sizeof(KeyEntry), key_count, file);
    fclose(file);
}

void load_keystore() {
    FILE *file = fopen(KEYSTORE_FILE, "rb");
    if (file != NULL) {
        fread(&key_count, sizeof(int), 1, file);
        fread(keystore, sizeof(KeyEntry), key_count, file);
        fclose(file);
    }
}

int encrypt_key(const unsigned char *plaintext, unsigned char *ciphertext, int *ciphertext_len, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        handle_errors();
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, master_key, iv))
        handle_errors();

    int len;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, KEY_SIZE))
        handle_errors();
    *ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handle_errors();
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt_key(const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, master_key, iv))
        handle_errors();

    int len;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();
    int plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handle_errors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void store_key(const char *name, const unsigned char *key) {
    if (key_count >= MAX_KEYS) {
        fprintf(stderr, "Error: Keystore is full.\n");
        exit(1);
    }

    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            fprintf(stderr, "Error: Key with this name already exists.\n");
            exit(1);
        }
    }

    KeyEntry *entry = &keystore[key_count++];
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    if (!encrypt_key(key, entry->encrypted_key, &entry->encrypted_len, entry->iv)) {
        fprintf(stderr, "Error: Failed to encrypt key.\n");
        exit(1);
    }
    save_keystore();
    printf("Key stored successfully.\n");
}

void retrieve_key(const char *name, int pipe_mode) {
    for (int i = 0; i < key_count; i++) {
        if (strcmp(keystore[i].name, name) == 0) {
            unsigned char decrypted_key[KEY_SIZE];
            int decrypted_len = decrypt_key(keystore[i].encrypted_key, keystore[i].encrypted_len, decrypted_key, keystore[i].iv);
            if (decrypted_len != KEY_SIZE) {
                fprintf(stderr, "Error: Decrypted key length mismatch.\n");
                exit(1);
            }
            fwrite(decrypted_key, 1, KEY_SIZE, stdout);
            if (pipe_mode) {
                printf("\n");
            }
            return;
        }
    }
    fprintf(stderr, "Error: Key not found.\n");
    exit(1);
}

void list_keys() {
    for (int i = 0; i < key_count; i++) {
        printf("%s\n", keystore[i].name);
    }
}

void print_usage() {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  ./virtual_hsm -store <key_name>\n");
    fprintf(stderr, "  ./virtual_hsm -retrieve <key_name> [-pipe]\n");
    fprintf(stderr, "  ./virtual_hsm -list\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    load_master_key();
    load_keystore();

    if (strcmp(argv[1], "-store") == 0) {
        if (argc != 3) {
            print_usage();
            return 1;
        }
        unsigned char key[KEY_SIZE];
        if (fread(key, 1, KEY_SIZE, stdin) != KEY_SIZE) {
            fprintf(stderr, "Error: Invalid key input. Please provide 32 bytes.\n");
            return 1;
        }
        store_key(argv[2], key);
    } else if (strcmp(argv[1], "-retrieve") == 0) {
        if (argc != 3 && argc != 4) {
            print_usage();
            return 1;
        }
        int pipe_mode = (argc == 4 && strcmp(argv[3], "-pipe") == 0);
        retrieve_key(argv[2], pipe_mode);
    } else if (strcmp(argv[1], "-list") == 0) {
        list_keys();
    } else {
        print_usage();
        return 1;
    }

    return 0;
}