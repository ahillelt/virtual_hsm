#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <uuid/uuid.h>
#include <errno.h>
#include <unistd.h>  // Added for access() and F_OK

#define BUFFER_SIZE 4096
#define IV_SIZE 16
#define KEY_SIZE 32
#define TOKEN_SIZE 37  // UUID string length (36) + null terminator
#define HASH_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)  // Hex string length + null terminator
#define STORAGE_PATH "./secure_storage/"
#define KEY_FILE_PATH "./secure_storage/master.key"

// Structure to store metadata - moved to the top before any function declarations
typedef struct {
    char token[TOKEN_SIZE];
    size_t data_size;
    unsigned char iv[IV_SIZE];
    char original_filename[256];
} Metadata;

// Function Header Declarations
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex);
void hash_token(const char* token, char* hashed_filename);
int save_key(const unsigned char* key);
int load_key(unsigned char* key);
char* generate_token(void);
int initialize_key(unsigned char* key);
void print_file_info(const char* filepath);

// File handling declarations
char* handle_file_conflict(const char* output_dir, const char* original_filename);
int handle_store_file(const char* input_path, char** output_path, const char* token, size_t* file_size);

// Encryption/Decryption declarations
int encrypt_file_core(FILE* ifp, FILE* ofp, unsigned char* key, unsigned char* iv);
int encrypt_file(const char* input_path, const char* output_path, unsigned char* key, unsigned char* iv);
int decrypt_file_core(FILE* ifp, FILE* ofp, unsigned char* key, unsigned char* iv);
int decrypt_file(const char* input_path, const char* output_dir, unsigned char* key, unsigned char* iv, const Metadata* metadata);

// Metadata handling declarations
int save_metadata(const Metadata* metadata);
int load_metadata(const char* token, Metadata* metadata);



// Function to convert bytes to hex string
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

// store handling function
int handle_store_file(const char* input_path, char** output_path, const char* token, size_t* file_size) {
    struct stat st;
    if (stat(input_path, &st) == -1) {
        printf("Error: Input file does not exist\n");
        return -1;
    }

    // Store file size
    *file_size = st.st_size;

    // Get and display file information
    printf("\nProcessing file: %s\n", input_path);
    printf("Original file information:\n");
    print_file_info(input_path);
    
    // Create storage directory if it doesn't exist
    mkdir(STORAGE_PATH, 0700);
    
    // Generate hashed filename
    char hashed_filename[HASH_SIZE];
    hash_token(token, hashed_filename);
    
    // Allocate and create output path
    *output_path = malloc(512);
    if (!*output_path) {
        printf("Error: Memory allocation failed\n");
        return -1;
    }
    snprintf(*output_path, 512, "%s%s.enc", STORAGE_PATH, hashed_filename);

    printf("\nStarting encryption process...\n");
    printf("File size: %zu bytes\n", *file_size);
    printf("This may take a while for larger files.\n");
    printf("Target encrypted file: %s\n", *output_path);

    return 0;
}



// Function to hash token into filename
void hash_token(const char* token, char* hashed_filename) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Create new message digest context
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Error creating message digest context\n");
        return;
    }

    // Initialize with SHA256 algorithm
    md = EVP_sha256();
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        printf("Error initializing digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Update with input token
    if (EVP_DigestUpdate(mdctx, token, strlen(token)) != 1) {
        printf("Error updating digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Finalize hash
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        printf("Error finalizing digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Convert hash to hex string
    bytes_to_hex(hash, hash_len, hashed_filename);

    // Clean up
    EVP_MD_CTX_free(mdctx);
}

// Function to save the encryption key
int save_key(const unsigned char* key) {
    FILE* fp = fopen(KEY_FILE_PATH, "wb");
    if (!fp) {
        printf("Error opening key file: %s\n", strerror(errno));
        return -1;
    }
    size_t written = fwrite(key, 1, KEY_SIZE, fp);
    fclose(fp);
    return (written == KEY_SIZE) ? 0 : -1;
}

// Function to load the encryption key
int load_key(unsigned char* key) {
    FILE* fp = fopen(KEY_FILE_PATH, "rb");
    if (!fp) {
        printf("Error opening key file: %s\n", strerror(errno));
        return -1;
    }
    size_t read = fread(key, 1, KEY_SIZE, fp);
    fclose(fp);
    return (read == KEY_SIZE) ? 0 : -1;
}

// Generate a unique token using UUID
char* generate_token(void) {
    uuid_t uuid;
    char* token = malloc(TOKEN_SIZE);
    if (!token) {
        return NULL;
    }
    uuid_generate(uuid);
    uuid_unparse(uuid, token);
    return token;
}

// Initialize or load encryption key
int initialize_key(unsigned char* key) {
    struct stat st;
    if (stat(KEY_FILE_PATH, &st) == 0) {
        // Key file exists, load it
        return load_key(key);
    } else {
        // Generate new key and save it
        if (RAND_bytes(key, KEY_SIZE) != 1) {
            return -1;
        }
        return save_key(key);
    }
}

// Encrypt file
int encrypt_file(const char* input_path, const char* output_path, 
                unsigned char* key, unsigned char* iv) {
    FILE *ifp, *ofp;
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer_in[BUFFER_SIZE];
    unsigned char buffer_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len;
    int ret = 0;

    // Open input file
    ifp = fopen(input_path, "rb");
    if (!ifp) {
        printf("Error opening input file: %s\n", strerror(errno));
        return -1;
    }

    // Open output file
    ofp = fopen(output_path, "wb");
    if (!ofp) {
        printf("Error opening output file: %s\n", strerror(errno));
        fclose(ifp);
        return -1;
    }

    // Generate random IV
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        fclose(ifp);
        fclose(ofp);
        return -1;
    }

    // Write IV at the beginning of the output file
    if (fwrite(iv, 1, IV_SIZE, ofp) != IV_SIZE) {
        fclose(ifp);
        fclose(ofp);
        return -1;
    }

    // Initialize encryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(ifp);
        fclose(ofp);
        return -1;
    }

    // Initialize encryption operation
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(ifp);
        fclose(ofp);
        return -1;
    }

    // Encrypt file content
    while ((bytes_read = fread(buffer_in, 1, BUFFER_SIZE, ifp)) > 0) {
        if (!EVP_EncryptUpdate(ctx, buffer_out, &out_len, buffer_in, bytes_read)) {
            ret = -1;
            break;
        }
        if (fwrite(buffer_out, 1, out_len, ofp) != (size_t)out_len) {
            ret = -1;
            break;
        }
    }

    if (ret == 0) {
        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, buffer_out, &out_len)) {
            if (fwrite(buffer_out, 1, out_len, ofp) != (size_t)out_len) {
                ret = -1;
            }
        } else {
            ret = -1;
        }

        // Get and write the tag
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
            if (fwrite(tag, 1, 16, ofp) != 16) {
                ret = -1;
            }
        } else {
            ret = -1;
        }
    }

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(ifp);
    fclose(ofp);
    
    return ret;
}

// Handle file path and name conflicts
char* handle_file_conflict(const char* output_dir, const char* original_filename) {
    static char final_path[512];
    const char* base_filename = strrchr(original_filename, '/');
    if (base_filename == NULL) {
        base_filename = original_filename;
    } else {
        base_filename++; // Skip the '/' character
    }

    // Construct initial output filepath
    snprintf(final_path, sizeof(final_path), "%s/%s", output_dir, base_filename);

    // Check if file exists
    if (access(final_path, F_OK) != -1) {
        printf("\nFile already exists: %s\n", final_path);
        printf("Existing file information:\n");
        print_file_info(final_path);

        printf("\nChoose an option:\n");
        printf("1) Overwrite existing file\n");
        printf("2) Enter new filename\n");
        printf("Choice (1 or 2): ");
        
        char choice[8];  // Increased buffer size
        if (fgets(choice, sizeof(choice), stdin) != NULL) {
            choice[strcspn(choice, "\n")] = 0;  // Remove newline
            
            if (strcmp(choice, "2") == 0) {
                char new_filename[256];
                printf("Enter new filename: ");
                if (fgets(new_filename, sizeof(new_filename), stdin) != NULL) {
                    // Remove newline if present
                    new_filename[strcspn(new_filename, "\n")] = 0;
                    
                    // Create new path with the new filename
                    snprintf(final_path, sizeof(final_path), "%s/%s", output_dir, new_filename);
                }
            } else if (strcmp(choice, "1") != 0) {
                return NULL;  // Invalid choice
            }
        }
    }

    return final_path;
}

// Core decryption function - only handles the cryptographic operations
int decrypt_file_core(FILE* ifp, FILE* ofp, unsigned char* key, unsigned char* iv) {
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer_in[BUFFER_SIZE];
    unsigned char buffer_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len;
    int ret = 0;

    // Read IV from input file
    if (fread(iv, 1, IV_SIZE, ifp) != IV_SIZE) {
        printf("Error reading IV from file\n");
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Get file sizes
    fseek(ifp, 0, SEEK_END);
    long file_size = ftell(ifp);
    fseek(ifp, IV_SIZE, SEEK_SET);
    long encrypted_size = file_size - IV_SIZE - 16;  // Subtract IV and tag size

    // Decrypt file content
    long total_read = 0;
    while (total_read < encrypted_size) {
        bytes_read = fread(buffer_in, 1, 
                          ((encrypted_size - total_read) > BUFFER_SIZE) ? 
                          BUFFER_SIZE : (encrypted_size - total_read), 
                          ifp);
        if (bytes_read <= 0) break;
        
        total_read += bytes_read;
        if (!EVP_DecryptUpdate(ctx, buffer_out, &out_len, buffer_in, bytes_read)) {
            printf("Error in decrypt update\n");
            ret = -1;
            break;
        }
        if (fwrite(buffer_out, 1, out_len, ofp) != (size_t)out_len) {
            ret = -1;
            break;
        }
    }

    // Handle authentication tag
    if (ret == 0) {
        unsigned char tag[16];
        if (fread(tag, 1, 16, ifp) != 16) {
            printf("Error reading authentication tag\n");
            ret = -1;
        }

        if (ret == 0) {
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
            if (EVP_DecryptFinal_ex(ctx, buffer_out, &out_len) <= 0) {
                printf("Error authenticating decrypted data\n");
                ret = -1;
            } else if (fwrite(buffer_out, 1, out_len, ofp) != (size_t)out_len) {
                ret = -1;
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// Main decrypt function - handles file operations and calls core decrypt
int decrypt_file(const char* input_path, const char* output_dir, 
                unsigned char* key, unsigned char* iv, const Metadata* metadata) {
    FILE *ifp = NULL, *ofp = NULL;
    int ret = -1;
    char *final_path;

    // Create output directory if it doesn't exist
    mkdir(output_dir, 0700);

    // Open input file
    ifp = fopen(input_path, "rb");
    if (!ifp) {
        printf("Error opening encrypted file: %s\n", strerror(errno));
        return -1;
    }

    // Handle file conflicts and get final path
    final_path = handle_file_conflict(output_dir, metadata->original_filename);
    if (!final_path) {
        printf("Error handling file path\n");
        fclose(ifp);
        return -1;
    }

    // Open output file
    ofp = fopen(final_path, "wb");
    if (!ofp) {
        printf("Error opening output file: %s\n", strerror(errno));
        fclose(ifp);
        return -1;
    }

    // Perform decryption
    ret = decrypt_file_core(ifp, ofp, key, iv);
    
    // Clean up
    fclose(ifp);
    fclose(ofp);

    if (ret == 0) {
        printf("\nFile successfully decrypted to: %s\n", final_path);
        printf("Decrypted file information:\n");
        print_file_info(final_path);
    } else {
        remove(final_path);  // Clean up partial file on error
    }

    return ret;
}

// Save metadata
int save_metadata(const Metadata* metadata) {
    char hashed_filename[HASH_SIZE];
    hash_token(metadata->token, hashed_filename);
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s.meta", STORAGE_PATH, hashed_filename);
    
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        printf("Error opening metadata file: %s\n", strerror(errno));
        return -1;
    }
    
    size_t written = fwrite(metadata, sizeof(Metadata), 1, fp);
    fclose(fp);
    return (written == 1) ? 0 : -1;
}

// Load metadata
int load_metadata(const char* token, Metadata* metadata) {
    char hashed_filename[HASH_SIZE];
    hash_token(token, hashed_filename);
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s.meta", STORAGE_PATH, hashed_filename);
    
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        printf("Error opening metadata file: %s\n", strerror(errno));
        return -1;
    }
    
    size_t read = fread(metadata, sizeof(Metadata), 1, fp);
    fclose(fp);
    return (read == 1) ? 0 : -1;
}


// check file existence and get info
void print_file_info(const char* filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));
        printf("Size: %ld bytes\n", st.st_size);
        printf("Last modified: %s\n", time_str);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage:\n");
        printf("To store: %s store <filepath>\n", argv[0]);
        printf("To retrieve: %s retrieve <token> <output_path>\n", argv[0]);
        return 1;
    }

    mkdir(STORAGE_PATH, 0700);
    OpenSSL_add_all_algorithms();

    unsigned char key[KEY_SIZE];
    if (initialize_key(key) != 0) {
        printf("Error initializing encryption key\n");
        return 1;
    }

	if (strcmp(argv[1], "store") == 0) {
		char* token = generate_token();
		if (!token) {
			printf("Error generating token\n");
			return 1;
		}

		char* encrypted_path = NULL;
		size_t original_file_size = 0;
		if (handle_store_file(argv[2], &encrypted_path, token, &original_file_size) != 0) {
			free(token);
			return 1;
		}

		unsigned char iv[IV_SIZE];
		printf("Encrypting file...\n");
		if (encrypt_file(argv[2], encrypted_path, key, iv) == 0) {
			Metadata metadata;
			strncpy(metadata.token, token, TOKEN_SIZE);
			metadata.data_size = original_file_size;  // Store the actual file size
			memcpy(metadata.iv, iv, IV_SIZE);
			strncpy(metadata.original_filename, argv[2], sizeof(metadata.original_filename));
			
			printf("Saving metadata...\n");
			if (save_metadata(&metadata) == 0) {
				printf("\nFile encrypted successfully.\n");
				printf("Original file size: %zu bytes\n", original_file_size);
				printf("Encrypted file information:\n");
				print_file_info(encrypted_path);
				printf("\nToken: %s\n", token);
				printf("Keep this token safe - you'll need it to retrieve your file.\n");
			} else {
				printf("Error saving metadata.\n");
			}
		} else {
			printf("Error encrypting file.\n");
		}
		
		free(encrypted_path);
		free(token);
	}
    else if (strcmp(argv[1], "retrieve") == 0) {
        if (argc < 4) {
            printf("Error: Output path required for retrieval.\n");
            return 1;
        }

        Metadata metadata;
        if (load_metadata(argv[2], &metadata) == 0) {
            char hashed_filename[HASH_SIZE];
            hash_token(argv[2], hashed_filename);
            
            char encrypted_path[512];
            snprintf(encrypted_path, sizeof(encrypted_path), 
                     "%s%s.enc", STORAGE_PATH, hashed_filename);

            if (decrypt_file(encrypted_path, argv[3], key, metadata.iv, &metadata) == 0) {
                printf("File decrypted successfully.\n");
            } else {
                printf("Error decrypting file.\n");
            }
        } else {
            printf("Error: Invalid token or metadata not found.\n");
        }
    }
    else {
        printf("Invalid command. Use 'store' or 'retrieve'.\n");
    }

    return 0;
}