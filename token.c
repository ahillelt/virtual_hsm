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
#include <unistd.h>
#include <libgen.h>

// Existing definitions
#define BUFFER_SIZE 4096
#define IV_SIZE 16
#define KEY_SIZE 32
#define TOKEN_SIZE 37
#define HASH_SIZE (SHA256_DIGEST_LENGTH * 2 + 1)
#define STORAGE_PATH "./secure_storage/"
#define KEY_FILE_PATH "./secure_storage/master.key"

// New definitions for chunking
#define MIN_CHUNK_SIZE (5 * 1024 * 1024)  // 5MB
#define MAX_CHUNK_SIZE (10 * 1024 * 1024) // 10MB
#define MAX_CHUNKS 1000                    // Maximum number of chunks per file



// Add encrypted metadata magic number for validation
#define METADATA_MAGIC 0x4D455441  // "META" in hex


typedef struct {
    char token[TOKEN_SIZE];
    size_t data_size;
    unsigned char iv[IV_SIZE];
    char original_filename[256];
    size_t chunk_count;
    char chunk_hashes[MAX_CHUNKS][HASH_SIZE];
    size_t chunk_sizes[MAX_CHUNKS];
} Metadata;

// Add encrypted metadata header structure
typedef struct {
    uint32_t magic;          // Magic number for validation
    size_t metadata_size;    // Size of the encrypted metadata
    unsigned char iv[IV_SIZE]; // IV for metadata encryption
} MetadataHeader;

void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex);
void hash_token(const char* token, char* hashed_filename);
int save_key(const unsigned char* key);
int load_key(unsigned char* key);
char* generate_token(void);
int initialize_key(unsigned char* key);
void print_file_info(const char* filepath);

char* handle_file_conflict(const char* output_dir, const char* original_filename);
int decrypt_file_core(FILE* ifp, FILE* ofp, unsigned char* key, const unsigned char* iv);

// chunking
size_t generate_chunk_size(void);
int handle_store_file(const char* input_path, char*** chunk_paths, size_t* chunk_count,const char* token, size_t* file_size, Metadata* metadata);
int encrypt_file_chunked(const char* input_path, char** chunk_paths, size_t chunk_count,unsigned char* key, Metadata* metadata);
int decrypt_file_chunked(const char* output_dir, unsigned char* key, const Metadata* metadata);

// Metadata
int encrypt_metadata(const Metadata* metadata, const unsigned char* key, const char* filepath);
int decrypt_metadata(const char* filepath, const unsigned char* key, Metadata* metadata);
int save_metadata(const Metadata* metadata);
int load_metadata(const char* token, Metadata* metadata);


// Function to convert bytes to hex string
void bytes_to_hex(const unsigned char* bytes, size_t len, char* hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

// Function to hash token into filename
void hash_token(const char* token, char* hashed_filename) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        printf("Error creating message digest context\n");
        return;
    }

    md = EVP_sha256();
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        printf("Error initializing digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestUpdate(mdctx, token, strlen(token)) != 1) {
        printf("Error updating digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        printf("Error finalizing digest\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    bytes_to_hex(hash, hash_len, hashed_filename);
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
        return load_key(key);
    } else {
        if (RAND_bytes(key, KEY_SIZE) != 1) {
            return -1;
        }
        return save_key(key);
    }
}

// Print file information
void print_file_info(const char* filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));
        printf("Size: %ld bytes\n", st.st_size);
        printf("Last modified: %s\n", time_str);
    }
}

///// 
int encrypt_metadata(const Metadata* metadata, const unsigned char* key, const char* filepath) {
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        printf("Error opening metadata file: %s\n", strerror(errno));
        return -1;
    }

    // Create and write header
    MetadataHeader header;
    header.magic = METADATA_MAGIC;
    header.metadata_size = sizeof(Metadata);
    if (RAND_bytes(header.iv, IV_SIZE) != 1) {
        printf("Error generating IV for metadata\n");
        fclose(fp);
        return -1;
    }

    if (fwrite(&header, sizeof(MetadataHeader), 1, fp) != 1) {
        printf("Error writing metadata header\n");
        fclose(fp);
        return -1;
    }

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, header.iv)) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    // Encrypt metadata
    int out_len;
    unsigned char* buffer_out = malloc(sizeof(Metadata) + EVP_MAX_BLOCK_LENGTH);
    if (!buffer_out) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, buffer_out, &out_len, (unsigned char*)metadata, sizeof(Metadata))) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    if (fwrite(buffer_out, 1, out_len, fp) != (size_t)out_len) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    int final_len;
    if (!EVP_EncryptFinal_ex(ctx, buffer_out + out_len, &final_len)) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    if (final_len > 0) {
        if (fwrite(buffer_out + out_len, 1, final_len, fp) != (size_t)final_len) {
            free(buffer_out);
            EVP_CIPHER_CTX_free(ctx);
            fclose(fp);
            return -1;
        }
    }

    // Write authentication tag
    unsigned char tag[16];
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    if (fwrite(tag, 1, 16, fp) != 16) {
        free(buffer_out);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return -1;
    }

    free(buffer_out);
    EVP_CIPHER_CTX_free(ctx);
    fclose(fp);
    return 0;
}

int decrypt_metadata(const char* filepath, const unsigned char* key, Metadata* metadata) {
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        printf("Error opening metadata file: %s\n", strerror(errno));
        return -1;
    }

    // Read and verify header
    MetadataHeader header;
    if (fread(&header, sizeof(MetadataHeader), 1, fp) != 1) {
        printf("Error reading metadata header\n");
        fclose(fp);
        return -1;
    }

    if (header.magic != METADATA_MAGIC) {
        printf("Invalid metadata file format\n");
        fclose(fp);
        return -1;
    }

    // Read encrypted data
    unsigned char* encrypted_data = malloc(header.metadata_size + 16);  // +16 for tag
    if (!encrypted_data) {
        fclose(fp);
        return -1;
    }

    size_t read_size = fread(encrypted_data, 1, header.metadata_size, fp);
    if (read_size != header.metadata_size) {
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Read authentication tag
    unsigned char tag[16];
    if (fread(tag, 1, 16, fp) != 16) {
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, header.iv)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Decrypt metadata
    int out_len;
    if (!EVP_DecryptUpdate(ctx, (unsigned char*)metadata, &out_len, encrypted_data, header.metadata_size)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    // Verify and finalize decryption
    int final_len;
    if (!EVP_DecryptFinal_ex(ctx, (unsigned char*)metadata + out_len, &final_len)) {
        printf("Error: Metadata authentication failed\n");
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        fclose(fp);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    free(encrypted_data);
    fclose(fp);
    return 0;
}

// Modified save_metadata function
int save_metadata(const Metadata* metadata) {
    char hashed_filename[HASH_SIZE];
    hash_token(metadata->token, hashed_filename);
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s.meta", STORAGE_PATH, hashed_filename);
    
    unsigned char key[KEY_SIZE];
    if (load_key(key) != 0) {
        printf("Error loading key for metadata encryption\n");
        return -1;
    }
    
    return encrypt_metadata(metadata, key, filepath);
}

// Modified load_metadata function
int load_metadata(const char* token, Metadata* metadata) {
    char hashed_filename[HASH_SIZE];
    hash_token(token, hashed_filename);
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s%s.meta", STORAGE_PATH, hashed_filename);
    
    unsigned char key[KEY_SIZE];
    if (load_key(key) != 0) {
        printf("Error loading key for metadata decryption\n");
        return -1;
    }
    
    return decrypt_metadata(filepath, key, metadata);
}

// Handle file conflicts
char* handle_file_conflict(const char* output_dir, const char* original_filename) {
    static char final_path[512];
    const char* base_filename = strrchr(original_filename, '/');
    base_filename = (base_filename == NULL) ? original_filename : base_filename + 1;

    snprintf(final_path, sizeof(final_path), "%s/%s", output_dir, base_filename);

    // Create the output directory if it doesn't exist
    char* output_dir_path = strdup(output_dir);
    char* dir = dirname(output_dir_path);
    if (access(dir, F_OK) != 0) {
        if (mkdir(dir, 0755) != 0) {
            printf("Error creating output directory: %s\n", strerror(errno));
            free(output_dir_path);
            return NULL;
        }
    }
    free(output_dir_path);

    if (access(final_path, F_OK) != -1) {
        printf("\nFile already exists: %s\n", final_path);
        printf("Existing file information:\n");
        print_file_info(final_path);

        printf("\nChoose an option:\n");
        printf("1) Overwrite existing file\n");
        printf("2) Enter new filename\n");
        printf("Choice (1 or 2): ");
        
        char choice[8];
        if (fgets(choice, sizeof(choice), stdin) != NULL) {
            choice[strcspn(choice, "\n")] = 0;
            
            if (strcmp(choice, "2") == 0) {
                char new_filename[256];
                printf("Enter new filename: ");
                if (fgets(new_filename, sizeof(new_filename), stdin) != NULL) {
                    new_filename[strcspn(new_filename, "\n")] = 0;
                    snprintf(final_path, sizeof(final_path), "%s/%s", output_dir, new_filename);
                }
            } else if (strcmp(choice, "1") != 0) {
                return NULL;
            }
        }
    }

    return final_path;
}

// Core decryption function
// Core decryption function
int decrypt_file_core(FILE* ifp, FILE* ofp, unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX *ctx;
    unsigned char buffer_in[BUFFER_SIZE];
    unsigned char buffer_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, out_len;
    int ret = 0;

    if (fread((unsigned char*)iv, 1, IV_SIZE, ifp) != IV_SIZE) {
        printf("Error reading IV from file\n");
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
        printf("Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    fseek(ifp, 0, SEEK_END);
    long file_size = ftell(ifp);
    fseek(ifp, IV_SIZE, SEEK_SET);
    long encrypted_size = file_size - IV_SIZE - 16;

    long total_read = 0;
    while (total_read < encrypted_size) {
        bytes_read = fread(buffer_in, 1, 
                          ((encrypted_size - total_read) > BUFFER_SIZE) ? 
                          BUFFER_SIZE : (encrypted_size - total_read), 
                          ifp);
        if (bytes_read <= 0) {
            printf("Error reading from input file\n");
            ret = -1;
            break;
        }
        
        total_read += bytes_read;
        if (!EVP_DecryptUpdate(ctx, buffer_out, &out_len, buffer_in, bytes_read)) {
            printf("Error in decrypt update\n");
            ret = -1;
            break;
        }
        if (fwrite(buffer_out, 1, out_len, ofp) != (size_t)out_len) {
            printf("Error writing to output file\n");
            ret = -1;
            break;
        }
    }

	if (ret == 0) {
		unsigned char tag[16];
		if (fread(tag, 1, 16, ifp) != 16) {
			printf("Error reading authentication tag\n");
			ret = -1;
		} else {
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
			if (EVP_DecryptFinal_ex(ctx, buffer_out, &out_len) <= 0) {
				printf("Error authenticating decrypted data\n");
				ret = -1;
			} else if (fwrite(buffer_out, 1, out_len, ofp) != (size_t)out_len) {
				printf("Error writing to output file\n");
				ret = -1;
			}
		}
	}

    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int decrypt_file_chunked(const char* output_dir, unsigned char* key, const Metadata* metadata) {
    // First, get the final path handling any conflicts
    char initial_path[512];
    snprintf(initial_path, sizeof(initial_path), "%s/%s", output_dir, metadata->original_filename);
    
    const char* final_path = handle_file_conflict(output_dir, metadata->original_filename);
    if (!final_path) {
        printf("Error handling file conflict\n");
        return -1;
    }

    // Create output directory
    char* dir_path = strdup(output_dir);
    if (dir_path) {
        if (mkdir(dir_path, 0755) != 0 && errno != EEXIST) {
            printf("Error creating output directory: %s\n", strerror(errno));
        }
        free(dir_path);
    }

    printf("Final output file path: %s\n", final_path);

    FILE* ofp = fopen(final_path, "wb");
    if (!ofp) {
        printf("Error opening output file: %s\n", strerror(errno));
        return -1;
    }

    // Process each chunk
    for (size_t i = 0; i < metadata->chunk_count; i++) {
        // Construct chunk path from hash stored in metadata
        char chunk_path[512];
        snprintf(chunk_path, sizeof(chunk_path), "%s%s.chunk", 
                STORAGE_PATH, metadata->chunk_hashes[i]);
        
        printf("Processing chunk %zu: %s\n", i, chunk_path);
        
        FILE* chunk_fp = fopen(chunk_path, "rb");
        if (!chunk_fp) {
            printf("Error opening chunk file: %s\n", chunk_path);
            fclose(ofp);
            return -1;
        }

        // Decrypt chunk
        if (decrypt_file_core(chunk_fp, ofp, key, metadata->iv) != 0) {
            printf("Error decrypting chunk %zu\n", i);
            fclose(chunk_fp);
            fclose(ofp);
            return -1;
        }

        fclose(chunk_fp);
        printf("Chunk %zu/%zu decrypted\n", i + 1, metadata->chunk_count);
    }

    fclose(ofp);
    printf("\nFile successfully decrypted to: %s\n", final_path);
    print_file_info(final_path);
    return 0;
}

// New function to generate random chunk size
size_t generate_chunk_size(void) {
    size_t range = MAX_CHUNK_SIZE - MIN_CHUNK_SIZE;
    size_t random_offset = (size_t)(((double)rand() / RAND_MAX) * range);
    return MIN_CHUNK_SIZE + random_offset;
}

int handle_store_file(const char* input_path, char*** chunk_paths, size_t* chunk_count,
                      const char* token, size_t* file_size, Metadata* metadata) {
    struct stat st;
    if (stat(input_path, &st) == -1) {
        printf("Error: Input file does not exist\n");
        return -1;
    }

    *file_size = st.st_size;
    size_t remaining_size = *file_size;
    *chunk_count = 0;
    
    // Calculate number of chunks needed
    while (remaining_size > 0) {
        size_t chunk_size = generate_chunk_size();
        if (chunk_size > remaining_size) {
            chunk_size = remaining_size;
        }
        (*chunk_count)++;
        remaining_size -= chunk_size;
        
        if (*chunk_count >= MAX_CHUNKS) {
            printf("Error: File too large, maximum chunks exceeded\n");
            return -1;
        }
    }

    // Allocate memory for chunk paths
    *chunk_paths = malloc(*chunk_count * sizeof(char*));
    if (!*chunk_paths) {
        printf("Error: Memory allocation failed\n");
        return -1;
    }

    mkdir(STORAGE_PATH, 0700);
    char base_hash[HASH_SIZE];
    hash_token(token, base_hash);

    // Generate chunk paths and store hashes
    for (size_t i = 0; i < *chunk_count; i++) {
        (*chunk_paths)[i] = malloc(512);
        if (!(*chunk_paths)[i]) {
            // Cleanup previously allocated memory
            for (size_t j = 0; j < i; j++) {
                free((*chunk_paths)[j]);
            }
            free(*chunk_paths);
            printf("Error: Memory allocation failed for chunk path\n");
            return -1;
        }

        // Generate unique hash for each chunk
        char chunk_input[HASH_SIZE + 20];
        snprintf(chunk_input, sizeof(chunk_input), "%s_%zu", base_hash, i);
        
        // Store just the hash in metadata
        char chunk_hash[HASH_SIZE];
        hash_token(chunk_input, chunk_hash);
        strncpy(metadata->chunk_hashes[i], chunk_hash, HASH_SIZE - 1);
        metadata->chunk_hashes[i][HASH_SIZE - 1] = '\0';

        // Construct the full path for chunk_paths
        snprintf((*chunk_paths)[i], 512, "%s%s.chunk", STORAGE_PATH, chunk_hash);
        
        printf("Chunk %zu path: %s\n", i, (*chunk_paths)[i]);
    }

    printf("File will be split into %zu chunks\n", *chunk_count);
    return 0;
}




// New function to encrypt file in chunks
int encrypt_file_chunked(const char* input_path, char** chunk_paths, size_t chunk_count, 
                        unsigned char* key, Metadata* metadata) {
    FILE* ifp = fopen(input_path, "rb");
    if (!ifp) {
        printf("Error opening input file: %s\n", strerror(errno));
        return -1;
    }

    size_t remaining_size = metadata->data_size;
    size_t current_pos = 0;

    for (size_t i = 0; i < chunk_count; i++) {
        size_t chunk_size = generate_chunk_size();
        if (chunk_size > remaining_size) {
            chunk_size = remaining_size;
        }

        unsigned char chunk_iv[IV_SIZE];
        if (RAND_bytes(chunk_iv, IV_SIZE) != 1) {
            fclose(ifp);
            return -1;
        }

        metadata->chunk_sizes[i] = chunk_size;

        // Use the already generated and stored chunk path from handle_store_file
        const char* chunk_path = chunk_paths[i];

        FILE* temp_fp = fopen(chunk_path, "wb");
        if (!temp_fp) {
            fclose(ifp);
            return -1;
        }

        fseek(ifp, current_pos, SEEK_SET);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fclose(ifp);
            fclose(temp_fp);
            return -1;
        }

        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, chunk_iv)) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(ifp);
            fclose(temp_fp);
            return -1;
        }

        if (fwrite(chunk_iv, 1, IV_SIZE, temp_fp) != IV_SIZE) {
            EVP_CIPHER_CTX_free(ctx);
            fclose(ifp);
            fclose(temp_fp);
            return -1;
        }

        unsigned char buffer_in[BUFFER_SIZE];
        unsigned char buffer_out[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
        size_t total_read = 0;
        int out_len;

        while (total_read < chunk_size) {
            size_t to_read = (chunk_size - total_read) < BUFFER_SIZE ? 
                            (chunk_size - total_read) : BUFFER_SIZE;
            
            size_t bytes_read = fread(buffer_in, 1, to_read, ifp);
            if (bytes_read == 0) break;

            if (!EVP_EncryptUpdate(ctx, buffer_out, &out_len, buffer_in, bytes_read)) {
                EVP_CIPHER_CTX_free(ctx);
                fclose(ifp);
                fclose(temp_fp);
                return -1;
            }

            if (fwrite(buffer_out, 1, out_len, temp_fp) != (size_t)out_len) {
                EVP_CIPHER_CTX_free(ctx);
                fclose(ifp);
                fclose(temp_fp);
                return -1;
            }

            total_read += bytes_read;
        }

        if (EVP_EncryptFinal_ex(ctx, buffer_out, &out_len)) {
            if (fwrite(buffer_out, 1, out_len, temp_fp) != (size_t)out_len) {
                EVP_CIPHER_CTX_free(ctx);
                fclose(ifp);
                fclose(temp_fp);
                return -1;
            }
        }

        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
            if (fwrite(tag, 1, 16, temp_fp) != 16) {
                EVP_CIPHER_CTX_free(ctx);
                fclose(ifp);
                fclose(temp_fp);
                return -1;
            }
        }

        EVP_CIPHER_CTX_free(ctx);
        fclose(temp_fp);

        current_pos += chunk_size;
        remaining_size -= chunk_size;

        printf("Chunk %zu/%zu encrypted (%zu bytes)\n", i + 1, chunk_count, chunk_size);
    }

    fclose(ifp);
    metadata->chunk_count = chunk_count;
    return 0;
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

        char** chunk_paths = NULL;
        size_t chunk_count = 0;
        size_t original_file_size = 0;
        
        // Declare and initialize Metadata
        Metadata metadata = {0};  // Initialize to zero
        strncpy(metadata.token, token, TOKEN_SIZE);

        if (handle_store_file(argv[2], &chunk_paths, &chunk_count, token, &original_file_size, &metadata) != 0) {
            free(token);
            return 1;
        }

        metadata.data_size = original_file_size;
        strncpy(metadata.original_filename, argv[2], sizeof(metadata.original_filename));

        printf("Encrypting file in chunks...\n");
        if (encrypt_file_chunked(argv[2], chunk_paths, chunk_count, key, &metadata) == 0) {
            printf("Saving metadata...\n");
            if (save_metadata(&metadata) == 0) {
                printf("\nFile encrypted successfully in %zu chunks.\n", chunk_count);
                printf("Token: %s\n", token);
                printf("Keep this token safe - you'll need it to retrieve your file.\n");
            }
        }

        // Cleanup
        for (size_t i = 0; i < chunk_count; i++) {
            free(chunk_paths[i]);
        }
        free(chunk_paths);
        free(token);
    }
    else if (strcmp(argv[1], "retrieve") == 0) {
        if (argc < 4) {
            printf("Error: Output path required for retrieval.\n");
            return 1;
        }

        printf("\nStarting file retrieval process...\n");
        printf("Token: %s\n", argv[2]);
        
        Metadata metadata;
        printf("Loading metadata...\n");
        if (load_metadata(argv[2], &metadata) == 0) {
            if (decrypt_file_chunked(argv[3], key, &metadata) == 0) {
                printf("\nRetrieval process completed successfully.\n");
            } else {
                printf("\nError: Decryption failed.\n");
            }
        } else {
            printf("Error: Invalid token or metadata not found.\n");
            printf("Please check if the token is correct and try again.\n");
        }
    }
    else {
        printf("Invalid command. Use 'store' or 'retrieve'.\n");
    }

    return 0;
}
