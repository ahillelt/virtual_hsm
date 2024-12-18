#ifndef COMMON_DEFS_H
#define COMMON_DEFS_H

#define MAX_FILENAME 256
#define MAX_NAME_LENGTH 49
#define MAX_KEYS 100
#define KEY_SIZE 32 
#define IV_SIZE 12  
#define TAG_SIZE 16

#define MASTER_KEY_HASH_SIZE 32 // Assuming SHA256 hash

// Encryption variables
#define PEM_KEY_CHAR_ARR_SIZE 4096
#define BUFFER_SIZE 1024
#define SIG_LENGTH 64

//Performance
// how much to increase our array when dynamically resizing
#define ARRAY_EXPANSION_MULTIPLE 2 
#define CHAR_ERR_MSG_ARRAY 256
#endif // COMMON_DEFS_H
