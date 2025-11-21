#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h>
#include <stdint.h>

/**
 * Securely wipe memory
 * Uses volatile pointer to prevent compiler optimization
 */
static inline void secure_wipe(void* ptr, size_t len) {
    if (!ptr || len == 0) {
        return;
    }

    volatile uint8_t* vptr = (volatile uint8_t*)ptr;
    while (len--) {
        *vptr++ = 0;
    }
}

/**
 * Securely allocate memory
 * Memory is locked to prevent swapping and zeroed
 */
void* secure_alloc(size_t size);

/**
 * Securely free memory
 * Memory is wiped before freeing
 */
void secure_free(void* ptr, size_t size);

#endif /* SECURE_MEMORY_H */
