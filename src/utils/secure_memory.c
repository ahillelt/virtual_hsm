#include "secure_memory.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void* secure_alloc(size_t size) {
    if (size == 0) {
        return NULL;
    }

    /* Allocate memory */
    void* ptr = malloc(size);
    if (!ptr) {
        return NULL;
    }

    /* Zero the memory */
    memset(ptr, 0, size);

    /* Try to lock memory to prevent swapping */
    /* Ignore errors as this may require privileges */
    mlock(ptr, size);

    return ptr;
}

void secure_free(void* ptr, size_t size) {
    if (!ptr) {
        return;
    }

    /* Wipe memory */
    secure_wipe(ptr, size);

    /* Unlock memory */
    munlock(ptr, size);

    /* Free memory */
    free(ptr);
}
