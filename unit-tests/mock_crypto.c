#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/wif.h"
#include "sha-256.h"

/**
 * Mock implementation, not to be used outside test environment.
 */
int __attribute__((weak)) cx_hash_sha256(const uint8_t *in,
                                         size_t len,
                                         uint8_t *out,
                                         size_t out_len) {
    if(out_len >= SIZE_OF_SHA_256_HASH) {
        calc_sha_256(out, in, len);
    } else {
        memset(out, 0, out_len);
    }
    return 0;
}

#ifdef __clang__
/**
 * Mock implementation, not to be used outside test environment.
 */
void __attribute__((weak)) explicit_bzero(void *ptr, size_t len) {
    memset(ptr, 0, len);
    *(volatile uint8_t*)ptr = *(volatile uint8_t*)ptr;
}
#endif
