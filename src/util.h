#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Reverses data in-place.
 *
 * @param[in,out] buf
 *   Buffer which contents needs to be reversed.
 * @param[in] len
 *   Length of the buffer in bytes.
 */
static inline void reverse_inplace(uint8_t *buf, size_t len) {
    uint8_t *p_end = buf + len - 1;
    for (size_t i = 0; i < len >> 1; ++i) {
        uint8_t tmp = *buf;
        *buf++ = *p_end;
        *p_end-- = tmp;
    }
}

/**
 * Copies bytes from one buffer to another in reverse order.
 *
 * @param[out] dst
 *   Destination buffer.
 * @param[in] src
 *   Source buffer.
 * @param len
 *   Number of bytes to copy.
 */
static inline void reverse_copy(uint8_t *dst, const uint8_t *src, size_t len) {
    const uint8_t *p_src = src + len - 1;
    for (size_t i = 0; i < len; ++i) {
        *dst++ = *p_src--;
    }
}

/**
 * Wrapper for explicit_bzero() supperssing "implicit function declaration" warning.
 *
 * @param[out] dest
 *   Buffer that needs to be zeroized.
 * @param[in] len
 *   Size of the buffer in bytes.
 */
static inline void call_explicit_bzero(void *dest, size_t len) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    explicit_bzero(dest, len);
#pragma GCC diagnostic pop
}
