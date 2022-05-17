#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

/**
 * Flags used by WIF private key decoder
 */
#define WIF_FLAG_MAINNET     (1 << 0)  // Key is to be used on mainnet
#define WIF_FLAG_TESTNET     (1 << 1)  // Key is to be used on testnet
#define WIF_FLAG_COMPRESSION (1 << 2)  // Key corresponds to a compressed public key

/**
 * Minimum and maximum length of private key in WIF Base58 format
 */
#define WIF_PRIVATE_KEY_LENGTH_MIN 51
#define WIF_PRIVATE_KEY_LENGTH_MAX 52

/**
 * Decodes private key stored in WIF format.
 *
 * @param[in] key_str
 *   Pointer to input buffer containing private key in WIF format.
 * @param[in] key_str_len
 *   Length of input data.
 * @param[out] out
 *   Pointer to the output buffer receiving decoded private key, can be NULL if not needed.
 * @param[in] out_len
 *   The length of the output buffer.
 * @param[out] p_flags
 *   Pointer to variable receiving flags, can be NULL if not needed.
 *
 * @return size of decoded private key in bytes, or -1 in case of error.
 */
int wif_decode_private_key(const char* key_str,
                           size_t key_str_len,
                           uint8_t *out,
                           size_t out_len,
                           uint32_t *p_flags);


/**
 * Convenience wrapper for wif_decode_private_key verifying WIF container.
 *
 * @param[in] key_str
 *   Pointer to input buffer containing private key in WIF format.
 * @param[in] key_str_len
 *   Length of input data.
 * @param[out] p_flags
 *   Pointer to variable receiving flags, can be NULL if not needed.
 *
 * @return true on success, false in case of error.
 */
static inline bool wif_verify_private_key(const char* key_str,
                                          size_t key_str_len,
                                          uint32_t *p_flags) {
    return wif_decode_private_key(key_str, key_str_len, NULL, 0, p_flags) > 0;
}
