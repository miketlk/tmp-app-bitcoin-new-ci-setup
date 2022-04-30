#include <string.h>   // memmove, memset
#include "wif.h"
#include "base58.h"

#ifndef SKIP_FOR_CMOCKA
#include "cx.h"
#else
// This function is defined in test module
extern size_t cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len);
#endif

/**
 * Constants used by WIF decoder
 */
#define WIF_PRIVATE_KEY_LEN     32
#define WIF_CHECKSUM_LEN        4
#define WIF_VERSION_MAINNET     0x80
#define WIF_VERSION_TESTNET     0xEF
#define WIF_COMPRESSION_SUFFIX  0x01

bool wif_decode_private_key(const char* key_str,
                            size_t key_str_len,
                            uint8_t *out,
                            size_t out_len,
                            uint32_t *p_flags) {
    if(!key_str ||
       key_str_len < WIF_PRIVATE_KEY_LENGTH_MIN ||
       key_str_len > WIF_PRIVATE_KEY_LENGTH_MAX) {
        return false;
    }

    bool success = true;
    uint32_t flags = 0;

    // Decode Base58, check key length and handle compression byte
    uint8_t decoded[1 + WIF_PRIVATE_KEY_LEN + 1 + WIF_CHECKSUM_LEN];
    int decoded_len = base58_decode(key_str, key_str_len, decoded, sizeof(decoded));
    if(decoded_len == sizeof(decoded)) {
        const uint8_t *p_compression = decoded + decoded_len - WIF_CHECKSUM_LEN - 1;
        if(*p_compression == WIF_COMPRESSION_SUFFIX) {
            flags |= WIF_FLAG_COMPRESSION;
        } else {
            success = false;
        }
    } else if (decoded_len != (sizeof(decoded) - 1)) {
        success = false;
    }

    // Handle version byte
    if(success) {
        if(decoded[0] == WIF_VERSION_MAINNET) {
            flags |= WIF_FLAG_MAINNET;
        } else if(decoded[0] == WIF_VERSION_TESTNET) {
            flags |= WIF_FLAG_TESTNET;
        } else {
            success = false;
        }
    }

    // Checksum verification
    if(success) {
        uint8_t hash[32];
        cx_hash_sha256(decoded, decoded_len - WIF_CHECKSUM_LEN, hash, sizeof(hash));
        cx_hash_sha256(hash, sizeof(hash), hash, sizeof(hash));
        const uint8_t *p_checksum_in = decoded + decoded_len - WIF_CHECKSUM_LEN;
        if(memcmp(hash, p_checksum_in, sizeof(uint8_t) * WIF_CHECKSUM_LEN) != 0) {
            success = false;
        }
    }

    // Output decoded key and flags
    if(success) {
        if(out) {
            if(out_len >= WIF_PRIVATE_KEY_LEN) {
                memcpy(out, decoded + 1, sizeof(uint8_t) * WIF_PRIVATE_KEY_LEN);
            } else {
                success = false;
            }
        }
        if(p_flags) {
            *p_flags = flags;
        }
    }

    // Zeroise temporary buffer ant return
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
    explicit_bzero(decoded, sizeof(decoded));
#pragma GCC diagnostic pop
    return success;
}
