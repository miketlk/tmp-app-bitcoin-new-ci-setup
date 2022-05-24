#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "../common/wallet.h"

/**
 * The label used to derive the master blinding key according to SLIP-0077
 */
#define SLIP77_LABEL "\0SLIP-0077"
#define SLIP77_LABEL_LEN \
    (sizeof(SLIP77_LABEL) - 1)  // sizeof counts the terminating 0

/**
 * Maximum length of the 'script' field of the LIQUID_GET_BLINDING_KEY command, that is currently
 * supported
 */
#define GET_BLINDING_KEY_MAX_SCRIPT_LEN 252

/**
 * Type of blinding key derivation
 */
typedef enum {
    BLINDING_KEY_UNKNOWN = 0, // Unknown derivation type
    BLINDING_KEY_SLIP77       // SLIP-0077
} liquid_blinding_key_type_t;

/**
 * Compression trait of a public key
 */
typedef enum {
    LIQUID_PUBKEY_UNCOMPRESSED = 0, // Public key is compressed, 33 bytes
    LIQUID_PUBKEY_COMPRESSED = 1    // Public key is uncompressed, 65 bytes
} liquid_pubkey_compression_t;

typedef struct {
    uint32_t p2pkh_version;
    uint32_t p2sh_version;
    uint32_t prefix_confidential;
    char segwit_prefix[MAX_SEGWIT_PREFIX_LENGTH+1];
    char segwit_prefix_confidential[MAX_SEGWIT_PREFIX_LENGTH+1];
} liquid_network_config_t;

#if defined(HAVE_LIQUID) && !defined(SKIP_FOR_CMOCKA)
// Network configuration defined at build time from Makefile variables
extern const liquid_network_config_t G_liquid_network_config;
#endif

/**
 * Derives master blinding key from seed according to SLIP-0077.
 *
 * @param[out] mbk
 *   Pointer to a 32-byte output buffer that will contain the generated key.
 */
void liquid_get_master_blinding_key(uint8_t mbk[static 32]);


/**
 * Derives blinding key from given script.
 *
 * @param[in] mbk
 *   Pointer to master blinding key.
 *
 * @param[in] script
 *   Script used to derive the key.
 *
 * @param[in] script_length
 *   Length of the script.
 *
 * @param[out] blinding_key
 *   Pointer to a 32-byte output buffer that will contain the generated key.
 *
 */
void liquid_get_blinding_key(const uint8_t mbk[static 32],
                             const uint8_t *script,
                             size_t script_length,
                             uint8_t blinding_key[static 32]);


/**
 * Returns a prefix for confidential SegWit address from a given SegWit address prefix.
 *
 * @param[in] segwit_prefix
 *   SegWit address prefix used for look-up.
 *
 * @return Prefix for a confidential SegWit address or NULL if unsuccessfull.
 */
const char* liquid_confidential_segwit_prefix(const char* segwit_prefix);

// TODO: describe
int liquid_get_script_confidential_address(const uint8_t script[],
                                           size_t script_len,
                                           const liquid_network_config_t *network_config,
                                           const uint8_t *pub_key,
                                           size_t pub_key_len,
                                           char *out,
                                           size_t out_len);

/**
 * Unwraps blinded tag and extracts master blinding key from wallet policy.
 *
 * @param[in,out] p_policy
 *   Pointer to a modifiable variable holding pointer to root policy node.
 * @param[out] p_is_blinded
 *   Pointer to a boolean variable which is set to true if the wallet policy has blinded tag.
 * @param blinding_key
 *   Pointer to buffer receiving extracted blinding key.
 * @param blinding_key_len
 *   The length of the ``blinding_key`` buffer.
 * @param p_wif_flags
 *   Pointer to variable receiving flags related to extracted blinding key, a combination of
 *   WIF_FLAG_* constants. Can be NULL if not needed.
 * @param p_key_type
 *   Pointer to variable receiving type of extracted blinding key.
 *
 * @return true on success, false in case of error.
 */
bool liquid_policy_unwrap_blinded(const policy_node_t **p_policy,
                                  bool *p_is_blinded,
                                  uint8_t *blinding_key,
                                  size_t blinding_key_len,
                                  uint32_t *p_wif_flags,
                                  liquid_blinding_key_type_t *p_key_type);


// TODO: describe
bool liquid_get_blinding_public_key(const uint8_t mbk[static 32],
                                    const uint8_t *script,
                                    size_t script_length,
                                    uint8_t *pubkey,
                                    size_t *p_pubkey_len,
                                    liquid_pubkey_compression_t pubkey_compression);