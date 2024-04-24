#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include "decorators.h"

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
 * Size of generator in bytes
 */
#define LIQUID_GENERATOR_LEN 65

/**
 * Size of commitment in bytes
 */
#define LIQUID_COMMITMENT_LEN 33

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
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT bool liquid_get_master_blinding_key(uint8_t mbk[static 32]);


/**
 * Derives blinding key from given script.
 *
 * @param[in] mbk
 *   Pointer to master blinding key.
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] blinding_key
 *   Pointer to a 32-byte output buffer that will contain the generated key.
 *
 * @return true - OK, false - error
 */
WARN_UNUSED_RESULT bool liquid_get_blinding_key(const uint8_t mbk[static 32],
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

/**
 * Returns a confidential address from given script and public key.
 *
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[in] network_config
 *   Network configuration.
 * @param[out] pubkey
 *   Public key.
 * @param[out] p_pubkey_len
 *   Length of the public key in bytes: 33 or 65.
 * @param[out] out
 *   Output buffer where produced address is placed.
 * @param[in] out_len
 *   Maximum length to write for the output buffer.
 *
 * @return size of produced address in bytes, or -1 in case of error.
 */
WARN_UNUSED_RESULT int liquid_get_script_confidential_address(const uint8_t *script,
                                                              size_t script_len,
                                                              const liquid_network_config_t *network_config,
                                                              const uint8_t *pub_key,
                                                              size_t pub_key_len,
                                                              char *out,
                                                              size_t out_len);

/**
 * Unwraps ct() tag from wallet policy.
 *
 * @param[in,out] p_policy
 *   Pointer to a modifiable variable holding pointer to root policy node.
 * @param[out] p_is_blinded
 *   Pointer to a boolean variable which is set to true if the wallet policy has ct() tag.
 *
 * @return true on success, false in case of error.
 */
WARN_UNUSED_RESULT bool liquid_policy_unwrap_ct(const policy_node_t **p_policy, bool *p_is_blinded);


/**
 * Derives blinding public key from the given policy with `ct` descriptor.
 *
 * @param[in] policy
 *   Pointer to a root policy node whose outer descriptor must be `ct` and contain blinding key.
 * @param[in] script
 *   Script used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] pubkey
 *   Buffer receiving derived public key, must be not smaller than 33 bytes.
 *
 * @return true on success, false in case of error.
 */
WARN_UNUSED_RESULT bool liquid_get_blinding_public_key(const policy_node_t *policy,
                                                       const uint8_t *script,
                                                       size_t script_length,
                                                       uint8_t pubkey[static 33]);


/**
 * Derives blinding public key from given bare public key according to ELIP 150.
 *
 * @param[in] bare_pubkey
 *   Bare compressed public blinding key, 33 bytes.
 * @param[in] script
 *   Script `scriptPubKey` used to derive the key.
 * @param[in] script_length
 *   Length of the script.
 * @param[out] out_pubkey
 *   Buffer receiving derived public blinding key, must be at least 33 bytes long.
 *
 * @return true on success, false in case of error.
 */
WARN_UNUSED_RESULT bool liquid_derive_blinding_public_key_elip150(const uint8_t bare_pubkey[static 33],
                                                                  const uint8_t *script,
                                                                  size_t script_length,
                                                                  uint8_t out_pubkey[static 33]);

/**
 * Validates the blinding key in the policy ensuring that it can be accepted.
 *
 * For SLIP-0077 derivation, this function also checks if the master blinding key is ours.
 *
 * @param[in] policy
 *   Pointer to a root policy node whose outer descriptor must be `ct` and contain blinding key.
 *
 * @return true if the policy having this specific blinding key is acceptable, false otherwise.
 */
bool liquid_is_blinding_key_acceptable(const policy_node_t *policy);

/**
 * Verifies if the given master blinding key is ours.
 *
 * @param[in] mbk
 *   Master blinding key to test, exactly 32 bytes.
 *
 * @return true if the given master blinding key is ours, false otherwise
 */
bool liquid_is_master_blinding_key_ours(const uint8_t mbk[static 32]);
