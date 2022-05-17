#pragma once

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

typedef struct {
    uint32_t p2pkh_version;
    uint32_t p2sh_version;
    uint32_t prefix_confidential;
    const char* segwit_prefix; // NULL if no segwit prefix
    const char* segwit_prefix_confidential; // NULL if no segwit prefix
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
void liquid_get_blinding_key(const uint8_t *script,
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
    