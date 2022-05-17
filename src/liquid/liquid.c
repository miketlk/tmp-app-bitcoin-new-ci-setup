#include <stdint.h>
#include <string.h>
#include "crypto.h"
#include "liquid.h"
#include "liquid_addr.h"
#include "../common/script.h"

#ifdef HAVE_LIQUID

// RIPEMD160 message digest size
#define HASH160_LEN 20

#ifndef SKIP_FOR_CMOCKA

// Network configuration defined at build time from Makefile variables
const liquid_network_config_t G_liquid_network_config =  {
    .p2pkh_version = COIN_P2PKH_VERSION,
    .p2sh_version = COIN_P2SH_VERSION,
    .prefix_confidential = COIN_PREFIX_CONFIDENTIAL,
    .segwit_prefix = COIN_NATIVE_SEGWIT_PREFIX,
    .segwit_prefix_confidential = COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL
};

#endif // SKIP_FOR_CMOCKA

#ifndef SKIP_FOR_CMOCKA

void liquid_get_master_blinding_key(uint8_t mbk[static 32]) {
    crypto_derive_symmetric_key(SLIP77_LABEL, SLIP77_LABEL_LEN, mbk);
}

void liquid_get_blinding_key(const uint8_t *script,
                             size_t script_length,
                             uint8_t blinding_key[static 32]) {
    uint8_t mbk[32]; // Master blinding key
    crypto_derive_symmetric_key(SLIP77_LABEL, SLIP77_LABEL_LEN, mbk);
    cx_hmac_sha256(mbk, sizeof(mbk), script, script_length, blinding_key, 32);
}

#endif

int liquid_get_script_confidential_address(const uint8_t script[],
                                           size_t script_len,
                                           const liquid_network_config_t *network_config,
                                           const uint8_t *pub_key,
                                           size_t pub_key_len,
                                           char *out,
                                           size_t out_len) {
    if(!script || !network_config ||!pub_key || !out) {
        return -1;
    }

    int script_type = get_script_type(script, script_len);
    if(script_type < 0 || script_len < 4) {
        return -1; // invalid script
    }

    int addr_len = -1;
    switch (script_type) {
        // Legacy P2PKH scripts are not supported
        case SCRIPT_TYPE_P2SH: {
            if(script_len - 2 < HASH160_LEN) {
                return -1;
            }
            addr_len = liquid_encode_address_base58(script + 2,
                                                    HASH160_LEN,
                                                    network_config->prefix_confidential,
                                                    network_config->p2sh_version,
                                                    pub_key,
                                                    pub_key_len,
                                                    out,
                                                    out_len);
            break;
        }
        case SCRIPT_TYPE_P2WPKH:
        case SCRIPT_TYPE_P2WSH:
        case SCRIPT_TYPE_P2TR:
        case SCRIPT_TYPE_UNKNOWN_SEGWIT: {
            uint8_t prog_len = script[1];  // length of the witness program
            int version = (script[0] == 0 ? 0 : script[0] - 80); // witness program version
            if(prog_len > script_len - 2) {
                return -1;
            }
            addr_len = liquid_encode_address_segwit(script + 2,
                                                    prog_len,
                                                    network_config->segwit_prefix_confidential,
                                                    version,
                                                    pub_key,
                                                    pub_key_len,
                                                    out,
                                                    out_len);
            break;
        }
    }
    return addr_len;
}

#endif // HAVE_LIQUID