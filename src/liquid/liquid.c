#include <stdint.h>
#include <string.h>
#include "crypto.h"
#include "liquid.h"
#include "liquid_addr.h"
#include "../common/wif.h"
#include "../common/script.h"
#include "tests.h"

#ifdef HAVE_LIQUID

/// RIPEMD160 message digest size
#define HASH160_LEN 20

#ifndef SKIP_FOR_CMOCKA

/// Network configuration defined at build time from Makefile variables
const liquid_network_config_t G_liquid_network_config =  {
    .p2pkh_version = COIN_P2PKH_VERSION,
    .p2sh_version = COIN_P2SH_VERSION,
    .prefix_confidential = COIN_PREFIX_CONFIDENTIAL,
    .segwit_prefix = COIN_NATIVE_SEGWIT_PREFIX,
    .segwit_prefix_confidential = COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL
};

#endif // SKIP_FOR_CMOCKA

// ELIP 150 tag for computing the hashed tag function used for tweaking public keys
static const uint8_t ELIP150_hash_tag[] =
    {'C', 'T', '-', 'B', 'l', 'i', 'n', 'd', 'i', 'n', 'g', '-', 'K', 'e', 'y', '/', '1', '.', '0'};

#ifndef SKIP_FOR_CMOCKA

bool liquid_get_master_blinding_key(uint8_t mbk[static 32]) {
    return crypto_derive_symmetric_key(SLIP77_LABEL, SLIP77_LABEL_LEN, mbk);
}

bool liquid_get_blinding_key(const uint8_t mbk[static 32],
                             const uint8_t *script,
                             size_t script_length,
                             uint8_t blinding_key[static 32]) {
    cx_hmac_sha256_t hmac;
    return ( CX_OK == cx_hmac_sha256_init_no_throw(&hmac, mbk, 32) &&
             CX_OK == cx_hmac_no_throw( (cx_hmac_t*)&hmac,
                                        CX_LAST,
                                        script,
                                        script_length,
                                        blinding_key,
                                        32) );
}

bool liquid_get_blinding_public_key(const uint8_t mbk[static 32],
                                    const uint8_t *script,
                                    size_t script_length,
                                    uint8_t *pubkey,
                                    size_t *p_pubkey_len,
                                    liquid_pubkey_compression_t pubkey_compression) {
    if(!mbk || !script || !pubkey || !p_pubkey_len ||
       (LIQUID_PUBKEY_COMPRESSED == pubkey_compression && *p_pubkey_len < 33) ||
       (LIQUID_PUBKEY_UNCOMPRESSED == pubkey_compression && *p_pubkey_len < 65) ) {
        return false;
    }

    uint8_t raw_privkey[32];
    cx_ecfp_private_key_t privkey_inst = {0};
    cx_ecfp_public_key_t pubkey_inst = {0};

    // Get raw blinding key
    bool ok = liquid_get_blinding_key(mbk, script, script_length, raw_privkey);

    // New private key instance from raw private key
    ok = ok && CX_OK == cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1,
                                                          raw_privkey,
                                                          sizeof(raw_privkey),
                                                          &privkey_inst);

    // Generate corresponding public key
    ok = ok && CX_OK == cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &pubkey_inst, &privkey_inst, 1);

    // Save produced public key in compressed or uncompressed format
    if (ok) {
        if(LIQUID_PUBKEY_COMPRESSED == pubkey_compression) {
            pubkey[0] = ((pubkey_inst.W[64] & 1) ? 0x03 : 0x02);
            memcpy(pubkey + 1, pubkey_inst.W + 1, 32);
            *p_pubkey_len = 33;
        } else if(LIQUID_PUBKEY_UNCOMPRESSED == pubkey_compression) {
            memcpy(pubkey, pubkey_inst.W, 65);
            *p_pubkey_len = 65;
        } else {
            ok = false;
        }
    }

    // Zeroize sensitive data
    explicit_bzero(&raw_privkey, sizeof(raw_privkey));
    explicit_bzero(&privkey_inst, sizeof(privkey_inst));
    explicit_bzero(&pubkey_inst, sizeof(pubkey_inst));

    return ok;
}

bool liquid_derive_blinding_public_key_elip150(const uint8_t bare_pubkey[static 33],
                                               const uint8_t *script,
                                               size_t script_length,
                                               uint8_t out_pubkey[static 33]) {
    if(!bare_pubkey || !script || !out_pubkey ||
       !(0x02 == bare_pubkey[0] || 0x03 == bare_pubkey[0])) {
        return false;
    }

    bool ok = true;
    uint8_t hash_bytes[SHA256_LEN];
    {
        // Calculate tagget hash
        cx_sha256_t hash_context;
        crypto_tr_tagged_hash_init(&hash_context, ELIP150_hash_tag, sizeof(ELIP150_hash_tag));
        crypto_hash_update(&hash_context.header, bare_pubkey, 33);
        crypto_hash_update_varint(&hash_context.header, script_length);
        crypto_hash_update(&hash_context.header, script, script_length);
        crypto_hash_digest(&hash_context.header, hash_bytes, sizeof(hash_bytes));
        explicit_bzero(&hash_context, sizeof(hash_context));
    }

    cx_ecfp_public_key_t tweak_pubkey_inst;
    {
        cx_ecfp_private_key_t tweak_privkey_inst;

        // New private key instance from 256-bit hash scalar
        ok = ok && CX_OK == cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1,
                                                              hash_bytes,
                                                              sizeof(hash_bytes),
                                                              &tweak_privkey_inst);

        // Generate corresponding public key (tweak point)
        ok = ok && CX_OK == cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1,
                                                           &tweak_pubkey_inst,
                                                           &tweak_privkey_inst,
                                                           1);

        explicit_bzero(&tweak_privkey_inst, sizeof(tweak_privkey_inst));
    }

    {
        uint8_t point[65];

        // Uncompress bare public key
        ok = ok && 0 == crypto_get_uncompressed_pubkey(bare_pubkey, point);
        // Add tweak point
        ok = ok && CX_OK == cx_ecfp_add_point_no_throw(CX_CURVE_SECP256K1,
                                                       point,
                                                       point,
                                                       tweak_pubkey_inst.W);
        // Compress and output resulting public key
        if (ok) {
            out_pubkey[0] = ((point[64] & 1) ? 0x03 : 0x02);
            memcpy(out_pubkey + 1, point + 1, 32);
        }
        explicit_bzero(point, sizeof(point));
    }

    explicit_bzero(hash_bytes, sizeof(hash_bytes));
    explicit_bzero(&tweak_pubkey_inst, sizeof(tweak_pubkey_inst));

    return ok;
}

#endif

int liquid_get_script_confidential_address(const uint8_t *script,
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

bool liquid_policy_unwrap_ct(const policy_node_t **p_policy,
                             bool *p_is_blinded,
                             uint8_t *blinding_key,
                             size_t blinding_key_len,
                             liquid_blinding_key_type_t *p_key_type) {
    if(!p_policy || !(*p_policy) || !p_is_blinded || !blinding_key || !p_key_type) {
        return false;
    }

    *p_is_blinded = false;
    *p_key_type = BLINDING_KEY_UNKNOWN;

    if((*p_policy)->type == TOKEN_CT) {
        *p_is_blinded = true;
        const policy_node_ct_t *root = (const policy_node_ct_t*)*p_policy;
        if(root->mbk_script && root->script) {
            if (root->mbk_script->type == TOKEN_SLIP77) {
                *p_key_type = BLINDING_KEY_SLIP77;
                const policy_node_blinding_privkey_t *slip77 =
                    (const policy_node_blinding_privkey_t*)root->mbk_script;

                if (sizeof(slip77->privkey) <= blinding_key_len) {
                    memcpy(blinding_key, slip77->privkey, sizeof(slip77->privkey));
                    *p_policy = root->script;
                    return true;
                }
            }
        }
        return false;
    }
    return true;
}

#ifdef IMPLEMENT_ON_DEVICE_TESTS
#include "liquid_tests.h"
#endif

#endif // HAVE_LIQUID
