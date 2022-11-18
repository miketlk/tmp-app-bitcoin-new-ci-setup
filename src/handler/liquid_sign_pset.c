/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifdef HAVE_LIQUID

#include <stdint.h>

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/merkle.h"
#include "../common/psbt.h"
#include "../common/pset.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/varint.h"
#include "../common/write.h"

#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"

#include "lib/policy.h"
#include "lib/check_merkle_tree_sorted.h"
#include "lib/get_preimage.h"
#include "lib/get_merkleized_map.h"
#include "lib/get_merkleized_map_value.h"
#include "lib/pset_parse_rawtx.h"

#include "liquid_sign_pset.h"
#include "../liquid/liquid_proofs.h"

#include "sign_psbt/compare_wallet_script_at_path.h"
#include "sign_psbt/get_fingerprint_and_path.h"
#include "sign_psbt/is_in_out_internal.h"
#include "sign_psbt/update_hashes_with_map_value.h"

#include "../swap/swap_globals.h"

extern global_context_t *G_coin_config;

typedef enum {
    HAS_BIP32_DERIVATION = (1 << 0),
    HAS_VALUE_COMMITMENT = (1 << 1),
    HAS_VALUE_BLINDING_FACTOR = (1 << 2),
    HAS_ASSET = (1 << 3),
    HAS_ASSET_BLINDING_FACTOR = (1 << 4),
    HAS_WITNESSUTXO = (1 << 5),
    HAS_NONWITNESSUTXO = (1 << 6),
    HAS_REDEEMSCRIPT = (1 << 7),
    HAS_SIGHASH_TYPE = (1 << 8),
    HAS_PREVOUT_AMOUNT = (1 << 9),
    HAS_ASSET_COMMITMENT = (1 << 10),
    HAS_BLINDING_PUBKEY = (1 << 11),
    HAS_ECDH_PUBKEY = (1 << 12),
    HAS_BLINDER_INDEX = (1 << 13),
    HAS_ISSUE_VALUE = (1 << 14),
    HAS_ISSUE_COMMITMENT = (1 << 15),
    HAS_ISSUE_NONCE = (1 << 16),
    HAS_ISSUE_ENTROPY = (1 << 17),
    HAS_TOKEN_COMMITMENT = (1 << 18),
    HAS_TOKEN_VALUE = (1 << 19),
    HAS_ISSUE_PROOF = (1 << 20),
    HAS_TOKEN_PROOF = (1 << 21),
    HAS_VALUE = (1 << 22),
    HAS_VALUE_PROOF = (1 << 23),
    HAS_ASSET_PROOF = (1 << 24),
    HAS_ASSET_SURJECTION_PROOF = (1 << 25),
    HAS_VALUE_RANGEPROOF = (1 << 26)
} key_presence_flags_t;

/// State of input_keys_callback()
typedef struct {
    uint32_t key_presence;  ///< Flags indicating presence of keys in input scope
    uint8_t *out_pubkey;    ///< Pointer to buffer receiving public key
    size_t pubkey_size;     ///< Size of public key buffer, filled with public key size on complete
    bool error;             ///< Flag indicating error during handling of keys
} input_keys_callback_state_t;

/// State of output_keys_callback()
typedef struct {
    uint32_t key_presence;  ///< Flags indicating presence of keys in input scope
    uint8_t *out_pubkey;    ///< Pointer to buffer receiving public key
    size_t pubkey_size;     ///< Size of public key buffer, filled with public key size on complete
    bool error;             ///< Flag indicating error during handling of keys
} output_keys_callback_state_t;

// Input validation
static void process_input_map(dispatcher_context_t *dc);
static void check_input_commitments(dispatcher_context_t *dc);
static void check_input_owned(dispatcher_context_t *dc);

static void alert_external_inputs(dispatcher_context_t *dc);

// Output validation
static void verify_outputs_init(dispatcher_context_t *dc);
static void process_output_map(dispatcher_context_t *dc);
static void check_output_commitments(dispatcher_context_t *dc);
static void check_output_owned(dispatcher_context_t *dc);
static void output_validate_external(dispatcher_context_t *dc);
static void output_next(dispatcher_context_t *dc);

// User confirmation (all)
static void confirm_transaction(dispatcher_context_t *dc);

// Signing process (all)
static void sign_init(dispatcher_context_t *dc);
static void compute_segwit_hashes(dispatcher_context_t *dc);
static void sign_process_input_map(dispatcher_context_t *dc);

// Legacy sighash computation (P2PKH and P2SH)
static void sign_legacy(dispatcher_context_t *dc);
static void sign_legacy_compute_sighash(dispatcher_context_t *dc);

// Segwit sighash computation (P2WPKH, P2WSH and P2TR)
static void sign_segwit(dispatcher_context_t *dc);
static void sign_segwit_v0(dispatcher_context_t *dc);
static void sign_segwit_v1(dispatcher_context_t *dc);

// Sign input and yield result
static void sign_sighash_ecdsa(dispatcher_context_t *dc);
static void sign_sighash_schnorr(dispatcher_context_t *dc);

// End point and return
static void finalize(dispatcher_context_t *dc);

/* BIP0341 tags for computing the tagged hashes when computing he sighash */
static const uint8_t BIP0341_sighash_tag[] = {'T', 'a', 'p', 'S', 'i', 'g', 'h', 'a', 's', 'h'};



/*
Current assumptions during signing:
  1) exactly one of the keys in the wallet is internal (enforce during wallet registration)
  2) all the keys in the wallet have a wildcard (that is, they end with '**'), with at most
     4 derivation steps before it.

Assumption 2 simplifies the handling of pubkeys (and their paths) used for signing,
as all the internal keys will have a path that ends with /change/address_index (BIP44-style).

It would be possible to generalize to more complex scripts, but it makes it more difficult to detect
the right paths to identify internal inputs/outputs.
*/

// HELPER FUNCTIONS

/**
 * Tests proprietary key stored in buffer against reference key given as byte array.
 * It is assumed that top-level <keytype> (0xfd) is already taken from the buffer before this
 * function is called and <identifierlen> would be the first value available to read.
 *
 * Buffer position is left unchanged after return.
 */
static bool test_proprietary_key(buffer_t *buffer, const uint8_t *ref_key) {
    // Offsets within proprietary key byte array, assuming length and types are single-byte.
    enum {OFF_KEYTYPE = 0, OFF_ID_LEN, OFF_ID };

    // Sanity check
    if(!buffer || !ref_key || ref_key[OFF_KEYTYPE] != 0xfc ||
       ref_key[OFF_ID_LEN] > PSBT_PROPRIETARY_ID_MAX_LENGTH ||
       ref_key[OFF_ID + ref_key[OFF_ID_LEN]] > 0xfc) {
        return false;
    }

    bool success = true;
    buffer_snapshot_t snapshot = buffer_snapshot(buffer);

    uint8_t id_len;
    // Only single-byte type and length values are supported
    if(buffer_read_u8(buffer, &id_len) && id_len == ref_key[OFF_ID_LEN]) {
        uint8_t curr_byte;
        const uint8_t *p_ref_key = ref_key + OFF_ID;
        // Compare all bytes of identifier + a single byte of sub-keytype
        for(int i = 0; i < id_len + 1; ++i, p_ref_key++) {
            if(!buffer_read_u8(buffer, &curr_byte) || curr_byte != *p_ref_key) {
                success = false;
                break;
            }
        }
        // Assure there is no more bytes left in buffer
        success = success && !buffer_can_read(buffer, 1);
    } else {
        success = false;
    }

    buffer_restore(buffer, snapshot);
    return success;
}

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void input_keys_callback(input_keys_callback_state_t *state, buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t keytype;
        buffer_read_u8(data, &keytype);
        if (keytype == PSBT_IN_WITNESS_UTXO) {
            state->key_presence |= HAS_WITNESSUTXO;
        } else if (keytype == PSBT_IN_NON_WITNESS_UTXO) {
            state->key_presence |= HAS_NONWITNESSUTXO;
        } else if (keytype == PSBT_IN_REDEEM_SCRIPT) {
            state->key_presence |= HAS_REDEEMSCRIPT;
        } else if (keytype == PSBT_IN_SIGHASH_TYPE) {
            state->key_presence |= HAS_SIGHASH_TYPE;
        } else if ((keytype == PSBT_IN_BIP32_DERIVATION ||
                    keytype == PSBT_IN_TAP_BIP32_DERIVATION) &&
                    !(state->key_presence & HAS_BIP32_DERIVATION)) {
            // The first time that we encounter a PSBT_IN_BIP32_DERIVATION or
            // PSBT_IN_TAP_BIP32_DERIVATION (handled below) key, we store the pubkey. Since we only
            // use this to identify the change and address_index, it does not matter which of the
            // keys we use here (if there are multiple), as per the assumptions above.
            state->key_presence |= HAS_BIP32_DERIVATION;

            // Check if storage of public key is requested
            if(state->out_pubkey && state->pubkey_size) {
                // x-only pubkeys for taproot, normal compressed pubkeys otherwise
                size_t key_len = (keytype == PSBT_IN_TAP_BIP32_DERIVATION ? 32 : 33);

                if(state->pubkey_size >= key_len) {
                    if (!buffer_read_bytes(data,
                                           state->out_pubkey,
                                           key_len)  // read compressed pubkey or x-only pubkey
                        || buffer_can_read(data, 1)  // ...but should not be able to read more
                    ) {
                        state->error = true;
                    } else {
                        state->pubkey_size = key_len;
                    }
                } else {
                    state->error = true;
                }
            }
        } else if (keytype == PSBT_IN_PROPRIETARY) {
            if (test_proprietary_key(data, PSBT_ELEMENTS_IN_EXPLICIT_VALUE)) {
                state->key_presence |= HAS_VALUE;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_IN_EXPLICIT_ASSET)) {
                state->key_presence |= HAS_ASSET;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_IN_ISSUANCE_VALUE)) {
                state->key_presence |= HAS_ISSUE_VALUE;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT)) {
                state->key_presence |= HAS_ISSUE_COMMITMENT;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF)) {
                state->key_presence |= HAS_ISSUE_PROOF;
            } else if (test_proprietary_key(data,
                                            PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT)) {
                state->key_presence |= HAS_TOKEN_VALUE;
            } else if (test_proprietary_key(data,
                                            PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT)) {
                state->key_presence |= HAS_TOKEN_COMMITMENT;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE)) {
                state->key_presence |= HAS_ISSUE_NONCE;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY)) {
                state->key_presence |= HAS_ISSUE_ENTROPY;
            } else if (test_proprietary_key(data,
                                            PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF)) {
                state->key_presence |= HAS_TOKEN_PROOF;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_IN_VALUE_PROOF)) {
                state->key_presence |= HAS_VALUE_PROOF;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_IN_ASSET_PROOF)) {
                state->key_presence |= HAS_ASSET_PROOF;
            }
        }
    }
}

/**
 * Callback to process all the keys of the current input map.
 * Keeps track if the current input has a witness_utxo and/or a redeemScript.
 */
static void output_keys_callback(output_keys_callback_state_t *state, buffer_t *data) {
    size_t data_len = data->size - data->offset;
    if (data_len >= 1) {
        uint8_t keytype;
        buffer_read_u8(data, &keytype);

        if ((keytype == PSBT_OUT_BIP32_DERIVATION || keytype == PSBT_OUT_TAP_BIP32_DERIVATION) &&
            !(state->key_presence & HAS_BIP32_DERIVATION)) {
            // The first time that we encounter a PSBT_OUT_BIP32_DERIVATION or
            // PSBT_OUT_TAP_BIP32_DERIVATION key, we store the pubkey.
            state->key_presence |= HAS_BIP32_DERIVATION;

            // Check if storage of public key is requested
            if(state->out_pubkey && state->pubkey_size) {
                // x-only pubkeys for taproot, normal compressed pubkeys otherwise
                size_t key_len = (keytype == PSBT_IN_TAP_BIP32_DERIVATION ? 32 : 33);

                if(state->pubkey_size >= key_len) {
                    if (!buffer_read_bytes(data,
                                           state->out_pubkey,
                                           key_len)  // read compressed pubkey or x-only pubkey
                        || buffer_can_read(data, 1)  // ...but should not be able to read more
                    ) {
                        state->error = true;
                    } else {
                        state->pubkey_size = key_len;
                    }
                } else {
                    state->error = true;
                }
            }
        } else if (keytype == PSBT_OUT_AMOUNT) {
            state->key_presence |= HAS_VALUE;
        } else if (keytype == PSBT_IN_PROPRIETARY) {
            if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_VALUE_COMMITMENT)) {
                state->key_presence |= HAS_VALUE_COMMITMENT;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_ASSET)) {
                state->key_presence |= HAS_ASSET;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_ASSET_COMMITMENT)) {
                state->key_presence |= HAS_ASSET_COMMITMENT;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF)) {
                state->key_presence |= HAS_VALUE_RANGEPROOF;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF)) {
                state->key_presence |= HAS_ASSET_SURJECTION_PROOF;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_BLINDING_PUBKEY)) {
                state->key_presence |= HAS_BLINDING_PUBKEY;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_ECDH_PUBKEY)) {
                state->key_presence |= HAS_ECDH_PUBKEY;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_BLINDER_INDEX)) {
                state->key_presence |= HAS_BLINDER_INDEX;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF)) {
                state->key_presence |= HAS_VALUE_PROOF;
            } else if (test_proprietary_key(data, PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF)) {
                state->key_presence |= HAS_ASSET_PROOF;
            }
        }
    }
}

// Updates the hash_context with the network serialization of all the outputs
// returns -1 on error. 0 on success.
static int hash_output(dispatcher_context_t *dc,
                       int output_index,
                       cx_hash_t *hash_context,
                       cx_hash_t *rangeproof_hash_context) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    // get this output's map
    merkleized_map_commitment_t ith_map;
    uint32_t key_presence = 0;
    int res;

    // get output's merkelized map
    {
        output_keys_callback_state_t callback_state = (output_keys_callback_state_t) { 0 };
        res = call_get_merkleized_map_with_callback(
            dc,
            state->outputs_root,
            state->n_outputs,
            output_index,
            make_callback(&callback_state, (dispatcher_callback_t) output_keys_callback),
            &ith_map);
        if (res < 0 || callback_state.error) {
            return -1;
        }
        key_presence = callback_state.key_presence;
    }

    if (hash_context) {
        // hash asset or asset commitment
        if (key_presence & HAS_ASSET_COMMITMENT) {
            uint8_t commitment[33];
            if (sizeof(commitment) !=
                call_get_merkleized_map_value(dc,
                                            &ith_map,
                                            PSBT_ELEMENTS_OUT_ASSET_COMMITMENT,
                                            sizeof(PSBT_ELEMENTS_OUT_ASSET_COMMITMENT),
                                            commitment,
                                            sizeof(commitment))) {
                return -1;
            }
            crypto_hash_update(hash_context, commitment, sizeof(commitment));
        } else if (key_presence & HAS_ASSET) {
            uint8_t asset[32];
            if (sizeof(asset) !=
                call_get_merkleized_map_value(dc,
                                            &ith_map,
                                            PSBT_ELEMENTS_OUT_ASSET,
                                            sizeof(PSBT_ELEMENTS_OUT_ASSET),
                                            asset,
                                            sizeof(asset))) {
                return -1;
            }
            crypto_hash_update_u8(hash_context, 0x01);
            crypto_hash_update(hash_context, asset, sizeof(asset));
        } else {
            PRINTF("No asset nor asset commitment provided for output %i", output_index);
            return -1;
        }

        // hash amount or value commitment
        if (key_presence & HAS_VALUE_COMMITMENT) {
            uint8_t commitment[33];
            if (sizeof(commitment) !=
                call_get_merkleized_map_value(dc,
                                            &ith_map,
                                            PSBT_ELEMENTS_OUT_VALUE_COMMITMENT,
                                            sizeof(PSBT_ELEMENTS_OUT_VALUE_COMMITMENT),
                                            commitment,
                                            sizeof(commitment))) {
                return -1;
            }
            crypto_hash_update(hash_context, commitment, sizeof(commitment));
        } else if (key_presence & HAS_VALUE) {
            uint8_t value_raw[8];
            if (sizeof(value_raw) !=
                call_get_merkleized_map_value(dc,
                                            &ith_map,
                                            (uint8_t[]){PSBT_OUT_AMOUNT},
                                            1,
                                            value_raw,
                                            sizeof(value_raw))) {
                return -1;
            }
            crypto_hash_update_u8(hash_context, 0x01);
            for(int i = 7; i >= 0; --i) {
                // Value is serialized as big endian
                crypto_hash_update_u8(hash_context, value_raw[i]);
            }
        } else {
            PRINTF("No value commitment nor amount provided for output %i", output_index);
            return -1;
        }

        // hash ephemeral ECDH pubkey
        if (key_presence & HAS_ECDH_PUBKEY) {
            uint8_t ecdh_pubkey[33];
            if (sizeof(ecdh_pubkey) !=
                call_get_merkleized_map_value(dc,
                                            &ith_map,
                                            PSBT_ELEMENTS_OUT_ECDH_PUBKEY,
                                            sizeof(PSBT_ELEMENTS_OUT_ECDH_PUBKEY),
                                            ecdh_pubkey,
                                            sizeof(ecdh_pubkey))) {
                return -1;
            }
            crypto_hash_update(hash_context, ecdh_pubkey, sizeof(ecdh_pubkey));
        } else {
            crypto_hash_update_u8(hash_context, 0x00);
        }

        // hash scriptPubKey
        {
            uint8_t out_script[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
            int out_script_len = call_get_merkleized_map_value(dc,
                                                            &ith_map,
                                                            (uint8_t[]){PSBT_OUT_SCRIPT},
                                                            1,
                                                            out_script,
                                                            sizeof(out_script));
            if (out_script_len == -1) {
                return -1;
            }
            crypto_hash_update_varint(hash_context, out_script_len);
            crypto_hash_update(hash_context, out_script, out_script_len);
        }
    }

    if (rangeproof_hash_context) {
        static const uint32_t witness_mask = HAS_VALUE_RANGEPROOF | HAS_ASSET_SURJECTION_PROOF;
        if ((key_presence & witness_mask) == witness_mask) { // Output has witness
            // update hash with range proof
            res = update_hashes_with_map_value(dc,
                                               &ith_map,
                                               PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF,
                                               sizeof(PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF),
                                               NULL,
                                               rangeproof_hash_context);
            if (res < 0) {
                PRINTF("Error fetching range proof\n");
                return -1;
            }

            // update hash with surjection proof
            res = update_hashes_with_map_value(dc,
                                               &ith_map,
                                               PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF,
                                               sizeof(PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF),
                                               NULL,
                                               rangeproof_hash_context);
            if (res < 0) {
                PRINTF("Error fetching surjection proof\n");
                return -1;
            }
        } else if ((key_presence & witness_mask) == 0) { // No output witness
            crypto_hash_update_zeros(rangeproof_hash_context, 2);
        } else { // Incomplete witness
            PRINTF("Unsupported output witness configuration\n");
            return -1;
        }
    }

    return 0;
}

// Updates the hash_context with the network serialization of all the outputs
// returns -1 on error. 0 on success.
static int hash_outputs(dispatcher_context_t *dc,
                        cx_hash_t *hash_context,
                        cx_hash_t *rangeproof_hash_context) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    for (unsigned int i = 0; i < state->n_outputs; i++) {
        int res = hash_output(dc, i, hash_context, rangeproof_hash_context);
        if (res < 0) {
            return -1;
        }
    }
    return 0;
}

static inline bool input_has_issuance(uint32_t key_presence) {
    return !!(key_presence & (HAS_ISSUE_VALUE | HAS_ISSUE_COMMITMENT));
}

static bool hash_input_issuance(dispatcher_context_t *dc,
                                const merkleized_map_commitment_t *map,
                                uint32_t key_presence,
                                cx_hash_t *hash_context) {
    // Hash nonce
    if (key_presence & HAS_ISSUE_NONCE) {
        uint8_t nonce[32];
        if (sizeof(nonce) != call_get_merkleized_map_value(
                dc,
                map,
                PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE,
                sizeof(PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE),
                nonce,
                sizeof(nonce)
            )) {
            return false;
        }
        crypto_hash_update(hash_context, nonce, sizeof(nonce));
    } else {
        return false;
    }

    // Hash entropy
    if (key_presence & HAS_ISSUE_ENTROPY) {
        uint8_t entropy[32];
        if (sizeof(entropy) != call_get_merkleized_map_value(
                dc,
                map,
                PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY,
                sizeof(PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY),
                entropy,
                sizeof(entropy)
            )) {
            return false;
        }
        crypto_hash_update(hash_context, entropy, sizeof(entropy));
    } else {
        return false;
    }

    // Hash amount commitment
    if (key_presence & HAS_ISSUE_COMMITMENT) {
        uint8_t commitment[33];
        if (sizeof(commitment) != call_get_merkleized_map_value(
                dc,
                map,
                PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT,
                sizeof(PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT),
                commitment,
                sizeof(commitment)
            )) {
            return false;
        }
        crypto_hash_update(hash_context, commitment, sizeof(commitment));
    } else if (key_presence & HAS_ISSUE_VALUE) {
        uint8_t value[8];
        if (sizeof(value) != call_get_merkleized_map_value(
                dc,
                map,
                PSBT_ELEMENTS_IN_ISSUANCE_VALUE,
                sizeof(PSBT_ELEMENTS_IN_ISSUANCE_VALUE),
                value,
                sizeof(value)
            )) {
            return false;
        }
        crypto_hash_update(hash_context, value, sizeof(value));
    } else {
        return false;
    }

    // Hash token commitment
    if (key_presence & HAS_TOKEN_COMMITMENT) {
        uint8_t commitment[33];
        if (sizeof(commitment) != call_get_merkleized_map_value(
                dc,
                map,
                PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT,
                sizeof(PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT),
                commitment,
                sizeof(commitment)
            )) {
            return false;
        }
        crypto_hash_update(hash_context, commitment, sizeof(commitment));
    } else if (key_presence & HAS_TOKEN_VALUE) {
        uint8_t value[8];
        if (sizeof(value) != call_get_merkleized_map_value(
                dc,
                map,
                PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT,
                sizeof(PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_AMOUNT),
                value,
                sizeof(value)
            )) {
            return false;
        }
        crypto_hash_update(hash_context, value, sizeof(value));
    } else {
        crypto_hash_update_u8(hash_context, 0x00);
    }

    return true;
}

static int get_segwit_version(const uint8_t scriptPubKey[], int scriptPubKey_len) {
    if (scriptPubKey_len <= 1) {
        return -1;
    }

    if (scriptPubKey[0] == 0x00) {
        return 0;
    } else if (scriptPubKey[0] >= 0x51 && scriptPubKey[0] <= 0x60) {
        return scriptPubKey[0] - 0x50;
    }

    return -1;
}

/*
 Convenience function to get the amount and scriptpubkey from the non-witness-utxo of a certain
 input in a PSBTv2.
 If expected_prevout_hash is not NULL, the function fails if the txid computed from the
 non-witness-utxo does not match the one pointed by expected_prevout_hash. Returns -1 on failure, 0
 on success.
*/
static int parse_utxo_nonwitness(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    tx_asset_t *asset,
    tx_amount_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len,
    const uint8_t *expected_prevout_hash,
    cx_sha256_t *issuance_hash_context) {
    // If there is no witness-utxo, it must be the case that this is a legacy input.
    // In this case, we can only retrieve the prevout amount and scriptPubKey by parsing
    // the non-witness-utxo

    // Read the prevout index
    uint32_t prevout_n;
    if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                  input_map,
                                                  (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                  1,
                                                  &prevout_n)) {
        return -1;
    }

    txid_parser_outputs_t parser_outputs;
    // request non-witness utxo, and get the prevout's value and scriptpubkey
    int res = call_pset_parse_rawtx(dc,
                                    input_map,
                                    (uint8_t[]){PSBT_IN_NON_WITNESS_UTXO},
                                    1,
                                    prevout_n,
                                    &parser_outputs,
                                    issuance_hash_context);
    if (res < 0) {
        PRINTF("Parsing rawtx failed\n");
        return -1;
    }

    // if expected_prevout_hash is given, check that it matches the txid obtained from the parser
    if (expected_prevout_hash != NULL &&
        memcmp(parser_outputs.txid, expected_prevout_hash, 32) != 0) {
        PRINTF("Prevout hash did not match non-witness-utxo transaction hash\n");

        return -1;
    }

    if(parser_outputs.vout.scriptpubkey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
        return -1;
    }

    if (asset != NULL) {
        *asset = parser_outputs.vout.asset;
    }
    if (amount != NULL) {
        *amount = parser_outputs.vout.amount;
    }
    if (scriptPubKey_len != NULL && scriptPubKey != NULL) {
        *scriptPubKey_len = parser_outputs.vout.scriptpubkey_len;
        memcpy(scriptPubKey,
               parser_outputs.vout.scriptpubkey,
               parser_outputs.vout.scriptpubkey_len);
    }

    return 0;
}

/*
 Convenience function to get the amount, asset and scriptpubkey from the witness-utxo of a certain input in
 a PSBTv2.
 Returns -1 on failure, 0 on success.
*/
static int parse_utxo_witness(
    dispatcher_context_t *dc,
    const merkleized_map_commitment_t *input_map,
    tx_asset_t *asset,
    tx_amount_t *amount,
    uint8_t scriptPubKey[static MAX_PREVOUT_SCRIPTPUBKEY_LEN],
    size_t *scriptPubKey_len) {
    txid_parser_vout_t parser_output;

    int res = call_pset_parse_rawtx_single_output(dc,
                                                  input_map,
                                                  (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                  1,
                                                  &parser_output,
                                                  NULL);

    if (res < 0) {
        PRINTF("Parsing witness UTXO failed\n");
        return -1;
    }

    if(parser_output.scriptpubkey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
        return -1;
    }

    if (asset != NULL) {
        *asset = parser_output.asset;
    }
    if (amount != NULL) {
        *amount = parser_output.amount;
    }
    if (scriptPubKey_len != NULL && scriptPubKey != NULL) {
        *scriptPubKey_len = parser_output.scriptpubkey_len;
        memcpy(scriptPubKey, parser_output.scriptpubkey, parser_output.scriptpubkey_len);
    }

    return 0;
}

/**
 * Handles confidential value of an input or an output
 */
static bool set_in_out_amount(overlayed_in_out_info_t *p_info, tx_amount_t *amount) {
    if(!p_info || !amount) {
        return false;
    }

    if(!amount->is_blinded) {
        if(!(p_info->key_read_status & HAS_PREVOUT_AMOUNT)) {
            p_info->in_out.value = amount->value;
            p_info->key_read_status |= HAS_PREVOUT_AMOUNT;
        } else if(amount->value != p_info->in_out.value) {
            // new value does not match with the previous initialization
            return false;
        }
    } else {
        if(p_info->key_read_status & HAS_VALUE_COMMITMENT) {
            if(0 != memcmp(p_info->in_out.value_commitment,
                           amount->commitment,
                           sizeof(p_info->in_out.value_commitment))) {
                return false;
            }
        } else {
            memcpy(p_info->in_out.value_commitment,
                   amount->commitment,
                   sizeof(p_info->in_out.value_commitment));
            p_info->key_read_status |= HAS_VALUE_COMMITMENT;
        }
    }

    return true;
}

/**
 * Handles confidential asset of an input or an output
 */
static bool set_in_out_asset(overlayed_in_out_info_t *p_info, tx_asset_t *asset) {
    if(!p_info || !asset) {
        return false;
    }

    if (asset->is_blinded) {
        if (asset->commitment[0] != 0x0a && asset->commitment[0] != 0x0b) {
            return false;
        }
        if (p_info->key_read_status & HAS_ASSET_COMMITMENT) {
            return 0 == memcmp(p_info->in_out.asset_commitment,
                               asset->commitment,
                               sizeof(p_info->in_out.asset_commitment));
        } else {
            memcpy(p_info->in_out.asset_commitment,
                   asset->commitment,
                   sizeof(p_info->in_out.asset_commitment));
            p_info->key_read_status |= HAS_ASSET_COMMITMENT;
        }
    } else {
        if (p_info->key_read_status & HAS_ASSET) {
            return 0 == memcmp(p_info->in_out.asset_tag,
                               asset->tag,
                               sizeof(p_info->in_out.asset_tag));
        } else {
            p_info->in_out.asset_info = liquid_get_asset_info(asset->tag);
            memcpy(p_info->in_out.asset_tag,
                   asset->tag,
                   sizeof(p_info->in_out.asset_tag));
            p_info->key_read_status |= HAS_ASSET;
        }
    }
     return true;
}

// TODO: document
static cx_sha256_t* sha_context_alloc(sign_pset_state_t *state) {
    if(state->sha_context_index >= SIGN_PSET_SHA_CONTEXT_POOL_SIZE) {
        return NULL;
    }
    return &state->sha_context_pool[state->sha_context_index++];
}

// TODO: document
// contexts must be freed in reverse order
static bool sha_context_free(sign_pset_state_t *state, const cx_sha256_t *context) {
    if(!state->sha_context_index ||
       context != &state->sha_context_pool[state->sha_context_index - 1]) {
        return false;
    }
    state->sha_context_index--;
    return true;
}

/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in
 * it.
 */
void handler_liquid_sign_pset(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    merkleized_map_commitment_t global_map;
    if (!buffer_read_varint(&dc->read_buffer, &global_map.size)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    if (!buffer_read_bytes(&dc->read_buffer, global_map.keys_root, 32) ||
        !buffer_read_bytes(&dc->read_buffer, global_map.values_root, 32)) {
        LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    uint64_t n_inputs;
    if (!buffer_read_varint(&dc->read_buffer, &n_inputs) ||
        !buffer_read_bytes(&dc->read_buffer, state->inputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_inputs > MAX_N_INPUTS_CAN_SIGN) {
        // TODO: remove this limitation
        PRINTF("At most %d inputs are supported\n", MAX_N_INPUTS_CAN_SIGN);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }
    state->n_inputs = (unsigned int) n_inputs;

    uint64_t n_outputs;
    if (!buffer_read_varint(&dc->read_buffer, &n_outputs) ||
        !buffer_read_bytes(&dc->read_buffer, state->outputs_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_outputs < 2) {
        PRINTF("At least 2 outputs are required (including fee output)\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    state->n_outputs = (unsigned int) n_outputs;

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];
    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    // Fetch the serialized wallet policy from the client
    uint8_t serialized_wallet_policy[MAX_POLICY_MAP_SERIALIZED_LENGTH];
    int serialized_wallet_policy_len = call_get_preimage(dc,
                                                         wallet_id,
                                                         serialized_wallet_policy,
                                                         sizeof(serialized_wallet_policy));
    if (serialized_wallet_policy_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    policy_map_wallet_header_t wallet_header;
    buffer_t serialized_wallet_policy_buf =
        buffer_create(serialized_wallet_policy, serialized_wallet_policy_len);
    if ((read_policy_map_wallet(&serialized_wallet_policy_buf, &wallet_header)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    memcpy(state->wallet_header_keys_info_merkle_root,
           wallet_header.keys_info_merkle_root,
           sizeof(state->wallet_header_keys_info_merkle_root));
    state->wallet_header_n_keys = wallet_header.n_keys;

    buffer_t policy_map_buffer =
        buffer_create(&wallet_header.policy_map, wallet_header.policy_map_len);

    if (parse_policy_map(&policy_map_buffer,
                         state->wallet_policy.map_bytes,
                         sizeof(state->wallet_policy.map_bytes)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // Unwrap policy map removing blinded() tag and extracting master blinding key
    state->wallet_policy_map_unwrapped = &state->wallet_policy.map;
    uint8_t master_blinding_key[32]; // Currently unused
    liquid_blinding_key_type_t blinding_key_type; // Currently unused
    bool wallet_is_blinded; // Currently unused
    if(!liquid_policy_unwrap_blinded(&state->wallet_policy_map_unwrapped,
                                     &wallet_is_blinded,
                                     master_blinding_key,
                                     sizeof(master_blinding_key),
                                     NULL,
                                     &blinding_key_type)) {
        SEND_SW(dc, SW_INCORRECT_DATA);  // unexpected
        return;
    }
    state->wallet_policy_root_type = state->wallet_policy_map_unwrapped->type;

    uint8_t hmac_or =
        0;  // the binary OR of all the hmac bytes (so == 0 iff the hmac is identically 0)
    for (int i = 0; i < 32; i++) {
        hmac_or = hmac_or | wallet_hmac[i];
    }
    if (hmac_or == 0) {
        // No hmac, verify that the policy is a canonical one that is allowed by default

        if (state->wallet_header_n_keys != 1) {
            PRINTF("Non-standard policy, it should only have 1 key\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        int address_type = get_policy_address_type(state->wallet_policy_map_unwrapped);
        if (address_type == -1) {
            PRINTF("Non-standard policy, and no hmac provided\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        state->is_wallet_canonical = true;

        // Based on the address type, we set the expected bip44 purpose for this canonical wallet
        state->bip44_purpose = get_bip44_purpose(address_type);
        if (state->bip44_purpose < 0) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }

        // We do not check here that the purpose field, coin_type and account (first three step of
        // the bip44 derivation) are standard. Will check at signing time that the path is valid.
    } else {
        // Verify hmac

        if (!check_wallet_hmac(wallet_id, wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

        state->is_wallet_canonical = false;
    }

#ifdef LIQUID_HAS_SWAP
    // Swap feature: check that wallet is canonical
    if (G_swap_state.called_from_swap && !state->is_wallet_canonical) {
        PRINTF("Must be a canonical wallet for swap feature\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
#else
    if (G_swap_state.called_from_swap) {
        PRINTF("Swap feature is not supported\n");
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }
#endif

    state->inputs_total_value = 0;
    state->internal_inputs_total_value = 0;
    memset(state->internal_inputs, 0, sizeof(state->internal_inputs));

    state->master_key_fingerprint = crypto_get_master_key_fingerprint();

    // process global map
    {
        // Check integrity of the global map
        if (call_check_merkle_tree_sorted(dc, global_map.keys_root, (size_t) global_map.size) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t raw_result[9];  // max size for a varint
        int result_len;

        // Read tx version
        result_len = call_get_merkleized_map_value(dc,
                                                   &global_map,
                                                   (uint8_t[]){PSBT_GLOBAL_TX_VERSION},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
        if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        state->tx_version = read_u32_le(raw_result, 0);

        // Read fallback locktime.
        // Unlike BIP-0370 recommendation, we use the fallback locktime as-is, ignoring each input's
        // preferred height/block locktime. If that's relevant, the client must set the fallback
        // locktime to the appropriate value before calling sign_psbt.
        result_len = call_get_merkleized_map_value(dc,
                                                   &global_map,
                                                   (uint8_t[]){PSBT_GLOBAL_FALLBACK_LOCKTIME},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
        if (result_len == -1) {
            state->locktime = 0;
        } else if (result_len != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        } else {
            state->locktime = read_u32_le(raw_result, 0);
        }

        // we already know n_inputs and n_outputs, so we skip reading from the global map
    }

    state->cur_input_index = 0;

    if (state->is_wallet_canonical) {
        // Canonical wallet, we start processing the psbt directly
        dc->next(process_input_map);
    } else {

        // Show screen to authorize spend from a registered wallet
        ui_authorize_wallet_spend(dc, wallet_header.name, process_input_map);
    }
}

/** Inputs verification flow
 *
 *  Go though all the inputs:
 *  - verify the non_witness_utxo
 *  - compute value spent
 *  - detect internal inputs that should be signed, and external inputs that shouldn't
 */

static void process_input_map(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->cur_input_index >= state->n_inputs) {
        // all inputs already processed
        dc->next(alert_external_inputs);
        return;
    }

    // Reset cur struct
    memset(&state->cur, 0, sizeof(state->cur));

    {
        input_keys_callback_state_t callback_state = (input_keys_callback_state_t) {
            .out_pubkey = state->cur.in_out.bip32_derivation_pubkey,
            .pubkey_size = sizeof(state->cur.in_out.bip32_derivation_pubkey)
        };
        int res = call_get_merkleized_map_with_callback(
            dc,
            state->inputs_root,
            state->n_inputs,
            state->cur_input_index,
            make_callback(&callback_state, (dispatcher_callback_t) input_keys_callback),
            &state->cur.in_out.map);
        if (res < 0) {
            PRINTF("Failed to process input map\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (callback_state.error) {
            PRINTF("Error during processing input keys (wrong pubkey format?)\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        state->cur.key_presence = callback_state.key_presence;
    }

    if (state->cur.key_presence & HAS_ASSET) {
        tx_asset_t asset;
        asset.is_blinded = false;

        if ( sizeof(asset.tag) ==
                call_get_merkleized_map_value(dc,
                                              &state->cur.in_out.map,
                                              PSBT_ELEMENTS_IN_EXPLICIT_ASSET,
                                              sizeof(PSBT_ELEMENTS_IN_EXPLICIT_ASSET),
                                              asset.tag,
                                              sizeof(asset.tag)) ) {
            if (!set_in_out_asset(&state->cur, &asset)) {
                PRINTF("Invalid asset for input %u\n", state->cur_input_index);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            PRINTF("Failed to obtain asset tag for input %u\n", state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    PRINTF("\nkey_presence=%04x\n", state->cur.key_presence);

    if(state->cur.key_presence & HAS_VALUE) {
        tx_amount_t prevout_amount;
        prevout_amount.is_blinded = false;

        // Obtain input value from PSET field
        if (8 == call_get_merkleized_map_value_u64_le(dc,
                                                      &state->cur.in_out.map,
                                                      PSBT_ELEMENTS_IN_EXPLICIT_VALUE,
                                                      sizeof(PSBT_ELEMENTS_IN_EXPLICIT_VALUE),
                                                      &prevout_amount.value) ) {
            if (!set_in_out_amount(&state->cur, &prevout_amount)) {
                PRINTF("Amount is invalid\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            PRINTF("Failed to obtain value for input %u\n", state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    // either witness utxo or non-witness utxo (or both) must be present.
    if (0 == (state->cur.key_presence & (HAS_NONWITNESSUTXO | HAS_WITNESSUTXO))) {
        PRINTF("No witness utxo nor non-witness utxo present in input.\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // validate non-witness utxo (if present) and witness utxo (if present)

    if (state->cur.key_presence & HAS_NONWITNESSUTXO) {
        uint8_t prevout_hash[32];

        // check if the prevout_hash of the transaction matches the computed one from the
        // non-witness utxo
        if (0 > call_get_merkleized_map_value(dc,
                                              &state->cur.in_out.map,
                                              (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                              1,
                                              prevout_hash,
                                              sizeof(prevout_hash))) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // request non-witness utxo, and get the prevout's asset, value and scriptpubkey
        tx_asset_t asset;
        tx_amount_t prevout_amount;
        if (0 > parse_utxo_nonwitness(dc,
                                      &state->cur.in_out.map,
                                      &asset,
                                      &prevout_amount,
                                      state->cur.in_out.scriptPubKey,
                                      &state->cur.in_out.scriptPubKey_len,
                                      prevout_hash,
                                      NULL /* issuance_hash_context */)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (!set_in_out_asset(&state->cur, &asset)) {
            PRINTF("Invalid asset for input %u\n", state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (!set_in_out_amount(&state->cur, &prevout_amount)) {
            PRINTF("Amount in non-witness utxo doesn't match externally provided one\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    if (state->cur.key_presence & HAS_WITNESSUTXO) {
        size_t wit_utxo_scriptPubkey_len;
        uint8_t wit_utxo_scriptPubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
        tx_asset_t asset;
        tx_amount_t wit_utxo_prevout_amount;

        if (0 > parse_utxo_witness(dc,
                                   &state->cur.in_out.map,
                                   &asset,
                                   &wit_utxo_prevout_amount,
                                   wit_utxo_scriptPubkey,
                                   &wit_utxo_scriptPubkey_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        };

        if (!set_in_out_asset(&state->cur, &asset)) {
            PRINTF("Invalid asset for input %u\n", state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (!set_in_out_amount(&state->cur, &wit_utxo_prevout_amount)) {
            PRINTF("Amount in witness utxo doesn't previously decoded one\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (state->cur.key_presence & HAS_NONWITNESSUTXO) {
            // we already know the scriptPubKey, but we double check that it matches
            if (state->cur.in_out.scriptPubKey_len != wit_utxo_scriptPubkey_len ||
                memcmp(state->cur.in_out.scriptPubKey,
                       wit_utxo_scriptPubkey,
                       wit_utxo_scriptPubkey_len) != 0) {
                PRINTF("scriptPubKey in non-witness utxo doesn't match with witness utxo\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            // we extract the scriptPubKey from the witness utxo
            if (wit_utxo_scriptPubkey_len <= sizeof(state->cur.in_out.scriptPubKey)) {
                memcpy(state->cur.in_out.scriptPubKey,
                       wit_utxo_scriptPubkey,
                       wit_utxo_scriptPubkey_len);
                state->cur.in_out.scriptPubKey_len = wit_utxo_scriptPubkey_len;
            } else {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        }
    }

    if (!(state->cur.key_read_status & HAS_PREVOUT_AMOUNT)) {
        PRINTF("Non-blinded amount is not provided for input %u\n", state->cur_input_index);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    state->inputs_total_value += state->cur.in_out.value;

    if ( !(state->cur.key_read_status & HAS_ASSET) || !(state->cur.key_read_status & HAS_ASSET) ) {
        PRINTF("Asset tag is not provided for input %u\n", state->cur_input_index);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if(!state->cur.in_out.asset_info) {
        // Warn the user about unknown asset
        ui_warn_unknown_asset(dc, state->cur.in_out.asset_tag, check_input_commitments);
    } else {
        dc->next(check_input_commitments);
    }
}

static void check_input_commitments(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t blinded_asset_gen[LIQUID_GENERATOR_LEN];
    bool blinded_asset_gen_init = false;

    // Verify asset commitment.
    // Also save blinded asset generator for value commitment verification.
    if (state->cur.key_read_status & HAS_ASSET_COMMITMENT) {
        if (!liquid_generator_parse(blinded_asset_gen, state->cur.in_out.asset_commitment)) {
            PRINTF("Error parsing asset commitment\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        blinded_asset_gen_init = true;

        if (state->cur.key_read_status & HAS_ASSET) {
            uint8_t proof[LIQUID_MAX_SINGLE_SURJECTION_PROOF_LEN];

            int proof_len = call_get_merkleized_map_value(dc,
                                                          &state->cur.in_out.map,
                                                          PSBT_ELEMENTS_IN_ASSET_PROOF,
                                                          sizeof(PSBT_ELEMENTS_IN_ASSET_PROOF),
                                                          proof,
                                                          sizeof(proof));
            if (proof_len <= 0) {
                PRINTF("Error fetching asset proof\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            uint8_t asset_gen[LIQUID_GENERATOR_LEN];
            if (!liquid_generator_generate(asset_gen, state->cur.in_out.asset_tag)) {
                PRINTF("Invalid asset tag\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            bool result = liquid_surjectionproof_verify_single(proof,
                                                               proof_len,
                                                               asset_gen,
                                                               blinded_asset_gen);
            if (!result) {
                PRINTF("Invalid asset commitment for input %u\n", state->cur_input_index);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            PRINTF("Asset tag not provided for input %u\n", state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    // Verify value commitment
    if (state->cur.key_read_status & HAS_VALUE_COMMITMENT) {
        if (!blinded_asset_gen_init) {
            PRINTF("Asset commitment is required to verify value commitment\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t proof[LIQUID_MAX_VALUE_PROOF_LEN];
        int proof_len = call_get_merkleized_map_value(dc,
                                                      &state->cur.in_out.map,
                                                      PSBT_ELEMENTS_IN_VALUE_PROOF,
                                                      sizeof(PSBT_ELEMENTS_IN_VALUE_PROOF),
                                                      proof,
                                                      sizeof(proof));
        if (proof_len <= 0) {
            PRINTF("Error fetching value proof\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        bool result = liquid_rangeproof_verify_exact(proof,
                                                     (size_t)proof_len,
                                                     state->cur.in_out.value,
                                                     state->cur.in_out.value_commitment,
                                                     sizeof(state->cur.in_out.value_commitment),
                                                     blinded_asset_gen);
        if (!result) {
            PRINTF("Invalid value commitment for input %u\n", state->cur_input_index);
            PRINTF("value=%llu\n", state->cur.in_out.value);
            PRINT_HEX("asset_tag=", state->cur.in_out.asset_tag, sizeof(state->cur.in_out.asset_tag));
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    dc->next(check_input_owned);
}

static void check_input_owned(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    int is_internal = is_in_out_internal(dc,
                                         state,
                                         &state->cur.in_out,
                                         true,
                                         !!(state->cur.key_presence & HAS_BIP32_DERIVATION));

    if (is_internal < 0) {
        PRINTF("Error checking if input %d is internal\n", state->cur_input_index);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    } else if (is_internal == 0) {
        PRINTF("INPUT %d is external\n", state->cur_input_index);
    } else {
        bitvector_set(state->internal_inputs, state->cur_input_index, 1);
        if(!(state->cur.key_read_status & HAS_PREVOUT_AMOUNT)) {
            PRINTF("Non-blinded amount is not provided for input %u\n", state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        state->internal_inputs_total_value += state->cur.in_out.value;

        int segwit_version =
            get_segwit_version(state->cur.in_out.scriptPubKey, state->cur.in_out.scriptPubKey_len);

        // For legacy or segwit-v0 inputs, the non-witness utxo must be present
        if ((segwit_version == -1 || segwit_version == 0) &&
             !(state->cur.key_presence & HAS_NONWITNESSUTXO)) {
            PRINTF("Non-witness utxo missing for legacy or segwitv0 input\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // For all segwit transactions, the witness utxo must be present
        if (segwit_version >= 0 && !(state->cur.key_presence & HAS_WITNESSUTXO)) {
            PRINTF("Witness utxo missing for segwit input\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    ++state->cur_input_index;
    dc->next(process_input_map);
}

// If there are external inputs, it is unsafe to sign, therefore we warn the user
static void alert_external_inputs(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    size_t count_external_inputs = 0;
    for (unsigned int i = 0; i < state->n_inputs; i++) {
        if (!bitvector_get(state->internal_inputs, i)) {
            ++count_external_inputs;
        }
    }

    if (count_external_inputs == 0) {
        // no external inputs
        dc->next(verify_outputs_init);
    } else if (count_external_inputs == state->n_inputs) {
        // no internal inputs, nothing to sign
        PRINTF("No internal inputs. Aborting\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    } else {
#ifdef LIQUID_HAS_SWAP
        // Swap feature: no external inputs allowed
        if (G_swap_state.called_from_swap) {
            PRINTF("External inputs not allowed in swap transactions\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
#endif

        // some internal and some external inputs, warn the user first
        ui_warn_external_inputs(dc, verify_outputs_init);
    }
}

/** OUTPUTS VERIFICATION FLOW
 *
 *  For each output, check if it's a change address.
 *  Show each output that is not a change address to the user for verification.
 */

// entry point for the outputs verification flow
static void verify_outputs_init(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->outputs_total_value = 0;
    state->change_outputs_total_value = 0;
    state->change_count = 0;

    state->cur_output_index = 0;

    state->external_outputs_count = 0;

    dc->next(process_output_map);
}

static void process_output_map(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // The last output is a "fee output" in Elements transactions
    bool is_fee_output = (state->cur_output_index + 1 == state->n_outputs);
    // Reset cur struct
    memset(&state->cur, 0, sizeof(state->cur));

    {
        output_keys_callback_state_t callback_state = (output_keys_callback_state_t) {
            .out_pubkey = state->cur.in_out.bip32_derivation_pubkey,
            .pubkey_size = sizeof(state->cur.in_out.bip32_derivation_pubkey)
        };
        int res = call_get_merkleized_map_with_callback(
            dc,
            state->outputs_root,
            state->n_outputs,
            state->cur_output_index,
            make_callback(&callback_state, (dispatcher_callback_t) output_keys_callback),
            &state->cur.in_out.map);
        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (callback_state.error) {
            PRINTF("Error during processing input keys (wrong pubkey format?)\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        state->cur.key_presence = callback_state.key_presence;
    }

    // read output amount and scriptpubkey

    uint8_t raw_result[8];

    // Read the output's amount
    int result_len = call_get_merkleized_map_value(dc,
                                                   &state->cur.in_out.map,
                                                   (uint8_t[]){PSBT_OUT_AMOUNT},
                                                   1,
                                                   raw_result,
                                                   sizeof(raw_result));
    if (result_len != 8) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    uint64_t value = read_u64_le(raw_result, 0);

    {
        tx_amount_t amount = { .is_blinded = false, .value = value };
        if (!set_in_out_amount(&state->cur, &amount)) {
            PRINTF("Invalid amount for output %u\n", state->cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    if (!is_fee_output) {
        state->outputs_total_value += value;
    } else {
        state->fee_value = value;
    }

    if (state->cur.key_presence & HAS_ASSET) {
        tx_asset_t asset;
        asset.is_blinded = false;

        if ( sizeof(asset.tag) ==
                call_get_merkleized_map_value(dc,
                                              &state->cur.in_out.map,
                                              PSBT_ELEMENTS_OUT_ASSET,
                                              sizeof(PSBT_ELEMENTS_OUT_ASSET),
                                              asset.tag,
                                              sizeof(asset.tag)) ) {
            if (!set_in_out_asset(&state->cur, &asset)) {
                PRINTF("Invalid asset for output %u\n", state->cur_output_index);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            PRINTF("Failed to obtain asset tag for output %u\n", state->cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    // Read the output's scriptPubKey
    result_len = call_get_merkleized_map_value(dc,
                                               &state->cur.in_out.map,
                                               (uint8_t[]){PSBT_OUT_SCRIPT},
                                               1,
                                               state->cur.in_out.scriptPubKey,
                                               sizeof(state->cur.in_out.scriptPubKey));

    if (result_len == -1 || result_len > (int) sizeof(state->cur.in_out.scriptPubKey) ||
        (is_fee_output && result_len != 0)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    state->cur.in_out.scriptPubKey_len = result_len;

    if (is_fee_output) {
        dc->next(confirm_transaction);
    } else {
        dc->next(check_output_commitments);
    }
}

static void check_output_commitments(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t blinded_asset_gen[LIQUID_GENERATOR_LEN];
    bool blinded_asset_gen_init = false;

    // Verify asset commitment.
    // Also save blinded asset generator for value commitment verification.
    if (state->cur.key_presence & HAS_ASSET_COMMITMENT) {
        {
            uint8_t commitment[LIQUID_COMMITMENT_LEN];

            int commitment_len =
                call_get_merkleized_map_value(dc,
                                            &state->cur.in_out.map,
                                            PSBT_ELEMENTS_OUT_ASSET_COMMITMENT,
                                            sizeof(PSBT_ELEMENTS_OUT_ASSET_COMMITMENT),
                                            commitment,
                                            sizeof(commitment));
            if (commitment_len != sizeof(commitment)) {
                PRINTF("Error fetching asset commitment\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            if (!liquid_generator_parse(blinded_asset_gen, commitment)) {
                PRINTF("Error parsing asset commitment\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        }
        blinded_asset_gen_init = true;

        if (state->cur.key_read_status & HAS_ASSET) {
            uint8_t proof[LIQUID_MAX_SINGLE_SURJECTION_PROOF_LEN];

            int proof_len =
                call_get_merkleized_map_value(dc,
                                              &state->cur.in_out.map,
                                              PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF,
                                              sizeof(PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF),
                                              proof,
                                              sizeof(proof));
            if (proof_len <= 0) {
                PRINTF("Error fetching asset proof\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            uint8_t asset_gen[LIQUID_GENERATOR_LEN];
            if (!liquid_generator_generate(asset_gen, state->cur.in_out.asset_tag)) {
                PRINTF("Invalid asset tag\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            bool result = liquid_surjectionproof_verify_single(proof,
                                                               proof_len,
                                                               asset_gen,
                                                               blinded_asset_gen);
            if (!result) {
                PRINTF("Invalid asset commitment for output %u\n", state->cur_output_index);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            PRINTF("Asset tag not provided for output %u\n", state->cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    // Verify value commitment
    if (state->cur.key_presence & HAS_VALUE_COMMITMENT) {
        if (!blinded_asset_gen_init) {
            PRINTF("Asset commitment is required to verify value commitment\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t commitment[LIQUID_COMMITMENT_LEN];
        uint8_t proof[LIQUID_MAX_VALUE_PROOF_LEN];

        int commitment_len =
            call_get_merkleized_map_value(dc,
                                          &state->cur.in_out.map,
                                          PSBT_ELEMENTS_OUT_VALUE_COMMITMENT,
                                          sizeof(PSBT_ELEMENTS_OUT_VALUE_COMMITMENT),
                                          commitment,
                                          sizeof(commitment));
        if (commitment_len != sizeof(commitment)) {
            PRINTF("Error fetching value commitment\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        int proof_len =
            call_get_merkleized_map_value(dc,
                                          &state->cur.in_out.map,
                                          PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF,
                                          sizeof(PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF),
                                          proof,
                                          sizeof(proof));
        if (proof_len <= 0) {
            PRINTF("Error fetching value proof\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        bool result = liquid_rangeproof_verify_exact(proof,
                                                     (size_t)proof_len,
                                                     state->cur.in_out.value,
                                                     commitment,
                                                     (size_t)commitment_len,
                                                     blinded_asset_gen);
        if (!result) {
            PRINTF("Invalid value commitment for output %u\n", state->cur_output_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    dc->next(check_output_owned);
}

static void check_output_owned(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    int is_internal = is_in_out_internal(dc,
                                         state,
                                         &state->cur.in_out,
                                         false,
                                         !!(state->cur.key_presence & HAS_BIP32_DERIVATION));

    if (is_internal < 0) {
        PRINTF("Error checking if output %d is internal\n", state->cur_output_index);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    } else if (is_internal == 0) {
        // external output, user needs to validate
        ++state->external_outputs_count;

        dc->next(output_validate_external);
        return;
    } else {
        // valid change address, nothing to show to the user

        state->change_outputs_total_value += state->cur.in_out.value;
        ++state->change_count;

        dc->next(output_next);
        return;
    }
}

static void output_validate_external(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // show this output's address
    char output_address[MAX(MAX_ADDRESS_LENGTH_STR + 1, MAX_OPRETURN_OUTPUT_DESC_SIZE)];
    int address_len = get_script_address(state->cur.in_out.scriptPubKey,
                                         state->cur.in_out.scriptPubKey_len,
                                         G_coin_config,
                                         output_address,
                                         sizeof(output_address));
    if (address_len < 0) {
        // script does not have an address; check if OP_RETURN
        if (is_opreturn(state->cur.in_out.scriptPubKey, state->cur.in_out.scriptPubKey_len)) {
            int res = format_opscript_script(state->cur.in_out.scriptPubKey,
                                             state->cur.in_out.scriptPubKey_len,
                                             output_address);
            if (res == -1) {
                PRINTF("Invalid or unsupported OP_RETURN for output %d\n", state->cur_output_index);
                SEND_SW(dc, SW_NOT_SUPPORTED);
                return;
            }
        } else {
            PRINTF("Unknown or unsupported script type for output %d\n", state->cur_output_index);
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return;
        }
    }

#ifdef LIQUID_HAS_SWAP
    if (G_swap_state.called_from_swap) {
        // Swap feature: do not show the address to the user, but double check it matches the
        // request from app-exchange; it must be the only external output (checked elsewhere).
        int swap_addr_len = strnlen(G_swap_state.destination_address,
                                    sizeof(G_swap_state.destination_address) - 1);
        if (swap_addr_len != address_len ||
            0 != strncmp(G_swap_state.destination_address, output_address, address_len)) {
            // address did not match
            PRINTF("Mismatching address for swap\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        } else {
            // no need for user vaidation during swap
            dc->next(output_next);
            return;
        }
    } else {
#endif // LIQUID_HAS_SWAP
        // Show address to the user
        if(state->cur.in_out.asset_info) {
            ui_validate_output(dc,
                               state->external_outputs_count,
                               output_address,
                               state->cur.in_out.asset_info->ticker,
                               state->cur.in_out.value,
                               state->cur.in_out.asset_info->decimals,
                               output_next);
        } else { // Unknown asset
            ui_validate_output(dc,
                               state->external_outputs_count,
                               output_address,
                               UNKNOWN_ASSET_TICKER,
                               state->cur.in_out.value,
                               UNKNOWN_ASSET_DECIMALS,
                               output_next);
        }
        return;
#ifdef LIQUID_HAS_SWAP
    }
#endif
}

static void output_next(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    ++state->cur_output_index;
    dc->next(process_output_map);
}

// Performs any final checks if needed, then show the confirmation UI to the user
// (except during swap)
static void confirm_transaction(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->fee_value > UINT64_MAX - state->outputs_total_value || // to avoid overflow
        state->inputs_total_value != state->outputs_total_value + state->fee_value) {
        PRINTF("Fee is invalid\n");
        // Fee must be equal to difference between sum of inputs and sum of outputs
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (state->change_count > 10) {
        // As the information regarding change outputs is aggregated, we want to prevent the user
        // from unknowingly signing a transaction that sends the change to too many (possibly
        // unspendable) outputs.
        PRINTF("Too many change outputs: %d\n", state->change_count);
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

#ifdef LIQUID_HAS_SWAP
    if (G_swap_state.called_from_swap) {
        // Swap feature: check total amount and fees are as expected; moreover, only one external
        // output
        if (state->external_outputs_count != 1) {
            PRINTF("Swap transaction must have exactly 1 external output\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (state->fee_value != G_swap_state.fees) {
            PRINTF("Mismatching fee for swap\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        uint64_t spent_amount = state->outputs_total_value - state->change_outputs_total_value;
        if (spent_amount != G_swap_state.amount) {
            PRINTF("Mismatching spent amount for swap\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        // No user validation required during swap
        dc->next(sign_init);
    } else {
#endif // LIQUID_HAS_SWAP
        // Show final user validation UI
        if(state->cur.in_out.asset_info) {
            ui_validate_transaction(dc,
                                    state->cur.in_out.asset_info->ticker,
                                    state->fee_value,
                                    state->cur.in_out.asset_info->decimals,
                                    sign_init);
        } else { // Unknown asset
            ui_validate_transaction(dc,
                                    UNKNOWN_ASSET_TICKER,
                                    state->fee_value,
                                    UNKNOWN_ASSET_DECIMALS,
                                    sign_init);
        }
#ifdef LIQUID_HAS_SWAP
    }
#endif
}

/** SIGNING FLOW
 *
 * Iterate over all inputs. For each input that should be signed, compute and sign sighash.
 */

// entry point for the signing flow
static void sign_init(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // find and parse our registered key info in the wallet
    bool our_key_found = false;
    for (unsigned int i = 0; i < state->wallet_header_n_keys; i++) {
        uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];

        int key_info_len = call_get_merkle_leaf_element(dc,
                                                        state->wallet_header_keys_info_merkle_root,
                                                        state->wallet_header_n_keys,
                                                        i,
                                                        key_info_str,
                                                        sizeof(key_info_str));

        if (key_info_len < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return;
        }

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

        policy_map_key_info_t our_key_info;
        if (parse_policy_map_key_info(&key_info_buffer, &our_key_info) == -1) {
            SEND_SW(dc, SW_BAD_STATE);  // should never happen
            return;
        }

        uint32_t fpr = read_u32_be(our_key_info.master_key_fingerprint, 0);
        if (fpr == state->master_key_fingerprint) {
            // it could be a collision on the fingerprint; we verify that we can actually generate
            // the same pubkey
            char pubkey_derived[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
            int serialized_pubkey_len =
                get_serialized_extended_pubkey_at_path(our_key_info.master_key_derivation,
                                                       our_key_info.master_key_derivation_len,
                                                       G_coin_config->bip32_pubkey_version,
                                                       pubkey_derived);
            if (serialized_pubkey_len == -1) {
                SEND_SW(dc, SW_BAD_STATE);
                return;
            }

            if (strncmp(our_key_info.ext_pubkey, pubkey_derived, MAX_SERIALIZED_PUBKEY_LENGTH) ==
                0) {
                our_key_found = true;

                state->our_key_derivation_length = our_key_info.master_key_derivation_len;
                for (int i = 0; i < our_key_info.master_key_derivation_len; i++) {
                    state->our_key_derivation[i] = our_key_info.master_key_derivation[i];
                }

                break;
            }
        }
    }

    if (!our_key_found) {
        PRINTF("Couldn't find internal key\n");
        // should never happen if we only register wallets with an internal key
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    state->sha_context_index = 0;
    dc->next(compute_segwit_hashes);
}

// Compute all the tx-wide hashes for segwit inputs. Can be skipped if all inputs are legacy.
static void compute_segwit_hashes(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);
    PRINT_STACK_POINTER();

    // Policy memory is now reused for hashes
    state->wallet_policy_map_unwrapped = NULL;
    memset(&state->hashes, 0, sizeof(state->hashes));

    {
        // compute sha_prevouts and sha_sequences
        cx_sha256_t *sha_prevouts_context = sha_context_alloc(state);
        cx_sha256_t *sha_sequences_context = sha_context_alloc(state);
        if (!sha_prevouts_context || !sha_sequences_context) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }

        // compute hashPrevouts and hashSequence
        cx_sha256_init(sha_prevouts_context);
        cx_sha256_init(sha_sequences_context);

        for (unsigned int i = 0; i < state->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;

            int res =
                call_get_merkleized_map(dc, state->inputs_root, state->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            // get prevout hash and output index for the i-th input
            uint8_t ith_prevout_hash[32];
            if (32 != call_get_merkleized_map_value(dc,
                                                    &ith_map,
                                                    (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                    1,
                                                    ith_prevout_hash,
                                                    32)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            crypto_hash_update(&sha_prevouts_context->header, ith_prevout_hash, 32);

            uint8_t ith_prevout_n_raw[4];
            if (4 != call_get_merkleized_map_value(dc,
                                                    &ith_map,
                                                    (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                                    1,
                                                    ith_prevout_n_raw,
                                                    4)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            crypto_hash_update(&sha_prevouts_context->header, ith_prevout_n_raw, 4);

            uint8_t ith_nSequence_raw[4];
            if (4 != call_get_merkleized_map_value(dc,
                                                    &ith_map,
                                                    (uint8_t[]){PSBT_IN_SEQUENCE},
                                                    1,
                                                    ith_nSequence_raw,
                                                    4)) {
                // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
                memset(ith_nSequence_raw, 0xFF, 4);
            }

            crypto_hash_update(&sha_sequences_context->header, ith_nSequence_raw, 4);
        }

        crypto_hash_digest(&sha_prevouts_context->header, state->hashes.sha_prevouts, 32);
        crypto_hash_digest(&sha_sequences_context->header, state->hashes.sha_sequences, 32);

        if ( !sha_context_free(state, sha_sequences_context) ||
             !sha_context_free(state, sha_prevouts_context) ) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
    }

    {
        // compute sha_outputs and sha_rangeproofs (if needed)
        cx_sha256_t *sha_outputs_context = sha_context_alloc(state);
        cx_sha256_t *sha_rangeproofs_context = sha_context_alloc(state);
        if (!sha_outputs_context || !sha_rangeproofs_context) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
        cx_sha256_init(sha_outputs_context);
        cx_sha256_init(sha_rangeproofs_context);

        if (hash_outputs(dc,
                         &sha_outputs_context->header,
                         &sha_rangeproofs_context->header) == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_digest(&sha_outputs_context->header, state->hashes.sha_outputs, 32);
        crypto_hash_digest(&sha_rangeproofs_context->header, state->hashes.sha_rangeproofs, 32);

        if ( !sha_context_free(state, sha_rangeproofs_context) ||
             !sha_context_free(state, sha_outputs_context) ) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
    }

    {
        // compute sha_amounts and sha_scriptpubkeys
        // TODO: could be skipped if there are no segwitv1 inputs to sign

        cx_sha256_t *sha_amounts_context = sha_context_alloc(state);
        cx_sha256_t *sha_scriptpubkeys_context = sha_context_alloc(state);
        cx_sha256_t *sha_issuances_context = sha_context_alloc(state);
        if (!sha_amounts_context || !sha_scriptpubkeys_context || !sha_issuances_context) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }

        cx_sha256_init(sha_amounts_context);
        cx_sha256_init(sha_scriptpubkeys_context);
        cx_sha256_init(sha_issuances_context);

        for (unsigned int i = 0; i < state->n_inputs; i++) {
            // get this input's map
            merkleized_map_commitment_t ith_map;
            input_keys_callback_state_t callback_state = (input_keys_callback_state_t) {
                .out_pubkey = NULL,
                .pubkey_size = 0
            };

            int res =
                call_get_merkleized_map_with_callback(
                    dc,
                    state->inputs_root,
                    state->n_inputs,
                    i,
                    make_callback(&callback_state, (dispatcher_callback_t) input_keys_callback),
                    &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            tx_amount_t in_amount;
            uint8_t in_scriptPubKey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
            size_t in_scriptPubKey_len;

            if (0 > parse_utxo_nonwitness(dc,
                                          &ith_map,
                                          NULL, /* asset */
                                          &in_amount,
                                          in_scriptPubKey,
                                          &in_scriptPubKey_len,
                                          NULL, /* expected_prevout_hash */
                                          NULL /* issuance_hash_context */)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            if(in_amount.is_blinded) {
                crypto_hash_update(&sha_amounts_context->header,
                                    in_amount.commitment,
                                    sizeof(in_amount.commitment));
            } else {
                uint8_t in_amount_le[8];
                write_u64_le(in_amount_le, 0, in_amount.value);
                crypto_hash_update(&sha_amounts_context->header, in_amount_le, 8);
            }

            crypto_hash_update_varint(&sha_scriptpubkeys_context->header, in_scriptPubKey_len);
            crypto_hash_update(&sha_scriptpubkeys_context->header,
                               in_scriptPubKey,
                               in_scriptPubKey_len);
            if (input_has_issuance(callback_state.key_presence)) {
                if (!hash_input_issuance(dc,
                                         &ith_map,
                                         callback_state.key_presence,
                                         &sha_issuances_context->header)) {
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return;
                }
            } else {
                crypto_hash_update_u8(&sha_issuances_context->header, 0x00);
            }
        }

        crypto_hash_digest(&sha_amounts_context->header, state->hashes.sha_amounts, 32);
        crypto_hash_digest(&sha_scriptpubkeys_context->header,
                            state->hashes.sha_scriptpubkeys,
                            32);
        crypto_hash_digest(&sha_issuances_context->header, state->hashes.sha_issuances, 32);

        if ( !sha_context_free(state, sha_issuances_context) ||
             !sha_context_free(state, sha_scriptpubkeys_context) ||
             !sha_context_free(state, sha_amounts_context) ) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
    }

    state->cur_input_index = 0;
    dc->next(sign_process_input_map);
}

static void sign_process_input_map(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // skip external inputs
    while (state->cur_input_index < state->n_inputs &&
           !bitvector_get(state->internal_inputs, state->cur_input_index)) {
        PRINTF("Skipping signing external input %d\n", state->cur_input_index);
        ++state->cur_input_index;
    }

    if (state->cur_input_index >= state->n_inputs) {
        // all inputs already processed
        dc->next(finalize);
        return;
    }

    // Reset cur struct
    memset(&state->cur, 0, sizeof(state->cur));

    {
        input_keys_callback_state_t callback_state = (input_keys_callback_state_t) {
            .out_pubkey = state->cur.in_out.bip32_derivation_pubkey,
            .pubkey_size = sizeof(state->cur.in_out.bip32_derivation_pubkey)
        };
        int res = call_get_merkleized_map_with_callback(
            dc,
            state->inputs_root,
            state->n_inputs,
            state->cur_input_index,
            make_callback(&callback_state, (dispatcher_callback_t) input_keys_callback),
            &state->cur.in_out.map);
        if (res < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (callback_state.error) {
            PRINTF("Error during processing input keys (wrong pubkey format?)\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        state->cur.key_presence = callback_state.key_presence;
    }

    if(state->cur.key_presence & HAS_VALUE) {
        tx_amount_t prevout_amount;
        prevout_amount.is_blinded = false;

        // Obtain input value from PSET field
        if (8 == call_get_merkleized_map_value_u64_le(dc,
                                                      &state->cur.in_out.map,
                                                      PSBT_ELEMENTS_IN_EXPLICIT_VALUE,
                                                      sizeof(PSBT_ELEMENTS_IN_EXPLICIT_VALUE),
                                                      &prevout_amount.value) ) {
            if (!set_in_out_amount(&state->cur, &prevout_amount)) {
                PRINTF("Amount is invalid\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            PRINTF("Failed to obtain value for input %u\n", state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    if (!(state->cur.key_presence & HAS_SIGHASH_TYPE)) {
        state->cur.input.sighash_type = SIGHASH_ALL;
    } else {
        // Get sighash type
        if (4 != call_get_merkleized_map_value_u32_le(dc,
                                                      &state->cur.in_out.map,
                                                      (uint8_t[]){PSBT_IN_SIGHASH_TYPE},
                                                      1,
                                                      &state->cur.input.sighash_type)) {
            PRINTF("Malformed PSBT_IN_SIGHASH_TYPE for input %d\n", state->cur_input_index);

            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    // get path, obtain change and address_index

    int bip32_path_len;
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    uint32_t fingerprint;

    if (state->wallet_policy_root_type == TOKEN_TR) {
        // taproot input, use PSBT_IN_TAP_BIP32_DERIVATION
        uint8_t key[1 + 32];
        key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(key + 1, state->cur.in_out.bip32_derivation_pubkey, sizeof(key) - 1);

        bip32_path_len = get_emptyhashes_fingerprint_and_path(dc,
                                                              &state->cur.in_out.map,
                                                              key,
                                                              sizeof(key),
                                                              &fingerprint,
                                                              bip32_path);
    } else {
        // legacy or segwitv0 input, use PSBT_IN_BIP32_DERIVATION
        uint8_t key[1 + 33];
        key[0] = PSBT_IN_BIP32_DERIVATION;
        memcpy(key + 1, state->cur.in_out.bip32_derivation_pubkey, sizeof(key) - 1);

        bip32_path_len = get_fingerprint_and_path(dc,
                                                  &state->cur.in_out.map,
                                                  key,
                                                  sizeof(key),
                                                  &fingerprint,
                                                  bip32_path);
    }

    if (bip32_path_len < 2) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    state->cur.input.change = bip32_path[bip32_path_len - 2];
    state->cur.input.address_index = bip32_path[bip32_path_len - 1];

    // Sign as segwit input iff it has a witness utxo
    if (!(state->cur.key_presence & HAS_WITNESSUTXO)) {
        dc->next(sign_legacy);
    } else {
        dc->next(sign_segwit);
    }
}

static void sign_legacy(dispatcher_context_t *dc) {
    // sign legacy P2PKH or P2SH

    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // sign_non_witness(non_witness_utxo.vout[psbt.tx.input_[i].prevout.n].scriptPubKey, i)

    if (0 > parse_utxo_nonwitness(dc,
                                  &state->cur.in_out.map,
                                  NULL, /* asset */
                                  NULL, /* amount */
                                  state->cur.in_out.scriptPubKey,
                                  &state->cur.in_out.scriptPubKey_len,
                                  NULL, /* expected_prevout_hash */
                                  NULL /* issuance_hash_context */ )) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    dc->next(sign_legacy_compute_sighash);
}

static void sign_legacy_compute_sighash(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[4];
    write_u32_le(tmp, 0, state->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    crypto_hash_update_varint(&sighash_context.header, state->n_inputs);

    for (unsigned int i = 0; i < state->n_inputs; i++) {
        // get this input's map
        merkleized_map_commitment_t ith_map;

        if (i != state->cur_input_index) {
            int res = call_get_merkleized_map(dc, state->inputs_root, state->n_inputs, i, &ith_map);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
        } else {
            // Avoid requesting the same map unnecessarily
            // (might be removed once a caching mechanism is implemented)
            memcpy(&ith_map, &state->cur.in_out.map, sizeof(ith_map));
        }

        // get prevout hash and output index for the i-th input
        uint8_t ith_prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &ith_map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                ith_prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_hash, 32);

        uint8_t ith_prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               ith_prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header, ith_prevout_n_raw, 4);

        if (i != state->cur_input_index) {
            // empty scriptcode
            crypto_hash_update_u8(&sighash_context.header, 0x00);
        } else {
            if (!(state->cur.key_presence & HAS_REDEEMSCRIPT)) {
                // P2PKH, the script_code is the prevout's scriptPubKey
                crypto_hash_update_varint(&sighash_context.header,
                                          state->cur.in_out.scriptPubKey_len);
                crypto_hash_update(&sighash_context.header,
                                   state->cur.in_out.scriptPubKey,
                                   state->cur.in_out.scriptPubKey_len);
            } else {
                // P2SH, the script_code is the redeemScript

                // update sighash_context with the length-prefixed redeem script
                int redeemScript_len =
                    update_hashes_with_map_value(dc,
                                                 &state->cur.in_out.map,
                                                 (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                                 1,
                                                 NULL,
                                                 &sighash_context.header);

                if (redeemScript_len < 0) {
                    PRINTF("Error fetching redeemScript\n");
                    SEND_SW(dc, SW_INCORRECT_DATA);
                    return;
                }
            }
        }

        uint8_t ith_nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &ith_map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               ith_nSequence_raw,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(ith_nSequence_raw, 0xFF, 4);
        }

        crypto_hash_update(&sighash_context.header, ith_nSequence_raw, 4);
    }

    // outputs
    crypto_hash_update_varint(&sighash_context.header, state->n_outputs);
    if (hash_outputs(dc, &sighash_context.header, NULL) == -1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // nLocktime
    write_u32_le(tmp, 0, state->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // hash type
    write_u32_le(tmp, 0, state->cur.input.sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, state->sighash, 32);
    cx_hash_sha256(state->sighash, 32, state->sighash, 32);

    dc->next(sign_sighash_ecdsa);
}

static void sign_segwit(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);
    PRINT_STACK_POINTER();

    int segwit_version;

    {
        tx_amount_t amount;
        if (0 > parse_utxo_witness(dc,
                                   &state->cur.in_out.map,
                                   NULL, /* asset */
                                   &amount,
                                   state->cur.in_out.scriptPubKey,
                                   &state->cur.in_out.scriptPubKey_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if(!set_in_out_amount(&state->cur, &amount)) {
            PRINTF("Amount in witness utxo doesn't match externally provided one\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        if(!(state->cur.key_read_status & HAS_PREVOUT_AMOUNT)) {
            PRINTF("Non-blinded amount is not provided for input %u\n", state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        state->inputs_total_value += state->cur.in_out.value;

        if (state->cur.key_presence & HAS_REDEEMSCRIPT) {
            // Get redeemScript
            uint8_t redeemScript[64];

            int redeemScript_length =
                call_get_merkleized_map_value(dc,
                                              &state->cur.in_out.map,
                                              (uint8_t[]){PSBT_IN_REDEEM_SCRIPT},
                                              1,
                                              redeemScript,
                                              sizeof(redeemScript));
            if (redeemScript_length < 0) {
                PRINTF("Error fetching redeem script\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            uint8_t p2sh_redeemscript[2 + 20 + 1];
            p2sh_redeemscript[0] = 0xa9;
            p2sh_redeemscript[1] = 0x14;
            crypto_hash160(redeemScript, redeemScript_length, p2sh_redeemscript + 2);
            p2sh_redeemscript[22] = 0x87;

            if (state->cur.in_out.scriptPubKey_len != 23 ||
                memcmp(state->cur.in_out.scriptPubKey, p2sh_redeemscript, 23) != 0) {
                PRINTF("witnessUtxo's scriptPubKey does not match redeemScript\n");
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            if (redeemScript_length <= (int)sizeof(state->cur.input.script)) {
                state->cur.input.script_len = redeemScript_length;
                memcpy(state->cur.input.script, redeemScript, redeemScript_length);
            } else {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
            segwit_version = get_segwit_version(redeemScript, redeemScript_length);
        } else {
            if (state->cur.in_out.scriptPubKey_len <= sizeof(state->cur.input.script)) {
                state->cur.input.script_len = state->cur.in_out.scriptPubKey_len;
                memcpy(state->cur.input.script,
                    state->cur.in_out.scriptPubKey,
                    state->cur.in_out.scriptPubKey_len);
            } else {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }

            segwit_version = get_segwit_version(state->cur.in_out.scriptPubKey,
                                                state->cur.in_out.scriptPubKey_len);
        }

        if (segwit_version > 1) {
            PRINTF("Segwit version not supported: %d\n", segwit_version);
            SEND_SW(dc, SW_NOT_SUPPORTED);
            return;
        }
    }

    if (segwit_version == 0) {
        dc->next(sign_segwit_v0);
        return;
    } else if (segwit_version == 1) {
        dc->next(sign_segwit_v1);

        return;
    }

    SEND_SW(dc, SW_BAD_STATE);  // can't happen
    return;
}

static void sign_segwit_v0(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    bool sighash_anyonecanpay = !!(state->cur.input.sighash_type & SIGHASH_ANYONECANPAY);
    bool sighash_rangeproof = !!(state->cur.input.sighash_type & SIGHASH_RANGEPROOF);
    uint32_t sighash_base = state->cur.input.sighash_type &
                            ~(SIGHASH_ANYONECANPAY | SIGHASH_RANGEPROOF);

    if (sighash_base != SIGHASH_ALL && sighash_base != SIGHASH_NONE &&
        sighash_base != SIGHASH_SINGLE ) {
        PRINTF("Invalid SIGHASH type");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    cx_sha256_t sighash_context;
    cx_sha256_init(&sighash_context);

    uint8_t tmp[9];

    // nVersion
    write_u32_le(tmp, 0, state->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    PRINT_HASH("version", &sighash_context);

    if (sighash_anyonecanpay) {
        crypto_hash_update_zeros(&sighash_context.header, 32);
    } else {
        // add to hash: hashPrevouts = sha256(sha_prevouts)
        uint8_t dbl_hash[32];
        cx_hash_sha256(state->hashes.sha_prevouts, 32, dbl_hash, 32);
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);
    }

    PRINT_HASH("prevouts", &sighash_context);

    if (sighash_anyonecanpay || sighash_base == SIGHASH_NONE || sighash_base == SIGHASH_SINGLE) {
        crypto_hash_update_zeros(&sighash_context.header, 32);
    } else {
        // add to hash: hashSequence sha256(sha_sequences)
        uint8_t dbl_hash[32];
        cx_hash_sha256(state->hashes.sha_sequences, 32, dbl_hash, 32);
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);
    }

    PRINT_HASH("sequences", &sighash_context);

    if (sighash_anyonecanpay) {
        crypto_hash_update_zeros(&sighash_context.header, 32);
    } else {
        // add to hash: hashIssuance sha256(sha_issuances)
        uint8_t dbl_hash[32];
        cx_hash_sha256(state->hashes.sha_issuances, 32, dbl_hash, 32);
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);
    }

    PRINT_HASH("issuances", &sighash_context);

    {
        // outpoint (32-byte prevout hash, 4-byte index)

        // get prevout hash and output index for the current input
        uint8_t prevout_hash[32];
        if (32 != call_get_merkleized_map_value(dc,
                                                &state->cur.in_out.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                prevout_hash,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header, prevout_hash, 32);

        PRINT_HASH("txid", &sighash_context);

        uint8_t prevout_n_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &state->cur.in_out.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               prevout_n_raw,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        crypto_hash_update(&sighash_context.header, prevout_n_raw, 4);
        PRINT_HASH("vout", &sighash_context);
    }

    // scriptCode
    if (is_p2wpkh(state->cur.input.script, state->cur.input.script_len)) {
        // P2WPKH(script[2:22])
        crypto_hash_update_u32(&sighash_context.header, 0x1976a914);
        crypto_hash_update(&sighash_context.header, state->cur.input.script + 2, 20);
        crypto_hash_update_u16(&sighash_context.header, 0x88ac);
    } else if (is_p2wsh(state->cur.input.script, state->cur.input.script_len)) {
        // P2WSH

        // update sighash_context.header with the length-prefixed witnessScript,
        // and also compute sha256(witnessScript)
        cx_sha256_t witnessScript_hash_context;
        cx_sha256_init(&witnessScript_hash_context);

        int witnessScript_len = update_hashes_with_map_value(dc,
                                                             &state->cur.in_out.map,
                                                             (uint8_t[]){PSBT_IN_WITNESS_SCRIPT},
                                                             1,
                                                             &witnessScript_hash_context.header,
                                                             &sighash_context.header);

        if (witnessScript_len < 0) {
            PRINTF("Error fetching witnessScript\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t witnessScript_hash[32];
        crypto_hash_digest(&witnessScript_hash_context.header, witnessScript_hash, 32);

        // check that script == P2WSH(witnessScript)
        if (state->cur.input.script_len != 2 + 32 || state->cur.input.script[0] != 0x00 ||
            state->cur.input.script[1] != 0x20 ||
            memcmp(state->cur.input.script + 2, witnessScript_hash, 32) != 0) {
            PRINTF("Mismatching witnessScript\n");

            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    } else {
        PRINTF("Invalid or unsupported script in segwit transaction\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    PRINT_HASH("pubkey", &sighash_context);

    // amount or amount commitment
    {
        txid_parser_vout_t parser_output;
        int res = call_pset_parse_rawtx_single_output(dc,
                                                    &state->cur.in_out.map,
                                                    (uint8_t[]){PSBT_IN_WITNESS_UTXO},
                                                    1,
                                                    &parser_output,
                                                    NULL);

        if (res < 0) {
            PRINTF("Parsing witness UTXO failed\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if(parser_output.amount.is_blinded) {
            crypto_hash_update(&sighash_context.header,
                               parser_output.amount.commitment,
                               sizeof(parser_output.amount.commitment));
        } else {
            tmp[0] = 0x01;
            write_u64_be(tmp, 1, parser_output.amount.value);
            crypto_hash_update(&sighash_context.header, tmp, 9);
        }
    }
    PRINT_HASH("value", &sighash_context);

    // nSequence
    {
        uint8_t nSequence_raw[4];
        if (4 != call_get_merkleized_map_value(dc,
                                               &state->cur.in_out.map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               nSequence_raw,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(nSequence_raw, 0xFF, 4);
        }
        crypto_hash_update(&sighash_context.header, nSequence_raw, 4);
    }
    PRINT_HASH("sequence", &sighash_context);

    if (input_has_issuance(state->cur.key_presence)) {
        if (!hash_input_issuance(dc,
                                 &state->cur.in_out.map,
                                 state->cur.key_presence,
                                 &sighash_context.header)) {
            PRINTF("Hashing input issuance information failed\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }
    PRINT_HASH("issuance", &sighash_context);

    if (sighash_base != SIGHASH_NONE && sighash_base != SIGHASH_SINGLE) {
        // compute hashOutputs = sha256(sha_outputs)
        uint8_t dbl_hash[32];
        cx_hash_sha256(state->hashes.sha_outputs, 32, dbl_hash, 32);
        crypto_hash_update(&sighash_context.header, dbl_hash, 32);

        PRINT_HASH("outputs", &sighash_context);
        // compute hashRangeproofs = sha256(sha_rangeproofs)
        if (sighash_rangeproof) {
            cx_hash_sha256(state->hashes.sha_rangeproofs, 32, dbl_hash, 32);
            crypto_hash_update(&sighash_context.header, dbl_hash, 32);
        }
    } else if (sighash_base == SIGHASH_SINGLE) {
        if(state->cur_input_index >= state->n_outputs) {
            PRINTF("SIGHASH_SINGLE: corresponding output is missing for input %u\n",
                   state->cur_input_index);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t hash[32];
        union {
            cx_sha256_t sha_output;
            cx_sha256_t sha_rangeproof;
            uint8_t dbl_hash[32];
        } t;

        // hash single output
        {
            cx_sha256_init(&t.sha_output);
            int res = hash_output(dc,
                                  state->cur_input_index,
                                  &t.sha_output.header,
                                  NULL);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
            crypto_hash_digest(&t.sha_output.header, hash, sizeof(hash));
            cx_hash_sha256(hash, sizeof(hash), t.dbl_hash, sizeof(t.dbl_hash));
            crypto_hash_update(&sighash_context.header, t.dbl_hash, sizeof(t.dbl_hash));
        }

        PRINT_HASH("outputs", &sighash_context);

        // hash range proof of the single output
        if (sighash_rangeproof) {
            cx_sha256_init(&t.sha_rangeproof);
            int res = hash_output(dc,
                                  state->cur_input_index,
                                  NULL,
                                  &t.sha_rangeproof.header);
            if (res < 0) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return;
            }
            crypto_hash_digest(&t.sha_rangeproof.header, hash, sizeof(hash));
            cx_hash_sha256(hash, sizeof(hash), t.dbl_hash, sizeof(t.dbl_hash));
            crypto_hash_update(&sighash_context.header, t.dbl_hash, sizeof(t.dbl_hash));
        }
    } else {
        crypto_hash_update_zeros(&sighash_context.header, sighash_rangeproof ? 64 : 32);
    }
    PRINT_HASH("rangeproofs", &sighash_context);

    // nLocktime
    write_u32_le(tmp, 0, state->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    PRINT_HASH("locktime", &sighash_context);

    // sighash type
    write_u32_le(tmp, 0, state->cur.input.sighash_type);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    PRINT_HASH("sighasg_type", &sighash_context);

    // compute sighash
    crypto_hash_digest(&sighash_context.header, state->sighash, 32);
    cx_hash_sha256(state->sighash, 32, state->sighash, 32);

    dc->next(sign_sighash_ecdsa);
}

// TODO: modify for Liquid Network
static void sign_segwit_v1(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_sha256_t sighash_context;
    crypto_tr_tagged_hash_init(&sighash_context, BIP0341_sighash_tag, sizeof(BIP0341_sighash_tag));
    // the first 0x00 byte is not part of SigMsg
    crypto_hash_update_u8(&sighash_context.header, 0x00);

    uint8_t tmp[32];

    // hash type
    uint8_t sighash_byte = (uint8_t) (state->cur.input.sighash_type & 0xFF);
    crypto_hash_update_u8(&sighash_context.header, sighash_byte);

    // nVersion
    write_u32_le(tmp, 0, state->tx_version);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    // nLocktime
    write_u32_le(tmp, 0, state->locktime);
    crypto_hash_update(&sighash_context.header, tmp, 4);

    if ((sighash_byte & 0x80) != SIGHASH_ANYONECANPAY) {
        crypto_hash_update(&sighash_context.header, state->hashes.sha_prevouts, 32);
        crypto_hash_update(&sighash_context.header, state->hashes.sha_amounts, 32);
        crypto_hash_update(&sighash_context.header, state->hashes.sha_scriptpubkeys, 32);
        crypto_hash_update(&sighash_context.header, state->hashes.sha_sequences, 32);
    }

    if ((sighash_byte & 3) != SIGHASH_NONE && (sighash_byte & 3) != SIGHASH_SINGLE) {
        crypto_hash_update(&sighash_context.header, state->hashes.sha_outputs, 32);
    }

    // annex and ext_flags not supported, so spend_type = 0
    crypto_hash_update_u8(&sighash_context.header, 0x00);

    if ((sighash_byte & 0x80) == SIGHASH_ANYONECANPAY) {
        // outpoint (hash)
        if (32 != call_get_merkleized_map_value(dc,
                                                &state->cur.in_out.map,
                                                (uint8_t[]){PSBT_IN_PREVIOUS_TXID},
                                                1,
                                                tmp,
                                                32)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        crypto_hash_update(&sighash_context.header, tmp, 32);

        // outpoint (output index)
        if (4 != call_get_merkleized_map_value(dc,
                                               &state->cur.in_out.map,
                                               (uint8_t[]){PSBT_IN_OUTPUT_INDEX},
                                               1,
                                               tmp,
                                               4)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);

        // amount
        // TODO: add support of amount commitment
        write_u64_le(tmp, 0, state->cur.in_out.value);
        crypto_hash_update(&sighash_context.header, tmp, 8);

        // scriptPubKey
        crypto_hash_update(&sighash_context.header,
                           state->cur.in_out.scriptPubKey,
                           state->cur.in_out.scriptPubKey_len);

        // nSequence
        if (4 != call_get_merkleized_map_value(dc,
                                               &state->cur.in_out.map,
                                               (uint8_t[]){PSBT_IN_SEQUENCE},
                                               1,
                                               tmp,
                                               4)) {
            // if no PSBT_IN_SEQUENCE is present, we must assume nSequence 0xFFFFFFFF
            memset(tmp, 0xFF, 4);
        }
        crypto_hash_update(&sighash_context.header, tmp, 4);
    } else {
        // input_index
        write_u32_le(tmp, 0, state->cur_input_index);
        crypto_hash_update(&sighash_context.header, tmp, 4);
    }

    // no annex

    // TODO: SIGHASH_SINGLE not implemented

    crypto_hash_digest(&sighash_context.header, state->sighash, 32);

    dc->next(sign_sighash_schnorr);
}

// Common for legacy and segwitv0 transactions
static void sign_sighash_ecdsa(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (int i = 0; i < state->our_key_derivation_length; i++) {
        sign_path[i] = state->our_key_derivation[i];
    }
    sign_path[state->our_key_derivation_length] = state->cur.input.change;
    sign_path[state->our_key_derivation_length + 1] = state->cur.input.address_index;

    int sign_path_len = state->our_key_derivation_length + 2;

    uint8_t sig[MAX_DER_SIG_LEN];

    int sig_len =
        crypto_ecdsa_sign_sha256_hash_with_key(sign_path, sign_path_len, state->sighash, sig, NULL);
    if (sig_len < 0) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];
    int input_index_varint_len = varint_write(buf, 0, state->cur_input_index);
    dc->add_to_response(&buf, input_index_varint_len);

    dc->add_to_response(&sig, sig_len);
    uint8_t sighash_byte = (uint8_t) (state->cur.input.sighash_type & 0xFF);
    dc->add_to_response(&sighash_byte, 1);

    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    ++state->cur_input_index;
    dc->next(sign_process_input_map);
}

// Signing for segwitv1 (taproot)
static void sign_sighash_schnorr(dispatcher_context_t *dc) {
    sign_pset_state_t *state = (sign_pset_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_ecfp_private_key_t private_key = {0};
    uint8_t *seckey = private_key.d;  // convenience alias (entirely within the private_key struct)

    uint8_t chain_code[32] = {0};

    uint32_t sign_path[MAX_BIP32_PATH_STEPS];
    for (int i = 0; i < state->our_key_derivation_length; i++) {
        sign_path[i] = state->our_key_derivation[i];
    }
    sign_path[state->our_key_derivation_length] = state->cur.input.change;
    sign_path[state->our_key_derivation_length + 1] = state->cur.input.address_index;

    int sign_path_len = state->our_key_derivation_length + 2;

    uint8_t sig[64];
    size_t sig_len;

    volatile bool error = false;
    BEGIN_TRY {
        TRY {
            crypto_derive_private_key(&private_key, chain_code, sign_path, sign_path_len);
            crypto_tr_tweak_seckey(seckey);

            unsigned int err = cx_ecschnorr_sign_no_throw(&private_key,
                                                          CX_ECSCHNORR_BIP0340 | CX_RND_TRNG,
                                                          CX_SHA256,
                                                          state->sighash,
                                                          32,
                                                          sig,
                                                          &sig_len);
            if (err != CX_OK) {
                error = true;
            }
        }
        CATCH_ALL {
            error = true;
        }
        FINALLY {
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    if (error) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    if (sig_len != 64) {
        PRINTF("SIG LEN: %d\n", sig_len);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    // yield signature
    uint8_t cmd = CCMD_YIELD;
    dc->add_to_response(&cmd, 1);

    uint8_t buf[9];
    int input_index_varint_len = varint_write(buf, 0, state->cur_input_index);
    dc->add_to_response(&buf, input_index_varint_len);

    dc->add_to_response(&sig, sizeof(sig));

    // only append the sighash type byte if it is non-zero
    uint8_t sighash_byte = (uint8_t) (state->cur.input.sighash_type & 0xFF);
    if (sighash_byte != 0x00) {
        // only add the sighash byte if not 0
        dc->add_to_response(&sighash_byte, 1);
    }
    dc->finalize_response(SW_INTERRUPTED_EXECUTION);

    if (dc->process_interruption(dc) < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    ++state->cur_input_index;
    dc->next(sign_process_input_map);
}

static void finalize(dispatcher_context_t *dc) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Only if called from swap, the app should terminate after sending the response
    if (G_swap_state.called_from_swap) {
        G_swap_state.should_exit = true;
    }

    SEND_SW(dc, SW_OK);
}

#endif // HAVE_LIQUID