#pragma once

#ifdef HAVE_LIQUID

#include "../boilerplate/dispatcher.h"
#include "../constants.h"
#include "../common/bitvector.h"
#include "../common/merkle.h"
#include "../common/wallet.h"
#include "../liquid/liquid.h"
#include "../liquid/liquid_assets.h"

#define MAX_N_INPUTS_CAN_SIGN 512
#define SIGN_PSET_SHA_CONTEXT_POOL_SIZE 3

// common info that applies to either the current input or the current output
typedef struct {
    merkleized_map_commitment_t map;

    uint8_t
        bip32_derivation_pubkey[33];  // the pubkey of the first PSBT_{IN,OUT}_BIP32_DERIVATION or
                                      // PSBT_{IN,OUT}_TAP_BIP32_DERIVATION key seen.
                                      // Could be 33 (legacy or segwitv0) or 32 bytes long
                                      // (taproot), based on the script type.

    // For an output, its scriptPubKey
    // for an input, the prevout's scriptPubKey (either from the non-witness-utxo, or from the
    // witness-utxo)

    uint8_t scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t scriptPubKey_len;
    uint64_t value;
    uint8_t value_commitment[33]; // value commitment of the current input or output
    uint8_t asset_commitment[33]; // asset commitment of the current input or output
    uint8_t asset_tag[32];
    const asset_definition_t *asset_info;
} in_out_info_t;

typedef struct {
    // the script used when signing, either from the witness utxo or the redeem script
    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    size_t script_len;

    uint32_t sighash_type;

    int change;
    int address_index;
} input_info_t;

typedef struct {
} output_info_t;

typedef struct  {
    in_out_info_t in_out;
    union {
        input_info_t input;
        output_info_t output;
    };
    uint32_t key_presence;
    uint32_t key_read_status;
} overlayed_in_out_info_t;

typedef struct {
    machine_context_t ctx;

    uint32_t tx_version;
    uint32_t locktime;

    unsigned int n_inputs;
    uint8_t inputs_root[32];  // merkle root of the vector of input maps commitments
    unsigned int n_outputs;
    uint8_t outputs_root[32];  // merkle root of the vector of output maps commitments

    bool is_wallet_canonical;
    int bip44_purpose;  // only relevant for canonical wallets

    uint8_t wallet_header_keys_info_merkle_root[32];
    size_t wallet_header_n_keys;

    uint32_t master_key_fingerprint;

    // bitmap to track of which inputs are internal
    uint8_t internal_inputs[BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)];

    union {
        unsigned int cur_input_index;
        unsigned int cur_output_index;
        unsigned int sha_context_index;
    };

    union {
        overlayed_in_out_info_t cur;
        // Pool of SHA256 contexts used in compute_segwit_hashes()
        cx_sha256_t sha_context_pool[SIGN_PSET_SHA_CONTEXT_POOL_SIZE];
    };

    uint8_t sighash[32];

    union {
        union {
            uint8_t map_bytes[MAX_POLICY_MAP_BYTES];
            policy_node_t map;
        } wallet_policy;
        struct {
            uint8_t sha_prevouts[32];
            uint8_t sha_amounts[32];
            uint8_t sha_scriptpubkeys[32];
            uint8_t sha_sequences[32];
            uint8_t sha_outputs[32];
            uint8_t sha_issuances[32];
            uint8_t sha_rangeproofs[32];
        } hashes;
    };
    const policy_node_t *wallet_policy_map_unwrapped;
    PolicyNodeType wallet_policy_root_type;

    uint64_t inputs_total_value;
    uint64_t outputs_total_value;

    uint64_t internal_inputs_total_value;

    uint64_t change_outputs_total_value;

    uint64_t fee_value;

    int external_outputs_count;  // count of external outputs that are shown to the user
    int change_count;            // count of outputs compatible with change outputs

    int our_key_derivation_length;
    uint32_t our_key_derivation[MAX_BIP32_PATH_STEPS];
} sign_pset_state_t;

void handler_liquid_sign_pset(dispatcher_context_t *dispatcher_context);

#endif // HAVE_LIQUID
