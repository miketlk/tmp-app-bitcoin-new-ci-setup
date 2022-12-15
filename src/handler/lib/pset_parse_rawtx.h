#pragma once

#ifdef HAVE_LIQUID

#include "cx.h"
#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../constants.h"

#ifndef RAWTX_DECODE_ECDH_PUBKEY
#define RAWTX_DECODE_ECDH_PUBKEY 0
#endif

typedef struct {
    bool is_blinded;   // true if value is blinded and stored as commitment[], otherwise as value
    union {
        uint64_t value;         // normal value of the output
        uint8_t commitment[33]; // amount commitment of a confidential output
    };
} tx_amount_t;

typedef struct {
    bool is_blinded;   // true if asset is blinded and stored as commitment[], otherwise as tag
    union {
        uint8_t tag[32];
        uint8_t commitment[33];
    };
} tx_asset_t;

typedef struct {
    tx_asset_t asset;
    tx_amount_t amount;
#if RAWTX_DECODE_ECDH_PUBKEY
    uint8_t ecdh_pubkey[33];        // ECDH public key of of the requested output
    bool ecdh_pubkey_valid;         // true if ECDH public key is valid
#endif
    unsigned int scriptpubkey_len;  // will contain the len of the scriptPubKey
    uint8_t scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];  // will contain the scriptPubKey
} txid_parser_vout_t;

typedef struct {
    txid_parser_vout_t vout; // will contain the information of the requested output
    uint8_t txid[32];        // will contain the computed txid
} txid_parser_outputs_t;

// TODO: document
/**
 * Given a commitment to a merkleized map and a key, this flow parses it as a serialized bitcoin
 * transaction, computes the transaction id and optionally keeps track of the vout amunt and
 * scriptPubkey of one of the outputs.
 */
int call_pset_parse_rawtx(dispatcher_context_t *dispatcher_context,
                          const merkleized_map_commitment_t *map,
                          const uint8_t *key,
                          int key_len,
                          int output_index,
                          txid_parser_outputs_t *outputs,
                          cx_sha256_t *issuance_hash_context);

// TODO: document
/**
 * Given a commitment to a merkleized map and a key, this flow parses it as a single output of
 * a serialized bitcoin transaction (typically UTXO) and saves results into provided structure.
 * Hashing is optional and disabled if 'hash_context' argument is NULL.
 */
int call_pset_parse_rawtx_single_output(dispatcher_context_t *dispatcher_context,
                                        const merkleized_map_commitment_t *map,
                                        const uint8_t *key,
                                        int key_len,
                                        txid_parser_vout_t *output,
                                        cx_sha256_t *hash_context);

#endif // HAVE_LIQUID
