#pragma once

#include "cx.h"
#include "../common/bip32.h"
#include "../boilerplate/dispatcher.h"

/// State of SIGN_MESSAGE handler
typedef struct {
    /// Machine context for command dispatcher
    machine_context_t ctx;

    /// Number of derivation steps in BIP32 path
    uint8_t bip32_path_len;
    /// BIP32 path used for signing
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    /// The byte length of the message to sign
    uint64_t message_length;
    /// The Merkle root of the message
    uint8_t message_merkle_root[32];

    /// SHA-256 context used to compute sha256(message)
    cx_sha256_t msg_hash_context;
    /// SHA-256 context used to compute the Bitcoin Message Signing digest
    cx_sha256_t bsm_digest_context;

    /// SHA-256 hash of the message
    uint8_t message_hash[32];
    /// Computed Bitcoin Message Signing digest
    uint8_t bsm_digest[32];
} sign_message_state_t;

/**
 * Handles SIGN_MESSAGE command.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context.
 */
void handler_sign_message(dispatcher_context_t *dispatcher_context);
