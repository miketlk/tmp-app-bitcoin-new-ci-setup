#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../common/wallet.h"
#include "../boilerplate/dispatcher.h"

#include "lib/get_merkle_leaf_element.h"

/// State of REGISTER_WALLET handler
typedef struct {
    /// Machine context for command dispatcher
    machine_context_t ctx;

    /// Wallet header with basic information from wallet policy
    policy_map_wallet_header_t wallet_header;

    /// Wallet identifier
    uint8_t wallet_id[32];
    union {
        /// Wallet policy map as array of bytes
        uint8_t policy_map_bytes[MAX_POLICY_MAP_BYTES];
        /// Wallet policy map as a structure
        policy_node_t policy_map;
    };
    /// Number of internal keys
    size_t n_internal_keys;
    /// Master key fingerprint
    uint32_t master_key_fingerprint;

    /// Zero-based public key index
    uint8_t next_pubkey_index;
    /// Public key information, a null-terminated string
    uint8_t next_pubkey_info[MAX_POLICY_KEY_INFO_LEN + 1];
} register_wallet_state_t;

/**
 * Handles REGISTER_WALLET command.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context.
 */
void handler_register_wallet(dispatcher_context_t *dispatcher_context);
