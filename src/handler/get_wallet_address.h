#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../common/wallet.h"
#include "../boilerplate/dispatcher.h"

#include "lib/get_merkle_leaf_element.h"

#ifdef HAVE_LIQUID
#include "../liquid/liquid.h"
#endif

/// State of GET_WALLET_ADDRESS handler
typedef struct {
    /// Machine context for command dispatcher
    machine_context_t ctx;

    /// Desired address index
    uint32_t address_index;
    /// Flag indicates change address if true
    uint8_t is_change;
    /// Flag enabling address display if true
    uint8_t display_address;

    /// Flag indicating that the wallet is canonical (doesn't need registration)
    bool is_wallet_canonical;
    /// Address type, one of ADDRESS_TYPE_* constants
    int address_type;

    // as deriving wallet addresses is stack-intensive, we move some
    // variables here to use less stack overall

    /// Wallet header with basic information from wallet policy
    policy_map_wallet_header_t wallet_header;

    /// Computed wallet identifier (hash)
    uint8_t computed_wallet_id[32];
    /// Received wallet identifier
    uint8_t wallet_id[32];
    /// The HMAC of a registered wallet
    uint8_t wallet_hmac[32];

    /// Root of a Merkle tree of the list of keys information
    uint8_t wallet_header_keys_info_merkle_root[32];
    /// Number of keys in wallet header
    size_t wallet_header_n_keys;

    union {
        /// Serialized wallet policy
        uint8_t serialized_wallet_policy[MAX_POLICY_MAP_SERIALIZED_LENGTH];
        /// Wallet policy map as array of bytes
        uint8_t wallet_policy_map_bytes[MAX_POLICY_MAP_BYTES];
        /// Wallet policy map as a structure
        policy_node_t wallet_policy_map;
    };

    /// Length of the address script
    int script_len;
    /// Address script
    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];

    /// Length of the address
    int address_len;
    /// Address, a null-terminated string
    char address[MAX_ADDRESS_LENGTH_STR + 1];

    /// Key information string
    uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];
#ifdef HAVE_LIQUID
    /// Flag indicating that the wallet policy has blinded tag
    bool is_blinded;
    /// Type of blinding key derivation
    liquid_blinding_key_type_t blinding_key_type;
    /// Master blinding key
    uint8_t master_blinding_key[32];
#endif
} get_wallet_address_state_t;

/**
 * Handles GET_WALLET_ADDRESS command.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context.
 */
void handler_get_wallet_address(dispatcher_context_t *dispatcher_context);
