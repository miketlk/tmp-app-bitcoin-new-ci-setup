#pragma once

#include <stdint.h>

#include "ledger_assert.h"

#include "common/bip32.h"
#include "common/buffer.h"
#include "common/wif.h"
#include "../constants.h"

#ifndef SKIP_FOR_CMOCKA
#include "os.h"
#include "cx.h"
#endif

/**
 * Wallet types
 */
/// Wallet type: policy map
#define WALLET_TYPE_POLICY_MAP 1

#ifdef HAVE_LIQUID
/// Maximum supported number of keys for a policy map.
#define MAX_POLICY_MAP_COSIGNERS 7
#else
/// Maximum supported number of keys for a policy map.
#define MAX_POLICY_MAP_COSIGNERS 5
#endif

/// Maximum supported number of keys for a policy map.
#define MAX_POLICY_MAP_KEYS MAX_POLICY_MAP_COSIGNERS

// The string describing a pubkey can contain:
// - (optional) the key origin info, which we limit to 46 bytes (2 + 8 + 3*12 = 46 bytes)
// - the xpub itself (up to 113 characters)
// - optional, the "/**" suffix.
// Therefore, the total length of the key info string is at most 162 bytes.
/// Maximum length of key information string
#define MAX_POLICY_KEY_INFO_LEN (46 + MAX_SERIALIZED_PUBKEY_LENGTH + 3)

#ifdef HAVE_LIQUID
/// Maximum length of blinding key descriptor (length of Base58-encoded xpub)
#define MAX_POLICY_MAP_BLINDING_KEY_LENGTH 112
// Enough to store "ct(<BLINDING_KEY>,sh(wsh(sortedmulti(15,@0,@1,...,@n))))"
/// Length of policy map string
#define MAX_POLICY_MAP_STR_LENGTH ( sizeof("ct(,sh(wsh(sortedmulti(15))))") - 1 + \
                                    MAX_POLICY_MAP_BLINDING_KEY_LENGTH + \
                                    4 * MAX_POLICY_MAP_COSIGNERS )
#else
// Enough to store "sh(wsh(sortedmulti(15,@0,@1,@2,@3,@4,@5,@6,@7,@8,@9,@10,@11,@12,@13,@14)))"
/// Length of policy map string
#define MAX_POLICY_MAP_STR_LENGTH 74
#endif

/// Maximum length of wallet policy
#define MAX_POLICY_MAP_NAME_LENGTH 16

// at most 126 bytes
// wallet type (1 byte)
// name length (1 byte)
// name (max MAX_POLICY_MAP_NAME_LENGTH bytes)
// policy length (1 byte)
// policy (max MAX_POLICY_MAP_STR_LENGTH bytes)
// n_keys (1 byte)
// keys_merkle_root (32 bytes)
/// Maximum length of serialized wallet policy
#define MAX_POLICY_MAP_SERIALIZED_LENGTH \
    (1 + 1 + MAX_POLICY_MAP_NAME_LENGTH + 1 + MAX_POLICY_MAP_STR_LENGTH + 1 + 32)

#ifdef HAVE_LIQUID
/// Maximum size of a parsed policy map in memory
#define MAX_POLICY_MAP_BYTES 208
#else
/// Maximum size of a parsed policy map in memory
#define MAX_POLICY_MAP_BYTES 128
#endif

// Currently only multisig is supported
/// Maximum length of wallet policy
#define MAX_POLICY_MAP_LEN MAX_MULTISIG_POLICY_MAP_LENGTH

/// Public key information
typedef struct {
    /// Derivation path from master key
    uint32_t master_key_derivation[MAX_BIP32_PATH_STEPS];
    /// Master key fingerprint
    uint8_t master_key_fingerprint[4];
    /// Length of derivation path, number of elements in master_key_derivation[]
    uint8_t master_key_derivation_len;
    /// Set to 1 if key has origin data: master key fingerprint and derivation path
    uint8_t has_key_origin;
    /// Set to 1 if key terminates with wildcard suffix: "/**"
    uint8_t has_wildcard;  // true iff the keys ends with the /** wildcard
    /// Serialized extended public key
    char ext_pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} policy_map_key_info_t;

/// Wallet header
typedef struct {
    /// Wallet type
    uint8_t type;  // Currently the only supported value is WALLET_TYPE_POLICY_MAP
    /// Length of wallet name
    uint8_t name_len;
    /// Wallet name
    char name[MAX_WALLET_NAME_LENGTH + 1];
    /// Length of wallet policy map
    uint16_t policy_map_len;
    /// Wallet policy map as a string
    char policy_map[MAX_POLICY_MAP_STR_LENGTH];
    /// Number of public keys
    size_t n_keys;
    /// /// Merkle root of the vector of key descriptors
    uint8_t keys_info_merkle_root[32];  // root of the Merkle tree of the keys information
} policy_map_wallet_header_t;

/// Type of policy node
typedef enum {
    TOKEN_SH,          ///< Pay to script hash
    TOKEN_WSH,         ///< Pay to witness script hash
    // TOKEN_PK,       //   disabled, but it will be needed for taproot
    TOKEN_PKH,         ///< Pay to public key hash
    TOKEN_WPKH,        ///< Pay to witness public key hash
    // TOKEN_COMBO     //   disabled, does not mix well with the script policy language
    TOKEN_MULTI,       ///< Multisig
    TOKEN_SORTEDMULTI, ///< Multisig with sorted keys
    TOKEN_TR,          ///< Taproot
    // TOKEN_ADDR,     //   unsupported
    // TOKEN_RAW,      //   unsupported
    TOKEN_CT,          ///< ELIP 150: confidential transaction top-level wrapper
    TOKEN_SLIP77,      ///< ELIP 150: SLIP-0077-derived master private blinding key
    TOKEN_HEX_PUB,     ///< ELIP 150: compressed public key, parsed from 66 hex string
    TOKEN_HEX_PRV,     ///< ELIP 150: private key, parsed from 64 hex string
    TOKEN_XPUB,        ///< ELIP 150: compressed public key, parsed from xpub
    TOKEN_XPRV,        ///< ELIP 150: private key, parsed from xprv
    TOKEN_ELIP151,     ///< ELIP 151: elip151 tag indicating ELIP 151 blinding key derivation
} PolicyNodeType;

// TODO: the following structures are using size_t for all integers to avoid alignment problems;
//       if memory is an issue, we could use a packed version instead, but care needs to be taken
//       when accessing pointers, since they would be unaligned.

/// Abstract type for all policy nodes
typedef struct {
    /// Type of this policy node
    PolicyNodeType type;
    /// Data specific to subtype
    void *node_data;  // subtypes will redefine this
} policy_node_t;

/// Policy node with script: sh(), wsh()
typedef struct {
    /// Type of this policy node
    PolicyNodeType type;  // == TOKEN_SH, == TOKEN_WSH
    /// Innder script
    policy_node_t *script;
} policy_node_with_script_t;

/// Policy node with key: pk(), pkh(), wpkh()
typedef struct {
    /// Type of this policy node
    PolicyNodeType type;  // == TOKEN_PK, == TOKEN_PKH, == TOKEN_WPKH
    /// Key index
    size_t key_index;     // index of the key
} policy_node_with_key_t;

/// Multisig policy node: multi(), sortedmulti()
typedef struct {
    /// Type of this policy node
    PolicyNodeType type;  // == TOKEN_MULTI, == TOKEN_SORTEDMULTI
    /// Threshold
    size_t k;
    /// Number of keys
    size_t n;
    /// Pointer to array of exactly n key indexes
    size_t *key_indexes;
} policy_node_multisig_t;

/// Policy node ct()
typedef struct {
    /// Type of this policy node
    PolicyNodeType type;        // == TOKEN_CT
    /// Master blinding key script, typically slip77()
    policy_node_t *mbk_script;
    /// Inner script
    policy_node_t *script;
} policy_node_ct_t;

/// Policy node containing ELIP 150 blinding public key
typedef struct {
    /// Type of this policy node, one of: TOKEN_HEX_PUB, TOKEN_XPUB
    PolicyNodeType type;
    /// Compressed public key
    uint8_t pubkey[33];
} policy_node_blinding_pubkey_t;

/// Policy node containing ELIP 150 blinding private key
typedef struct {
    /// Type of this policy node, one of: TOKEN_SLIP77, TOKEN_HEX_PRV, TOKEN_XPRV
    PolicyNodeType type;
    /// Private key
    uint8_t privkey[32];
} policy_node_blinding_privkey_t;

/**
 * Checks if the policy node has a private (blinding) key.
 *
 * @param[in] node
 *   Pointer to policy node.
 *
 * @return true if given policy node has a private blinding key, false otherwise.
 */
static inline bool policy_node_has_private_key(const policy_node_t *node) {
    return ( node->type == TOKEN_SLIP77 ||
             node->type == TOKEN_HEX_PRV ||
             node->type == TOKEN_XPRV );
}

/**
 * Checks if the policy node has a compressed public (blinding) key.
 *
 * @param[in] node
 *   Pointer to policy node.
 *
 * @return true if given policy node has a private blinding key, false otherwise.
 */
static inline bool policy_node_has_public_key(const policy_node_t *node) {
    return ( node->type == TOKEN_HEX_PUB ||
             node->type == TOKEN_XPUB );
}

/**
 * Reads wallet policy from buffer and decodes wallet header.
 *
 * @param[in,out] buffer
 *   Pointer to buffer storing serialized wallet policy.
 * @param[out] header
 *   Pointer to structure instance receiving decoded wallet header.
 *
 * @return 0 if successful, a negative number on error.
 */
int read_policy_map_wallet(buffer_t *buffer, policy_map_wallet_header_t *header);

/**
 * Parses a string representing the key information for a policy map wallet.
 *
 * The string is compatible with the output descriptor format, except that the pubkey must _not_
 * have derivation steps (the key origin info, if present, does have derivation steps from the
 * master key fingerprint). The serialized base58check-encoded pubkey is _not_ validated.
 *
 * For example:
 * "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
 *
 * @param[in,out] buffer
 *   Pointer to buffer storing serialized wallet policy.
 * @param[out] out
 *   Pointer to structure instance receiving parsed key information.
 *
 * @return 0 if successful, a negative number on error.
 */
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out);

/**
 * Parses a script expression from the input buffer.
 *
 * During parsing this function allocates the nodes and variables in the output buffer. The initial
 * pointer in output buffer will contain the root node of the script.
 *
 * @param[in,out] in_buf
 *   Input buffer with a script expression to parse.
 * @param[out] out
 *   Output buffer which receives a tree-like structure of nodes.
 * @param out_len
 *   Size of the output buffer.
 * @param bip32_pubkey_version
 *   Version prefix to use for the public key.
 * @param bip32_privkey_version
 *   Version prefix to use for the private key.
 *
 * @return 0 if successful, a negative number on error.
 */
int parse_policy_map(buffer_t *in_buf,
                     void *out,
                     size_t out_len,
                     uint32_t bip32_pubkey_version,
                     uint32_t bip32_privkey_version);

/**
 * Checks if the policy specifies a multisignature wallet.
 *
 * @param[in] policy
 *   Pointer to wallet's top-level policy node.
 *
 * @return true if the wallet is multisig, false otherwise.
 */
bool policy_is_multisig(const policy_node_t *policy);

#ifndef SKIP_FOR_CMOCKA

/**
 * Computes wallet identifier (sha256 of the serialization).
 *
 * @param[in] wallet_header
 *   Wallet header.
 * @param[out] out
 *   Output buffer receiving a computed 32-byte wallet identifier.
 */
void get_policy_wallet_id(const policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]);

/**
 * Validates the public key stored in key information for a policy map wallet.
 *
 * @param[in] key_info
 *   Key information.
 * @param bip32_pubkey_version
 *   Version prefix to use for the public key.
 *
 * @return true if key is valid, false otherwise.
 */
bool validate_policy_map_extended_pubkey(const policy_map_key_info_t *key_info,
                                         uint32_t bip32_pubkey_version);

#endif
