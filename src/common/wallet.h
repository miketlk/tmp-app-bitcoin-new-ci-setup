#pragma once

#include <stdint.h>
#include <assert.h>

#include "ledger_assert.h"

#include "common/bip32.h"
#include "common/buffer.h"
#include "../constants.h"
#include "../crypto.h"

#ifndef SKIP_FOR_CMOCKA
#include "os.h"
#include "cx.h"
#endif

// The maximum number of keys supported for CHECKMULTISIG{VERIFY}
// bitcoin-core supports up to 20, but we limit to 16 as bigger pushes require special handling.
#define MAX_PUBKEYS_PER_MULTISIG 16

#define WALLET_POLICY_VERSION_V1 1  // the legacy version of the first release
#define WALLET_POLICY_VERSION_V2 2  // the current full version

// The string describing a pubkey can contain:
// - (optional) the key origin info, which we limit to 46 bytes (2 + 8 + 3*12 = 46 bytes)
// - the xpub itself (up to 113 characters)
// - optional, the "/**" suffix.
// Therefore, the total length of the key info string is at most 162 bytes.
#define MAX_POLICY_KEY_INFO_LEN_V1 (46 + MAX_SERIALIZED_PUBKEY_LENGTH + 3)

// In V1, there is no "/**" suffix, as that is no longer part of the key
#define MAX_POLICY_KEY_INFO_LEN_V2 (46 + MAX_SERIALIZED_PUBKEY_LENGTH)

#define MAX_POLICY_KEY_INFO_LEN MAX(MAX_POLICY_KEY_INFO_LEN_V1, MAX_POLICY_KEY_INFO_LEN_V2)

// longest supported policy in V1 is "sh(wsh(sortedmulti(5,@0,@1,@2,@3,@4)))", 38 bytes
#define MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1 40

#ifdef TARGET_NANOS
// this amount should be enough for many useful policies
#define MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2 192
// As the in-memory representation of wallet policy is implementation-specific, we would like
// this limit not to be hit for descriptor templates below the maximum length
// MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2.
// A policy requiring about 300 bytes after parsing was reported by developers working on the Liana
// miniscript wallet. 320 = 64*5, so that it is a multiple of the NVRAM page size and fits all known
// cases.
#define MAX_WALLET_POLICY_BYTES 320
#else
// On larger devices, we can afford to reserve a lot more memory.
// We do not expect these limits to be reached in practice any time soon, and the value
// of MAX_WALLET_POLICY_BYTES is chosen so that MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2 and
// MAX_WALLET_POLICY_BYTES are approximately in the same proportion as defined on NanoS.
#define MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2 512
#define MAX_WALLET_POLICY_BYTES           896
#endif

#define MAX_DESCRIPTOR_TEMPLATE_LENGTH \
    MAX(MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1, MAX_DESCRIPTOR_TEMPLATE_LENGTH_V2)

// at most 92 bytes
// wallet type (1 byte)
// name length (1 byte)
// name (max MAX_WALLET_NAME_LENGTH bytes)
// policy length (1 byte)
// policy (max MAX_DESCRIPTOR_TEMPLATE_LENGTH bytes)
// n_keys (1 byte)
// keys_merkle_root (32 bytes)
#define MAX_WALLET_POLICY_SERIALIZED_LENGTH_V1 \
    (1 + 1 + MAX_WALLET_NAME_LENGTH + 1 + MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1 + 1 + 32)

// at most 100 bytes
// wallet type (1 byte)
// name length (1 byte)
// name (max MAX_WALLET_NAME_LENGTH bytes)
// policy length (varint, up to 9 bytes)
// policy hash 32
// n_keys (varint, up to 9 bytes)
// keys_merkle_root (32 bytes)
#define MAX_WALLET_POLICY_SERIALIZED_LENGTH_V2 (1 + 1 + MAX_WALLET_NAME_LENGTH + 9 + 32 + 9 + 32)

#define MAX_WALLET_POLICY_SERIALIZED_LENGTH \
    MAX(MAX_WALLET_POLICY_SERIALIZED_LENGTH_V1, MAX_WALLET_POLICY_SERIALIZED_LENGTH_V2)

// maximum depth of a taproot tree that we support
// (here depth 1 means only the root of the taptree)
#ifdef TARGET_NANOS
#define MAX_TAPTREE_POLICY_DEPTH 4
#else
#define MAX_TAPTREE_POLICY_DEPTH 9
#endif

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
    /// Wildcard flag: true iff the keys ends with the wildcard (/ followed by **)
    uint8_t has_wildcard;
    /// Serialized extended public key
    serialized_extended_pubkey_t ext_pubkey;
} policy_map_key_info_t;

/// Wallet header
typedef struct {
    // Policy version, supported values: WALLET_POLICY_VERSION_V1 and WALLET_POLICY_VERSION_V2
    uint8_t version;
    /// Length of wallet name
    uint8_t name_len;
    /// Length of descriptor template
    uint16_t descriptor_template_len;
    /// Wallet name
    char name[MAX_WALLET_NAME_LENGTH + 1];
    union {
        /// Descriptor template
        char descriptor_template[MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1];  // used in V1
        /// Hash of descriptor template
        uint8_t descriptor_template_sha256[32];  // used in V2
    };
    /// Number of public keys
    size_t n_keys;
    /// Root of the Merkle tree of the keys information
    uint8_t keys_info_merkle_root[32];
} policy_map_wallet_header_t;

/// Type of policy node
typedef enum {
    TOKEN_SH,
    TOKEN_WSH,
    TOKEN_PK,
    TOKEN_PKH,
    TOKEN_WPKH,
    // TOKEN_COMBO     // disabled, does not mix well with the script policy language
    TOKEN_MULTI,
    TOKEN_MULTI_A,
    TOKEN_SORTEDMULTI,
    TOKEN_SORTEDMULTI_A,
    TOKEN_TR,
// TOKEN_ADDR,     // unsupported
// TOKEN_RAW,      // unsupported

#ifdef HAVE_LIQUID
    TOKEN_CT,       ///< ELIP 150: confidential transaction top-level wrapper
    TOKEN_SLIP77,   ///< ELIP 150: SLIP-0077-derived master private blinding key
    TOKEN_HEX_PUB,  ///< ELIP 150: compressed public key, parsed from 66 hex string
    TOKEN_HEX_PRV,  ///< ELIP 150: private key, parsed from 64 hex string
    TOKEN_XPUB,     ///< ELIP 150: compressed public key, parsed from xpub
    TOKEN_XPRV,     ///< ELIP 150: private key, parsed from xprv
    TOKEN_ELIP151,  ///< ELIP 151: elip151 tag indicating ELIP 151 blinding key derivation
#endif

    /* miniscript tokens */

    TOKEN_0,
    TOKEN_1,
    TOKEN_PK_K,
    TOKEN_PK_H,
    TOKEN_OLDER,
    TOKEN_AFTER,
    TOKEN_SHA256,
    TOKEN_HASH256,
    TOKEN_RIPEMD160,
    TOKEN_HASH160,
    TOKEN_ANDOR,
    TOKEN_AND_V,
    TOKEN_AND_B,
    TOKEN_AND_N,
    TOKEN_OR_B,
    TOKEN_OR_C,
    TOKEN_OR_D,
    TOKEN_OR_I,
    TOKEN_THRESH,
    // wrappers
    TOKEN_A,
    TOKEN_S,
    TOKEN_C,
    TOKEN_T,
    TOKEN_D,
    TOKEN_V,
    TOKEN_J,
    TOKEN_N,
    TOKEN_L,
    TOKEN_U,

    TOKEN_INVALID = -1  // used to mark invalid tokens
} PolicyNodeType;

typedef enum {
    MINISCRIPT_CONTEXT_P2WSH,
    MINISCRIPT_CONTEXT_TAPSCRIPT,
} MiniscriptContext;

// miniscript basic types
#define MINISCRIPT_TYPE_B 0
#define MINISCRIPT_TYPE_V 1
#define MINISCRIPT_TYPE_K 2
#define MINISCRIPT_TYPE_W 3

// The various structures used to represent the wallet policy abstract syntax tree contain a lot
// pointers; using a regular pointer would make each of them 4 bytes long, moreover causing
// additional loss of memory due to padding. Instead, we use a 2-bytes relative pointer to point to
// policy_nodes, representing a non-negative offset from the position of the structure itself.
// This reduces the memory utilization of those pointers, and moreover it allows to reduce padding
// in other structures, as they no longer contain 32-bit pointers.
// Moreover, avoiding all pointers makes sure that the structure can be copied to a different
// location if needed (making sure the destination is aligned due to the platform restrictions).
// The following macro defines the data structure and the helper methods for a relative pointer to a
// type. The code does not depend on the type, but this allows to keep strong types when dealing
// with relative pointers, which otherwise would require numerous type casts.

// Defines a relative pointer type for name##t, and the conversion functions to/from a relative
// pointer and a pointer to name##_t.
// Relative pointers use an uint16_t to represent the offset; therefore, the offset must be
// non-negative and at most 65535.
// An offset of 0 corresponds to a NULL pointer in the conversion (and vice-versa).
#define DEFINE_REL_PTR(name, type)                                                               \
    /*                                                                                           \
     * Relative pointer structure for `type`.                                                    \
     *                                                                                           \
     * This structure holds an offset that is used to calculate the actual pointer               \
     * to a `type` object.                                                                       \
     */                                                                                          \
    typedef struct rptr_##name##_s {                                                             \
        uint16_t offset;                                                                         \
    } rptr_##name##_t;                                                                           \
                                                                                                 \
    /*                                                                                           \
     * Resolve a relative pointer to a `type` object.                                            \
     *                                                                                           \
     * @param ptr A pointer to the relative pointer structure.                                   \
     * @return A pointer to the `type` object.                                                   \
     */                                                                                          \
    static inline type *r_##name(const rptr_##name##_t *ptr) {                                   \
        if (ptr->offset == 0)                                                                    \
            return NULL;                                                                         \
        else                                                                                     \
            return (type *) ((const uint8_t *) ptr + ptr->offset);                               \
    }                                                                                            \
                                                                                                 \
    /*                                                                                           \
     * Returns true when the offset of the relative pointer is 0 (equivalent to a NULL pointer). \
     *                                                                                           \
     * @param relative_ptr A relative pointer.                                                   \
     */                                                                                          \
    static inline bool isnull_##name(const rptr_##name##_t *ptr) {                               \
        return ptr->offset == 0;                                                                 \
    }                                                                                            \
                                                                                                 \
    /*                                                                                           \
     * Initialize a relative pointer to a `type` object.                                         \
     *                                                                                           \
     * @param relative_ptr A pointer to the relative pointer structure to be initialized.        \
     * @param obj A pointer to the `type` object.                                                \
     */                                                                                          \
    static inline void i_##name(rptr_##name##_t *relative_ptr, void *obj) {                      \
        if (obj == NULL)                                                                         \
            relative_ptr->offset = 0;                                                            \
        else {                                                                                   \
            int offset = (uint8_t *) obj - (uint8_t *) relative_ptr;                             \
            LEDGER_ASSERT(offset >= 0 && offset < UINT16_MAX,                                    \
                          "Relative pointer's offset must be between 0 and 65535");              \
            relative_ptr->offset = (uint16_t) offset;                                            \
        }                                                                                        \
    }

// 2 bytes
typedef struct policy_node_s {
    PolicyNodeType type;
    struct {
        unsigned int is_miniscript : 1;
        unsigned int miniscript_type : 2;  // B, C, K or W
        unsigned int miniscript_mod_z : 1;
        unsigned int miniscript_mod_o : 1;
        unsigned int miniscript_mod_n : 1;
        unsigned int miniscript_mod_d : 1;
        unsigned int miniscript_mod_u : 1;
    } flags;  // 1 byte
} policy_node_t;

DEFINE_REL_PTR(policy_node, policy_node_t)

typedef struct miniscript_ops_s {
    uint16_t count;  // non-push opcodes
    int16_t sat;     // number of keys in possibly executed OP_CHECKMULTISIG(VERIFY)s to satisfy (-1
                     // for "invalid")
    int16_t dsat;    // number of keys in possibly executed OP_CHECKMULTISIG(VERIFY)s to dissatisfy
                     // (-1 for "invalid")
} miniscript_ops_t;

typedef struct miniscript_stacksize_s {
    int16_t sat;   // Maximum stack size to satisfy
    int16_t dsat;  // Maximum stack size to dissatisfy
} miniscript_stacksize_t;

typedef struct policy_node_ext_info_s {
    miniscript_ops_t ops;
    miniscript_stacksize_t ss;
    uint16_t script_size;

    unsigned int s : 1;  // has a signature

    unsigned int f : 1;  // forced
    unsigned int e : 1;

    unsigned int m : 1;  // non-malleable property

    // flags related to timelocks
    unsigned int g : 1;  // older: contains relative time timelock   (csv_time)
    unsigned int h : 1;  // older: contains relative height timelock (csv_height)
    unsigned int i : 1;  // after: contains time timelock   (cltv_time)
    unsigned int j : 1;  // after: contains height timelock (cltv_height)
    unsigned int k : 1;  // does not contain a combination of height and time locks

    unsigned int x : 1;  // the last opcode is not EQUAL, CHECKSIG, or CHECKMULTISIG
} policy_node_ext_info_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
// The compiler doesn't like /** inside a block comment, so we disable this warning temporarily.

/** Structure representing a key placeholder.
 * In V1, it's the index of a key expression in the key informations array, which includes the final
 * / ** step.
 * In V2, it's the index of a key expression in the key informations array, plus the two
 * numbers a, b in the /<NUM_a;NUM_b>/* derivation steps; here, the xpubs in the key informations
 * array don't have extra derivation steps.
 */
#pragma GCC diagnostic pop
// 12 bytes
typedef struct {
    // the following fields are only used in V2
    uint32_t num_first;   // NUM_a of /<NUM_a,NUM_b>/*
    uint32_t num_second;  // NUM_b of /<NUM_a,NUM_b>/*

    // common between V1 and V2
    int16_t key_index;  // index of the key
} policy_node_key_placeholder_t;

DEFINE_REL_PTR(policy_node_key_placeholder, policy_node_key_placeholder_t)

// 4 bytes
typedef struct {
    struct policy_node_s base;
} policy_node_constant_t;

// 4 bytes
typedef struct {
    struct policy_node_s base;
    rptr_policy_node_t script;
} policy_node_with_script_t;

// 6 bytes
typedef struct {
    struct policy_node_s base;
    rptr_policy_node_t scripts[2];
} policy_node_with_script2_t;

// 8 bytes
typedef struct {
    struct policy_node_s base;
    rptr_policy_node_t scripts[3];
} policy_node_with_script3_t;

// generic type with pointer for up to 3 (but constant) number of child scripts
typedef policy_node_with_script3_t policy_node_with_scripts_t;

// 4 bytes
typedef struct {
    struct policy_node_s base;
    rptr_policy_node_key_placeholder_t key_placeholder;
} policy_node_with_key_t;

// 8 bytes
typedef struct {
    struct policy_node_s base;
    uint32_t n;
} policy_node_with_uint32_t;

// 12 bytes
typedef struct {
    struct policy_node_s base;  // type is TOKEN_MULTI or TOKEN_SORTEDMULTI
    int16_t k;                  // threshold
    int16_t n;                  // number of keys
    rptr_policy_node_key_placeholder_t
        key_placeholders;  // pointer to array of exactly n key placeholders
} policy_node_multisig_t;

// 8 bytes
struct policy_node_scriptlist_s;  // forward declaration, as the struct is recursive

DEFINE_REL_PTR(policy_node_scriptlist, struct policy_node_scriptlist_s)

typedef struct policy_node_scriptlist_s {
    rptr_policy_node_scriptlist_t next;
    rptr_policy_node_t script;
} policy_node_scriptlist_t;

// 12 bytes, (+ 8 bytes for every script)
typedef struct {
    struct policy_node_s base;  // type is TOKEN_THRESH
    int16_t k;                  // threshold
    int16_t n;                  // number of child scripts
    rptr_policy_node_scriptlist_t
        scriptlist;  // pointer to array of exactly n pointers to child scripts
} policy_node_thresh_t;

typedef struct {
    struct policy_node_s base;  // type is TOKEN_SHA160 or TOKEN_HASH160
    uint8_t h[20];
} policy_node_with_hash_160_t;

typedef struct {
    struct policy_node_s base;  // type is TOKEN_SHA256 or TOKEN_HASH256
    uint8_t h[32];
} policy_node_with_hash_256_t;

struct policy_node_tree_s;  // forward declaration, as the struct is recursive
DEFINE_REL_PTR(policy_node_tree, struct policy_node_tree_s)

// a TREE is either a script, or a {TREE,TREE}
typedef struct policy_node_tree_s {
    bool is_leaf;  // if this is a leaf, then it contains a pointer to a SCRIPT;
                   // otherwise, it contains two pointers to TREE expressions.
    union {
        rptr_policy_node_t script;  // pointer to a policy_node_with_script_t
        struct {
            rptr_policy_node_tree_t left_tree;   // pointer to a policy_node_tree_s
            rptr_policy_node_tree_t right_tree;  // pointer to a policy_node_tree_s
        };
    };
} policy_node_tree_t;

typedef struct {
    struct policy_node_s base;
    rptr_policy_node_key_placeholder_t key_placeholder;
    rptr_policy_node_tree_t tree;  // NULL if tr(KP)
} policy_node_tr_t;

/**
 * Parses the string in the `buffer` as a serialized policy map into `header`
 *
 * @param buffer the pointer to the buffer_t to parse
 * @param header the pointer to a `policy_map_wallet_header_t` structure
 * @return a negative number on failure, 0 on success.
 */
int read_wallet_policy_header(buffer_t *buffer, policy_map_wallet_header_t *header);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
// The compiler doesn't like /** inside a block comment, so we disable this warning temporarily.

/**
 * Parses a string representing the key information for a policy map wallet.
 * The string is compatible with the output descriptor format, except that the pubkey must _not_
 * have derivation steps (the key origin info, if present, does have derivation steps from the
 * master key fingerprint). The serialized base58check-encoded pubkey is _not_ validated.
 *
 * For WALLET_POLICY_VERSION_V1, the final suffix /** must be present and is part of the key
 * information. For WALLET_POLICY_VERSION_V2, parsing stops at the xpub.

 * Example (V1):
 * "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/**"
 * Example (V2):
 * "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
 */
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out, int version);

#pragma GCC diagnostic pop

/**
 * Parses `in_buf` as a wallet policy descriptor template, constructing the abstract syntax tree in
 * the buffer `out` of size `out_len`.
 *
 * When parsing descriptors containing miniscript, this fails if the miniscript is not correct,
 * as defined by the miniscript type system.
 * This does NOT check non-malleability of the miniscript.
 * @param in_buf the buffer containing the policy map to parse
 * @param out the pointer to the output buffer, which must be 4-byte aligned
 * @param out_len the length of the output buffer
 * @param version either WALLET_POLICY_VERSION_V1 or WALLET_POLICY_VERSION_V2
 * @return The memory size of the parsed descriptor template (that is, the number of bytes consumed
 * in the output buffer) on success; -1 in case of parsing error, if the output buffer is unaligned,
 * or if the output buffer is too small.
 */
int parse_descriptor_template(buffer_t *in_buf, void *out, size_t out_len, int version);

/**
 * Given a valid policy that the bitcoin app is able to sign, returns the segwit version.
 * The result is undefined for a node that is not a valid root of a wallet policy that the bitcoin
 * app is able to sign.
 *
 * @param policy the root node of the wallet policy
 * @return -1 if it's a legacy policy, 0 if it is a policy for SegwitV0 (possibly nested), 1 for
 * SegwitV1 (taproot).
 */
int get_policy_segwit_version(const policy_node_t *policy);

/**
 * Computes additional properties of the given miniscript, to detect malleability and other security
 * properties to assess if the miniscript is sane.
 * The stack size limits are only valid for miniscript within wsh.
 *
 * @param policy_node a pointer to a miniscript policy node
 * @param out pointer to the output policy_node_ext_info_t
 * @param ctx either MINISCRIPT_CONTEXT_P2WSH or MINISCRIPT_CONTEXT_TAPSCRIPT
 * @return a negative number on error; 0 on success.
 */
int compute_miniscript_policy_ext_info(const policy_node_t *policy_node,
                                       policy_node_ext_info_t *out,
                                       MiniscriptContext ctx);

#ifndef SKIP_FOR_CMOCKA

/**
 * Computes the id of the policy map wallet (commitment to header + policy map + keys_info), as per
 * specifications.
 *
 * @param wallet_header
 * @param out a pointer to a 32-byte array for the output
 */
void get_policy_wallet_id(policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]);

#endif

#ifdef HAVE_LIQUID

/**
 * Checks if key placeholder is empty (the key is not intended for derivation).
 *
 * @param[in] placeholder
 *   Pointer to key placeholder structure to check.
 * @return true if the given key placeholder is empty, false otherwise.
 */
static inline bool policy_is_key_placeholder_empty(
    const policy_node_key_placeholder_t *placeholder) {
    return placeholder->num_first == UINT32_MAX && placeholder->num_second == UINT32_MAX;
}

/**
 * Initializes a key placeholder as empty (the key is not intended for derivation).
 *
 * @param[out] placeholder
 *   Pointer to key placeholder structure to initialize.
 */
static inline void policy_set_key_placeholder_empty(policy_node_key_placeholder_t *placeholder) {
    placeholder->num_first = UINT32_MAX;
    placeholder->num_second = UINT32_MAX;
}

#include "../liquid/liquid_wallet.h"
#endif  // HAVE_LIQUID

/**
 * Unwraps wallet policy from outer tags that are not used for script generation.
 *
 * @param[in] policy
 *   Pointer to root policy node.
 *
 * @return pointer to the inner policy node, or to the root node if the policy is not wrapped.
 */
static inline const policy_node_t *policy_unwrap(const policy_node_t *policy) {
#ifdef HAVE_LIQUID
    if (policy && TOKEN_CT == policy->type) {
        return r_policy_node(&((const policy_node_ct_t *) policy)->script);
    }
#endif
    return policy;
}
