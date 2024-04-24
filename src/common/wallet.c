#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <string.h>

#include "../common/bip32.h"
#include "../common/buffer.h"
#include "../common/segwit_addr.h"
#include "../common/wallet.h"
#include "../liquid/liquid.h"

#include "../boilerplate/sw.h"

#include "../crypto.h"
#include "base58.h"
#include "util.h"
#include "read.h"

#ifdef SKIP_FOR_CMOCKA
// disable problematic macros when compiling unit tests with CMOCKA
#define PRINTF(...)
#define PIC(x) (x)
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
// The compiler doesn't like /** inside a block comment, so we disable this warning temporarily.

/*
Currently supported policies for singlesig:

- pkh(key/**) where `key` follows `BIP44`       (legacy)
- wpkh(key/**) where `key` follows `BIP 84`     (native segwit)
- sh(wpkh(key/**)) where `key` follows `BIP 49` (nested segwit)
- tr(key/**) where `key` follows `BIP 86`       (single-key p2tr)

Currently supported wallet policies for multisig:

   LEGACY
  sh(multi(...)))
  sh(sortedmulti(...)))

   NATIVE SEGWIT
  wsh(multi(...))
  wsh(sortedmulti(...))

   WRAPPED SEGWIT
  sh(wsh(multi(...)))
  sh(wsh(sortedmulti(...)))
*/

#pragma GCC diagnostic pop

// TODO: add unit tests to this module

/// Bits specifying used characters
typedef enum {
    // BASIC CATEGORIES /////////////////////////////////////////////
    /// Numbers 0...9
    CHARSET_NUM = 1 << 0,
    /// Lowercase latin letters a...f
    CHARSET_ALPHA_AF_LOW = 1 << 1,
    /// Lowercase latin letters g...z
    CHARSET_ALPHA_GZ_LOW = 1 << 2,
    /// Uppercase latin letters a...f
    CHARSET_ALPHA_AF_UP = 1 << 3,
    /// Uppercase latin letters g...z
    CHARSET_ALPHA_GZ_UP = 1 << 4,
    /// Brackets ()
    CHARSET_BRACKETS = 1 << 5,
    /// Other characters
    CHARSET_OTHER = 1 << 6,

    // COMBINATIONS OT TRAITS ///////////////////////////////////////
    /// Lowercase hexadecimal numbers
    CHARSET_HEX_LOW = (CHARSET_NUM|CHARSET_ALPHA_AF_LOW),
    /// Lowercase latin letters
    CHARSET_ALPHA_LOW = (CHARSET_ALPHA_AF_LOW|CHARSET_ALPHA_GZ_LOW),
    /// Uppercase latin letters
    CHARSET_ALPHA_UP = (CHARSET_ALPHA_AF_UP|CHARSET_ALPHA_GZ_UP),
    /// Latin letters of any case
    CHARSET_ALPHA = (CHARSET_ALPHA_LOW|CHARSET_ALPHA_UP),
    /// Alphanumeric: numbers and latin letters of any case
    CHARSET_ALPHANUM = (CHARSET_NUM|CHARSET_ALPHA),
    /// Alphanumeric: numbers and lowercase latin letters
    CHARSET_ALPHANUM_LOW = (CHARSET_NUM|CHARSET_ALPHA_LOW),
    /// Alphanumeric: numbers and uppercase latin letters
    CHARSET_ALPHANUM_UP = (CHARSET_NUM|CHARSET_ALPHA_UP),
} charset_t;

/// Token descriptor
typedef struct {
    PolicyNodeType type; ///< Node type
    const char *name;    ///< Token name
} token_descriptor_t;

/// Table of token descriptors
static const token_descriptor_t KNOWN_TOKENS[] = {
    {.type = TOKEN_SH, .name = "sh"},
    {.type = TOKEN_WSH, .name = "wsh"},
    {.type = TOKEN_PKH, .name = "pkh"},
    {.type = TOKEN_WPKH, .name = "wpkh"},
    {.type = TOKEN_MULTI, .name = "multi"},
    {.type = TOKEN_SORTEDMULTI, .name = "sortedmulti"},
    {.type = TOKEN_TR, .name = "tr"},
#ifdef HAVE_LIQUID
    {.type = TOKEN_CT, .name = "ct"},
    {.type = TOKEN_SH, .name = "elsh"},
    {.type = TOKEN_WSH, .name = "elwsh"},
    {.type = TOKEN_PKH, .name = "elpkh"},
    {.type = TOKEN_WPKH, .name = "elwpkh"},
    {.type = TOKEN_MULTI, .name = "elmulti"},
    {.type = TOKEN_SORTEDMULTI, .name = "elsortedmulti"},
    {.type = TOKEN_TR, .name = "eltr"},
#endif
};

/// Maximum length of blinding key returned token prefix in characters
#define TOKEN_PREFIX_LEN 7

/// Token scan result
typedef struct {
    /// Detected token length
    size_t token_len;
    /// Charset detected, a combination of `charset_t` flags
    uint32_t charset;
    /// Token prefix string, null terminated. Containins up to TOKEN_PREFIX_LEN first
    /// characters of the token.
    char prefix[TOKEN_PREFIX_LEN + 1];
} token_scan_result_t;

#ifdef HAVE_LIQUID
/**
 * Length of the longest token in the policy wallet descriptor language (not including the
 * terminating \0 byte).
 */
#define MAX_TOKEN_LENGTH (sizeof("elsortedmulti") - 1)
#else
/**
 * Length of the longest token in the policy wallet descriptor language (not including the
 * terminating \0 byte).
 */
#define MAX_TOKEN_LENGTH (sizeof("sortedmulti") - 1)
#endif

int read_policy_map_wallet(buffer_t *buffer, policy_map_wallet_header_t *header) {
    if (!buffer_read_u8(buffer, &header->type)) {
        return -1;
    }

    if (header->type != WALLET_TYPE_POLICY_MAP) {
        return -2;
    }

    if (!buffer_read_u8(buffer, &header->name_len)) {
        return -3;
    }

    if (header->name_len > MAX_WALLET_NAME_LENGTH) {
        return -4;
    }

    if (!buffer_read_bytes(buffer, (uint8_t *) header->name, header->name_len)) {
        return -5;
    }
    header->name[header->name_len] = '\0';

    uint64_t policy_map_len;
    if (!buffer_read_varint(buffer, &policy_map_len) ||
        policy_map_len > MAX_POLICY_MAP_STR_LENGTH) {
        return -6;
    }
    header->policy_map_len = (uint16_t) policy_map_len;

    if (header->policy_map_len > MAX_POLICY_MAP_STR_LENGTH) {
        return -7;
    }

    if (!buffer_read_bytes(buffer, (uint8_t *) header->policy_map, header->policy_map_len)) {
        return -8;
    }

    uint64_t n_keys;
    if (!buffer_read_varint(buffer, &n_keys) || n_keys > 252) {
        return -9;
    }
    header->n_keys = (uint16_t) n_keys;

    if (!buffer_read_bytes(buffer, (uint8_t *) header->keys_info_merkle_root, 32)) {
        return -10;
    }

    return 0;
}

/**
 * Tests if the given character is a decimal digit.
 *
 * @param[in] c
 *   Character to test.
 *
 * @return true if the character is a decimal digit, false otherwise.
 */
static bool is_digit(char c) {
    return '0' <= c && c <= '9';
}

/**
 * Tests if the given character is a latin letter.
 *
 * @param[in] c
 *   Character to test.
 *
 * @return true if the character is a latin letter, false otherwise.
 */
static bool is_alpha(char c) {
    return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

/**
 * Tests if the given character is a digit or a latin letter.
 *
 * @param[in] c
 *   Character to test.
 *
 * @return true if the character is a digit or a latin letter, false otherwise.
 */
static bool is_alphanumeric(char c) {
    return is_alpha(c) || is_digit(c);
}

/**
 * Tests if the given character is a lowercase hexadecimal digit.
 *
 * @param[in] c
 *   Character to test.
 *
 * @return true if the character is a lowercase hexadecimal digit, false otherwise.
 */
static bool is_lowercase_hex(char c) {
    return is_digit(c) || ('a' <= c && c <= 'f');
}

/**
 * Converts a lowercase hexadecimal digit
 *
 * @param[in] c
 *   Input character.
 *
 * @return integer corresponding to the given hexadecimal digit.
 */
static uint8_t lowercase_hex_to_int(char c) {
    return (uint8_t) (is_digit(c) ? c - '0' : c - 'a' + 10);
}

// TODO: remove
#if 0
/**
 * Read up to out_len characters from buffer, until either:
 * - the buffer is exhausted
 * - out_len characters are read
 * - the next character is _not_ in [a-zAZ]
 */
static size_t read_word(buffer_t *buffer, char *out, size_t out_len) {
    size_t word_len = 0;
    uint8_t c;
    while (word_len < out_len && buffer_peek(buffer, &c) && is_alpha((char) c)) {
        out[word_len++] = (char) c;
        buffer_seek_cur(buffer, 1);
    }
    return word_len;
}
#endif // 0

/**
 * Reads a single tag from the buffer.
 *
 * Read up to out_len characters from buffer, until either:
 * - the buffer is exhausted
 * - out_len characters are read
 * - the next character is _not_ in [a-zAZ], [0-9]
 *
 * @param[in,out] buffer
 *   Input buffer.
 * @param[out] out
 *   Output buffer where outputted tag will be placed.
 * @param[in] out_len
 *   Size of the output buffer in bytes.
 *
 * @return length of outputted tag in bytes.
 */
static size_t read_tag(buffer_t *buffer, char *out, size_t out_len) {
    size_t tag_len = 0;
    uint8_t c;
    while (tag_len < out_len && buffer_peek(buffer, &c) && is_alphanumeric((char) c)) {
        out[tag_len++] = (char) c;
        buffer_seek_cur(buffer, 1);
    }
    return tag_len;
}

/**
 * Reads lowercase hexadecimal data bytes from buffer.
 *
 * @param[in,out] buffer
 *   Input buffer.
 * @param[out] out
 *   Pointer to output buffer. It is the responsibility of the caller to make sure that the output
 *   buffer is not smaller than the value in variable pointed by `out_len`.
 * @param[in] out_len
 *   Maximum number of bytes to read, must be no greater than INT_MAX.
 * @param[in] terminator
 *   Terminating character used to stop reading input data. Set to -1 if this feature is not needed.
 *
 * @return length of outputted data in bytes or -1 in case of error
 */
static int read_lowercase_hex_data(buffer_t *buffer,
                                   uint8_t *out,
                                   size_t out_len,
                                   int terminator) {
    size_t out_idx = 0;
    uint8_t c;
    char num[2];

    if (out_len > INT_MAX) {
        return -1;
    }

    while (buffer_peek(buffer, &c) && c != terminator && out_idx < out_len) {
        if (!buffer_read_bytes(buffer, (uint8_t *) num, 2)) {
            return -1;
        }
        if (!is_lowercase_hex(num[0]) || !is_lowercase_hex(num[1])) {
            return -1;
        }
        out[out_idx++] = lowercase_hex_to_int(num[0]) << 4 | lowercase_hex_to_int(num[1]);
    }
    return (int)out_idx;
}

/**
 * Reads a single tag from the buffer and finds corresponding type of policy node.
 *
 * @param[in,out] buffer
 *   Input buffer.
 *
 * @return type of policy node or -1 if not found.
 */
static int parse_token(buffer_t *buffer) {
    char word[MAX_TOKEN_LENGTH + 1];

    size_t word_len = read_tag(buffer, word, MAX_TOKEN_LENGTH);
    word[word_len] = '\0';

    for (unsigned int i = 0; i < sizeof(KNOWN_TOKENS) / sizeof(KNOWN_TOKENS[0]); i++) {
        if (strncmp((const char *) PIC(KNOWN_TOKENS[i].name), word, MAX_TOKEN_LENGTH) == 0) {
            return (int) PIC(KNOWN_TOKENS[i].type);
        }
    }

    return -1;
}

/**
 * Scans a single token in the buffer while keeping its position.
 *
 * @param[in] buffer
 *   Input buffer with a token to scan, position is preserved.
 * @param[in] separator
 *   A separator character on which scan process is stopped.
 * @param[out] result
 *   Pointer to structure instance receiving scan results.
 *
 * @return true if sucessfull, false in case of error
 */
static bool scan_token(buffer_t *buffer,
                       char separator,
                       token_scan_result_t *result) {
    buffer_snapshot_t in_buf_snapshot = buffer_snapshot(buffer);
    memset(result, 0, sizeof(token_scan_result_t));

    char c;
    while (buffer_peek(buffer, (uint8_t*)&c) && c != separator) {
        if (++result->token_len < sizeof(result->prefix)) {
            result->prefix[result->token_len - 1] = c;
        }

        if (c >= '0' && c <= '9') {
            result->charset |= CHARSET_NUM;
        } else if (c >= 'a' && c <= 'f') {
            result->charset |= CHARSET_ALPHA_AF_LOW;
        } else if (c >= 'g' && c <= 'z') {
            result->charset |= CHARSET_ALPHA_GZ_LOW;
        } else if (c >= 'A' && c <= 'F') {
            result->charset |= CHARSET_ALPHA_AF_UP;
        } else if (c >= 'G' && c <= 'Z') {
            result->charset |= CHARSET_ALPHA_GZ_UP;
        } else if (c == '(' || c == ')') {
            result->charset |= CHARSET_BRACKETS;
        } else {
            result->charset |= CHARSET_OTHER;
        }
        buffer_seek_cur(buffer, 1);
    }

    buffer_restore(buffer, in_buf_snapshot);
    return !!result->token_len;
}

/**
 * Parses an unsigned decimal number from buffer.
 *
 * Parsing stops when either the buffer ends, the next character is not a number, or the number is
 * already too big. Leading zeros are not allowed.
 *
 * @param[in,out] buffer
 *   Input buffer.
 * @param[out] out
 *   Pointer to variable receiving resulting integer.
 *
 * @return 0 on success, -1 on failure.
 */
static int parse_unsigned_decimal(buffer_t *buffer, size_t *out) {
    uint8_t c;
    if (!buffer_peek(buffer, &c) || !is_digit(c)) {
        PRINTF("parse_unsigned_decimal: couldn't read byte, or not a digit: %d\n", c);
        return -1;
    }

    size_t result = 0;
    int digits_read = 0;
    while (buffer_peek(buffer, &c) && is_digit(c)) {
        ++digits_read;
        uint8_t next_digit = c - '0';

        if (digits_read == 2 && result == 0) {
            // if the first digit was a 0, than it should be the only digit
            return -1;
        }

        if (10 * result + next_digit < result) {
            PRINTF("parse_unsigned_decimal: overflow. Current: %d. Next digit: %d\n",
                   result,
                   next_digit);
            return -1;  // overflow, integer too large
        }

        result = 10 * result + next_digit;

        buffer_seek_cur(buffer, 1);
    }
    *out = result;

    if (digits_read == 0) {
        return -1;
    }

    return 0;
}

/**
 * Reads a derivation step from buffer.
 *
 * Reads a derivation step expressed in decimal, with the symbol ' to mark if hardened (h is not
 * supported).
 *
 * @param[in,out] buffer
 *   Input buffer.
 * @param[out] out
 *   Output derivation step.
 *
 * @return 0 on success, -1 on error.
 */
static int buffer_read_derivation_step(buffer_t *buffer, uint32_t *out) {
    size_t der_step;
    if (parse_unsigned_decimal(buffer, &der_step) == -1 || der_step >= BIP32_FIRST_HARDENED_CHILD) {
        PRINTF("Failed reading derivation step\n");
        return -1;
    }

    *out = (uint32_t)der_step;

    // Check if hardened
    uint8_t c;
    if (buffer_peek(buffer, &c) && c == '\'') {
        *out |= BIP32_FIRST_HARDENED_CHILD;
        buffer_seek_cur(buffer, 1);  // skip the ' character
    }
    return 0;
}

// TODO: we are currently enforcing that the master key fingerprint (if present) is in lowercase
// hexadecimal digits,
//       and that the symbol for "hardened derivation" is "'".
//       This implies descriptors should be normalized on the client side.
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out) {
    memset(out, 0, sizeof(policy_map_key_info_t));

    uint8_t c;
    if (!buffer_peek(buffer, &c)) {
        return -1;
    }

    if (c == '[') {
        out->has_key_origin = 1;

        buffer_seek_cur(buffer, 1);         // skip 1 byte
        if (!buffer_can_read(buffer, 9)) {  // at least 8 bytes + (closing parenthesis or '\')
            return -1;
        }
        for (int i = 0; i < 4; i++) {
            char num[2];
            buffer_read_bytes(buffer, (uint8_t *) num, 2);
            if (!is_lowercase_hex(num[0]) || !is_lowercase_hex(num[1])) {
                return -1;
            }
            out->master_key_fingerprint[i] =
                16 * lowercase_hex_to_int(num[0]) + lowercase_hex_to_int(num[1]);
        }

        // read all the given derivation steps
        out->master_key_derivation_len = 0;
        while (buffer_peek(buffer, &c) && c == '/') {
            buffer_seek_cur(buffer, 1);  // skip the '/' character
            if (out->master_key_derivation_len > MAX_BIP32_PATH_STEPS) {
                return -1;
            }

            if (buffer_read_derivation_step(
                    buffer,
                    &out->master_key_derivation[out->master_key_derivation_len]) == -1) {
                return -1;
            };

            ++out->master_key_derivation_len;
        }

        // the next character must be ']'
        if (!buffer_read_u8(buffer, &c) || c != ']') {
            return -1;
        }
    }

    // consume the rest of the buffer into the pubkey, except possibly the final "/**"
    unsigned int ext_pubkey_len = 0;
    while (ext_pubkey_len < MAX_SERIALIZED_PUBKEY_LENGTH && buffer_peek(buffer, &c) &&
           is_alphanumeric(c)) {
        out->ext_pubkey[ext_pubkey_len] = c;
        ++ext_pubkey_len;
        buffer_seek_cur(buffer, 1);
    }
    out->ext_pubkey[ext_pubkey_len] = '\0';

    // either the string terminates now, or it has a final "/**" suffix for the wildcard.
    if (!buffer_can_read(buffer, 1)) {
        // no wildcard
        return 0;
    }

    out->has_wildcard = 1;

    // Only the final "/**" suffix should be left
    uint8_t wildcard[3];
    // Make sure that the buffer is indeed exhausted
    if (!buffer_read_bytes(buffer, wildcard, 3)  // should be able to read 3 characters
        || buffer_can_read(buffer, 1)            // but nothing more
        || wildcard[0] != '/'                    // suffix should be exactly "/**"
        || wildcard[1] != '*' || wildcard[2] != '*') {
        return -1;
    }

    return 0;
}

bool validate_policy_map_extended_pubkey(const policy_map_key_info_t *key_info,
                                         uint32_t bip32_pubkey_version) {
    int status = validate_serialized_extended_pubkey(
        key_info->ext_pubkey,
        key_info->master_key_derivation,
        key_info->has_key_origin ? key_info->master_key_derivation_len : -1,
        bip32_pubkey_version
    );

    return EXTENDED_PUBKEY_VALID == status;
}

/**
 * Parses key index from the input buffer.
 *
 * @param[in,out] in_buf
 *   Input buffer.
 *
 * @return a non-negative integer key index or -1 if error.
 */
static size_t parse_key_index(buffer_t *in_buf) {
    char c;
    if (!buffer_read_u8(in_buf, (uint8_t *) &c) || c != '@') {
        return -1;
    }

    size_t k;
    if (parse_unsigned_decimal(in_buf, &k) == -1) {
        return -1;
    }
    return k;
}

/// Flag: current context is within sh()
#define CONTEXT_WITHIN_SH      (1U << 0)
/// Flag: current context is within ct()
#define CONTEXT_WITHIN_CT      (1U << 1)

/// Script parser context
typedef struct {
    /// Input buffer with a script expression to parse.
    buffer_t *in_buf;
    /// Output buffer which receives a tree-like structure of nodes
    buffer_t *out_buf;
    /// Version prefix to use for the public key.
    uint32_t bip32_pubkey_version;
    /// Version prefix to use for the private key.
    uint32_t bip32_privkey_version;
} script_parser_ctx_t;

#ifdef HAVE_LIQUID

/**
 * Prototype for function implementing blinding key parser.
 *
 * This function should parse a BLINDING_KEY expression enclosed in ct() tag as specified in
 * ELIP: 150 and ELIP 151 from the `in_buf` buffer, aallocating the nodes and variables in
 * `out_buf`.
 *
 * @param[in,out] ctx
 *   Script parser context.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
typedef int (*blinding_key_parser_t)(script_parser_ctx_t *ctx, size_t token_len);

/**
 * Parses slip77() expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] ctx
 *   Script parser context.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_slip77(script_parser_ctx_t *ctx, size_t token_len) {
    UNUSED(token_len);

    policy_node_blinding_privkey_t *node = (policy_node_blinding_privkey_t *)
        buffer_alloc(ctx->out_buf, sizeof(policy_node_blinding_privkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->type = TOKEN_SLIP77;

    bool ok = buffer_skip_data(ctx->in_buf, (const uint8_t*) "slip77(", sizeof("slip77(") - 1);
    ok = ok && sizeof(node->privkey) ==
            read_lowercase_hex_data(ctx->in_buf, node->privkey, sizeof(node->privkey), ')');
    ok = ok && buffer_skip_data(ctx->in_buf, (const uint8_t*) ")", 1);

    return ok ? 0 : -1;
}

/**
 * Parses hexadecimal public key expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] ctx
 *   Script parser context.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_hex_pubkey(script_parser_ctx_t *ctx, size_t token_len) {
    UNUSED(token_len);

    policy_node_blinding_pubkey_t *node = (policy_node_blinding_pubkey_t *)
        buffer_alloc(ctx->out_buf, sizeof(policy_node_blinding_pubkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->type = TOKEN_HEX_PUB;

    bool ok = sizeof(node->pubkey) ==
        read_lowercase_hex_data(ctx->in_buf, node->pubkey, sizeof(node->pubkey), ',');

    return ok && (0x02 == node->pubkey[0] || 0x03 == node->pubkey[0]) ? 0 : -1;
}

/**
 * Parses hexadecimal private key expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] ctx
 *   Script parser context.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_hex_privkey(script_parser_ctx_t *ctx, size_t token_len) {
    UNUSED(token_len);

    policy_node_blinding_privkey_t *node = (policy_node_blinding_privkey_t *)
        buffer_alloc(ctx->out_buf, sizeof(policy_node_blinding_privkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->type = TOKEN_HEX_PRV;

    bool ok = sizeof(node->privkey) ==
        read_lowercase_hex_data(ctx->in_buf, node->privkey, sizeof(node->privkey), ',');

    return ok ? 0 : -1;
}

/**
 * Parses xpub expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] ctx
 *   Script parser context.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_xpub(script_parser_ctx_t *ctx, size_t token_len) {
    serialized_extended_pubkey_check_t pubkey_check;
    const serialized_extended_pubkey_t *pubkey = &pubkey_check.serialized_extended_pubkey;

    if (!buffer_can_read(ctx->in_buf, token_len)) {
        return -1;
    }
    if (sizeof(pubkey_check) != base58_decode((char*) buffer_get_cur(ctx->in_buf),
                                              token_len,
                                              (uint8_t *) &pubkey_check,
                                              sizeof(pubkey_check))) {
        return -1;
    }

    uint8_t checksum[4];
    crypto_get_checksum((uint8_t *)&pubkey_check.serialized_extended_pubkey,
                        sizeof(pubkey_check.serialized_extended_pubkey),
                        checksum);
    if (!memeq(checksum, pubkey_check.checksum, sizeof(checksum))) {
        return -1;
    }
    if (read_u32_be(pubkey->version, 0) != ctx->bip32_pubkey_version ||
        !(0x02 == pubkey->compressed_pubkey[0] || 0x03 == pubkey->compressed_pubkey[0])) {
        return -1;
    }

    policy_node_blinding_pubkey_t *node = (policy_node_blinding_pubkey_t *)
        buffer_alloc(ctx->out_buf, sizeof(policy_node_blinding_pubkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->type = TOKEN_XPUB;
    memcpy(node->pubkey, pubkey->compressed_pubkey, sizeof(node->pubkey));

    return buffer_seek_cur(ctx->in_buf, token_len) ? 0 : -1;
}

/**
 * Parses xprv expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] ctx
 *   Script parser context.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_xprv(script_parser_ctx_t *ctx, size_t token_len) {
    serialized_extended_privkey_check_t privkey_check;
    const serialized_extended_privkey_t *privkey = &privkey_check.serialized_extended_privkey;

    if (!buffer_can_read(ctx->in_buf, token_len)) {
        return -1;
    }
    if (sizeof(privkey_check) != base58_decode((char*) buffer_get_cur(ctx->in_buf),
                                               token_len,
                                               (uint8_t *) &privkey_check,
                                               sizeof(privkey_check))) {
        return -1;
    }

    uint8_t checksum[4];
    crypto_get_checksum((uint8_t *)&privkey_check.serialized_extended_privkey,
                        sizeof(privkey_check.serialized_extended_privkey),
                        checksum);
    if (!memeq(checksum, privkey_check.checksum, sizeof(checksum))) {
        return -1;
    }
    if (read_u32_be(privkey->version, 0) != ctx->bip32_privkey_version ||
        0 != privkey->null_prefix) {
        return -1;
    }

    policy_node_blinding_privkey_t *node = (policy_node_blinding_privkey_t *)
        buffer_alloc(ctx->out_buf, sizeof(policy_node_blinding_privkey_t), true);
    if (NULL == node) {
        return -1;
    }
    node->type = TOKEN_XPRV;
    memcpy(node->privkey, privkey->privkey, sizeof(node->privkey));

    return buffer_seek_cur(ctx->in_buf, token_len) ? 0 : -1;
}

/**
 * Parses elip151 expression within BLINDING_KEY context.
 *
 * Corresponds to `blinding_key_parser_t` type, refer to its description for more details.
 *
 * @param[in,out] ctx
 *   Script parser context.
 * @param[in] token_len
 *   Size of key token in characters.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_ct_elip151(script_parser_ctx_t *ctx, size_t token_len) {
    UNUSED(token_len);

    if (!buffer_skip_data(ctx->in_buf, (const uint8_t*) "elip151", sizeof("elip151") - 1)) {
        return -1;
    }

    policy_node_t *node = (policy_node_t *)
        buffer_alloc(ctx->out_buf, sizeof(policy_node_t), true);

    if (node) {
        node->type = TOKEN_ELIP151;
        node->node_data = NULL;
        return 0;
    }
    return -1;
}

/// Blinding key signature
typedef struct {
    size_t min_len;                     ///< Minimum allowed length
    size_t max_len;                     ///< Maximum allowed length
    uint32_t charset;                   ///< Allowed charset
    blinding_key_parser_t parser;       ///< Pinter to a function parsing a BLINDING_KEY expression.
    char prefix[TOKEN_PREFIX_LEN + 1];  ///< Token prefix
} blinding_key_signature_t;

/// Table of known blinding key signatures
static const blinding_key_signature_t BLINDING_KEY_SIGNATURES[] = {
    {
        .prefix = "slip77",
        .min_len = 72,
        .max_len = 72,
        .charset = CHARSET_ALPHANUM_LOW|CHARSET_BRACKETS,
        .parser = parse_ct_slip77
    },
    {
        .prefix = "xpub",
        .min_len = 111,
        .max_len = 112,
        .charset = CHARSET_ALPHANUM,
        .parser = parse_ct_xpub
    },
    {
        .prefix = "xprv",
        .min_len = 111,
        .max_len = 112,
        .charset = CHARSET_ALPHANUM,
        .parser = parse_ct_xprv
    },
    {
        .prefix = "elip151",
        .min_len = 7,
        .max_len = 7,
        .charset = CHARSET_ALPHANUM_LOW,
        .parser = parse_ct_elip151
    },
    {
        .prefix = "",
        .min_len = 64,
        .max_len = 64,
        .charset = CHARSET_HEX_LOW,
        .parser = parse_ct_hex_privkey
    },
    {
        .prefix = "",
        .min_len = 66,
        .max_len = 66,
        .charset = CHARSET_HEX_LOW,
        .parser = parse_ct_hex_pubkey
    }
};
/// Number of records in the table of known blinding key signatures
static const size_t N_BLINDING_KEY_SIGNATURES =
    sizeof(BLINDING_KEY_SIGNATURES) / sizeof(BLINDING_KEY_SIGNATURES[0]);

/**
 * Looks through the table of blinding key signatures and returns corresponding
 * parsing function.
 *
 * @param[in] scan_result
 *   Results of token scan used to find blinding key type by its signature.
 *
 * @return pointer to function parsing identified type of blinding key or NULL if not found.
 */
blinding_key_parser_t find_blinding_key_parser(const token_scan_result_t *scan_result) {
    for (size_t i = 0; i < N_BLINDING_KEY_SIGNATURES; ++i) {
        uint32_t expected_charset = (uint32_t) PIC(BLINDING_KEY_SIGNATURES[i].charset);
        const char *expected_prefix = (const char *) PIC(BLINDING_KEY_SIGNATURES[i].prefix);
        if (0 == (scan_result->charset & ~expected_charset) &&
            scan_result->token_len >= (size_t) PIC(BLINDING_KEY_SIGNATURES[i].min_len) &&
            scan_result->token_len <= (size_t) PIC(BLINDING_KEY_SIGNATURES[i].max_len) &&
            0 == strncmp(expected_prefix,
                         scan_result->prefix,
                         strnlen(expected_prefix, TOKEN_PREFIX_LEN))) {
            return (blinding_key_parser_t) PIC(BLINDING_KEY_SIGNATURES[i].parser);
        }
    }

    return NULL;
}

/**
 * Internal function parsing blinding key script inside ct() descriptor.
 *
 * Parses a BLINDING_KEY expression as specified in ELIP: 150 from the in_buf
 * buffer, allocating the node and variables in out_buf.The initial pointer in
 * out_buf will contain the node of the BLINDING_KEY.
 *
 * @param[in,out] ctx
 *   Script parser context.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_blinding_key_script(script_parser_ctx_t *ctx) {
    token_scan_result_t scan_result;
    if (!scan_token(ctx->in_buf, ',', &scan_result)) {
        return -1;
    }

    blinding_key_parser_t key_parser = find_blinding_key_parser(&scan_result);
    if (key_parser) {
        return (*key_parser)(ctx, scan_result.token_len);
    }
    return -1;
}

#endif // HAVE_LIQUID

/**
 * Internal function recursively parsing a script expression from the input buffer.
 *
 * Parses a SCRIPT expression from the in_buf buffer, allocating the nodes and variables in out_buf.
 * The initial pointer in out_buf will contain the root node of the SCRIPT.
 *
 * @param[in,out] ctx
 *   Script parser context.
 * @param[in] depth
 *   Current depth of nested structure.
 *
 * @return 0 if successful, a negative number on error.
 */
static int parse_script(script_parser_ctx_t *ctx, size_t depth, unsigned int context_flags) {
    // We read the token, we'll do different parsing based on what token we find
    int token = parse_token(ctx->in_buf);
    char c;
    unsigned int inner_context_flags = context_flags;

    // Opening '('
    if (!buffer_read_u8(ctx->in_buf, (uint8_t *) &c) && c != '(') {
        return -1;
    }

    switch (token) {
        case TOKEN_SH:
        case TOKEN_WSH: {
            if (token == TOKEN_SH) {
                if (depth != 0 && (context_flags & CONTEXT_WITHIN_CT) == 0) {
                    return -2;  // can only be top-level or inside ct
                }

            } else if (token == TOKEN_WSH) {
                if (depth != 0 &&
                    (context_flags & (CONTEXT_WITHIN_SH|CONTEXT_WITHIN_CT)) == 0) {
                    return -3;  // only top-level, inside sh or ct
                }
            }

            policy_node_with_script_t *node =
                (policy_node_with_script_t *) buffer_alloc(ctx->out_buf,
                                                           sizeof(policy_node_with_script_t),
                                                           true);
            if (node == NULL) {
                return -4;
            }
            node->type = token;

            if (token == TOKEN_SH) {
                inner_context_flags |= CONTEXT_WITHIN_SH;
            }

            // the internal script is recursively parsed (if successful) in the current location of
            // the output buffer
            int res2 = 0;
            node->script = (policy_node_t *) buffer_get_cur_aligned(ctx->out_buf);
            if (NULL == node->script || (res2 = parse_script(ctx, depth + 1, inner_context_flags)) < 0) {
                // failed while parsing internal script
                return res2 * 100 - 5;
            }

            break;
        }
        case TOKEN_PKH:
        case TOKEN_WPKH:
        case TOKEN_TR:  // not currently supporting x-only keys
        {
            if (token == TOKEN_WPKH) {
                if (depth != 0 &&
                    (context_flags & (CONTEXT_WITHIN_SH|CONTEXT_WITHIN_CT)) == 0) {
                    return -6;  // only top-level, inside sh or ct
                }
            }
            policy_node_with_key_t *node =
                (policy_node_with_key_t *) buffer_alloc(ctx->out_buf,
                                                        sizeof(policy_node_with_key_t),
                                                        true);
            if (node == NULL) {
                return -7;
            }
            node->type = token;

            int key_index = parse_key_index(ctx->in_buf);
            if (key_index == -1) {
                return -8;
            }
            node->key_index = (size_t) key_index;

            break;
        }
        case TOKEN_MULTI:
        case TOKEN_SORTEDMULTI: {
            policy_node_multisig_t *node =
                (policy_node_multisig_t *) buffer_alloc(ctx->out_buf,
                                                        sizeof(policy_node_multisig_t),
                                                        true);

            if (node == NULL) {
                return -9;
            }
            node->type = token;

            if (parse_unsigned_decimal(ctx->in_buf, &node->k) == -1) {
                PRINTF("Error parsing threshold\n");
                return -10;
            }

            // We allocate the array of key indices at the current position in the output buffer (on
            // success)
            node->key_indexes = (size_t *) buffer_get_cur_aligned(ctx->out_buf);
            if (NULL == node->key_indexes) {
                return -11;
            }

            node->n = 0;
            while (true) {
                // If the next character is a ')', we exit and leave it in the buffer
                if (buffer_peek(ctx->in_buf, (uint8_t *) &c) && c == ')') {
                    break;
                }

                // otherwise, there must be a comma
                if (!buffer_read_u8(ctx->in_buf, (uint8_t *) &c) || c != ',') {
                    PRINTF("Unexpected char: %c. Was expecting: ,\n", c);
                    return -12;
                }

                int key_index = parse_key_index(ctx->in_buf);
                if (key_index == -1) {
                    return -13;
                }

                size_t *key_index_out = (size_t *) buffer_alloc(ctx->out_buf, sizeof(size_t), true);
                if (key_index_out == NULL) {
                    return -14;
                }
                *key_index_out = (size_t) key_index;

                ++node->n;
            }

            // check integrity of k and n
            if (!(1 <= node->k && node->k <= node->n && node->n <= MAX_POLICY_MAP_COSIGNERS)) {
                return -15;
            }

            break;
        }
#ifdef HAVE_LIQUID
        case TOKEN_CT: {
            if (depth != 0) {
                return -16;  // can only be top-level
            }

            policy_node_ct_t *node =
                (policy_node_ct_t *) buffer_alloc(ctx->out_buf, sizeof(policy_node_ct_t), true);
            if (node == NULL) {
                return -17;
            }
            node->type = token;

            inner_context_flags |= CONTEXT_WITHIN_CT;

            // the master blinding key script is recursively parsed (if successful) in the current
            // location of the output buffer
            node->mbk_script = (policy_node_t *) buffer_get_cur_aligned(ctx->out_buf);
            if (NULL == node->mbk_script || 0 > parse_blinding_key_script(ctx)) {
                // failed while parsing internal script
                return -18;
            }

            // scripts must be separated by comma
            if (!buffer_read_u8(ctx->in_buf, (uint8_t *) &c) || c != ',') {
                PRINTF("Unexpected char: %c. Was expecting: ,\n", c);
                return -19;
            }

            // the internal script is recursively parsed (if successful) in the current location of
            // the output buffer
            int res2 = 0;
            node->script = (policy_node_t *) buffer_get_cur_aligned(ctx->out_buf);
            if (NULL == node->script || (res2 = parse_script(ctx, depth + 1, inner_context_flags)) < 0) {
                // failed while parsing internal script
                return res2 * 100 - 20;
            }
            break;
        }
#endif // HAVE_LIQUID
        default:
            PRINTF("Unknown token\n");
            return -21;
    }

    if (!buffer_read_u8(ctx->in_buf, (uint8_t *) &c) && c != ')') {
        return -22;
    }

    if (depth == 0 && buffer_can_read(ctx->in_buf, 1)) {
        PRINTF("Input buffer too long\n");
        return -23;
    }

    return 0;
}

int parse_policy_map(buffer_t *in_buf,
                     void *out,
                     size_t out_len,
                     uint32_t bip32_pubkey_version,
                     uint32_t bip32_privkey_version) {
    if ((uintptr_t) out % sizeof(void*) != 0) {
        PRINTF("Unaligned pointer\n");
        return -1;
    }

    buffer_t out_buf = buffer_create(out, out_len);

    script_parser_ctx_t parser_ctx = {
        .in_buf = in_buf,
        .out_buf = &out_buf,
        .bip32_pubkey_version = bip32_pubkey_version,
        .bip32_privkey_version = bip32_privkey_version
    };

    return parse_script(&parser_ctx, 0, 0);
}

bool policy_is_multisig(const policy_node_t *policy) {
    const policy_node_t *node = policy;

    while(node != NULL) {
        switch(node->type)
        {
        case TOKEN_CT:
            node = ((policy_node_ct_t *)node)->script;
            break;

        case TOKEN_SH:
        case TOKEN_WSH:
            node = ((policy_node_with_script_t *)node)->script;
            break;

        case TOKEN_MULTI:
        case TOKEN_SORTEDMULTI:
            return true;

        // TOKEN_PKH, TOKEN_WPKH, TOKEN_TR
        // TODO: add Taproot multisig when it will be supported project-wise
        default:
            return false;
        }
    }

    return false;
}

#ifndef SKIP_FOR_CMOCKA

void get_policy_wallet_id(const policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]) {
    cx_sha256_t wallet_hash_context;
    cx_sha256_init(&wallet_hash_context);

    crypto_hash_update_u8(&wallet_hash_context.header, wallet_header->type);
    crypto_hash_update_u8(&wallet_hash_context.header, wallet_header->name_len);
    crypto_hash_update(&wallet_hash_context.header, wallet_header->name, wallet_header->name_len);

    crypto_hash_update_varint(&wallet_hash_context.header, wallet_header->policy_map_len);
    crypto_hash_update(&wallet_hash_context.header,
                       wallet_header->policy_map,
                       wallet_header->policy_map_len);

    crypto_hash_update_varint(&wallet_hash_context.header, wallet_header->n_keys);

    crypto_hash_update(&wallet_hash_context.header, wallet_header->keys_info_merkle_root, 32);

    crypto_hash_digest(&wallet_hash_context.header, out, 32);
}

#endif
