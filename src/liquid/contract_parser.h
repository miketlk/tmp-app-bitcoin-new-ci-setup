#pragma once

#ifdef HAVE_LIQUID

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "constants.h"
#include "buffer.h"
#include "liquid_assets.h"
#include "liquid_hash_wrappers.h"

/// Maximum reasonable length of the contract
#define CONTRACT_MAX_LEN (10*1024)
/// Maximum length of key field in JSON (not including quotes and terminating null)
#define CONTRACT_MAX_KEY_LEN 11
/// Maximum length of value field in JSON (not including quotes and terminating null)
#define CONTRACT_MAX_VALUE_LEN 11

/// Contract parser context
typedef struct {
    asset_info_t *asset_info;               ///< Pointer to structure receiving output values
    uint32_t field_presence_flags;          ///< Flags indicating presence of the contract fields
    int state;                              ///< State of the parser's FSM
    bool has_opening_quotes;                ///< Flag: current chunk has opening quotes
    bool escape;                            ///< Flag: this character was escaped by '\'
    uint32_t nesting_level;                 ///< Current level for nested objects and arrays
    char key[CONTRACT_MAX_KEY_LEN + 1];     ///< Key buffer of a key-value pair
    int key_len;                            ///< Length of the key w/o trailing null character
    char value[CONTRACT_MAX_VALUE_LEN + 1]; ///< Value buffer of a key-value pair
    int value_len;                          ///< Length of the value w/o trailing null character
    cx_sha256_t sha256_context;             ///< Context of SHA-256 used to compute contreact hash
} contract_parser_context_t;

/**
 * Initializes contract parser.
 *
 * @param[out] ctx
 *   Instance of parser context to initialize.
 * @param[out] asset_info
 *   Poiter to structure instance receiving decoded values, saved in context.
 *
 * @return true on success, false in case of error.
 */
bool contract_parser_init(contract_parser_context_t *ctx, asset_info_t *asset_info);

/**
 * Processes input contract data.
 *
 * @param[out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Input data buffer to process.
 *
 * @return true on success, false in case of error.
 */
void contract_parser_process(contract_parser_context_t *ctx, buffer_t *data);

/**
 * Finalizes contract processing.
 *
 * Call this function to obtain output values after feeding all bytes of a contract to
 * contract_parser_process().
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[out] hash
 *   Pointer to buffer receiving computed contract hash.
 *
 * @return true on success, false in case of error.
 */
bool contract_parser_finalize(contract_parser_context_t *ctx,
                              uint8_t hash[static SHA256_LEN]);

#endif // HAVE_LIQUID
