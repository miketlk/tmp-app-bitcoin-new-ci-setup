#ifdef HAVE_LIQUID

#include <string.h>
#include <ctype.h>
#include "buffer.h"
#include "contract_parser.h"

/// States of the parser state machine
typedef enum {
    STATE_START = 0,     ///< Initial state, looking for opening '{'
    STATE_KEY,           ///< Decoding key of a key-value pair
    STATE_COLON,         ///< Looking for ':' symbol separating key and value
    STATE_VALUE,         ///< Decoding value of a key-value pair
    STATE_SKIP_OBJECT,   ///< Skipping nested object(s) (they are not supported currently)
    STATE_SKIP_ARRAY,    ///< Skipping array(s) (they are not supported currently)
    STATE_SEPARATOR,     ///< Looking for ',' separator or closing '}'
    STATE_FINISH,        ///< Processing is finished, remaining data ignored
    STATE_ERROR,         ///< Error ocurred during processing
} parser_state_t;

/// Bit flags indicating presence of the supported contract fields
typedef enum {
    HAS_TICKER = (1 << 0),                           ///< "ticker" field is present
    HAS_PRECISION = (1 << 1),                        ///< "precision" field is present
    HAS_ALL_REQUIRED = (HAS_TICKER | HAS_PRECISION)  ///< All required fields are present
} field_presence_flags_t;

/**
 * Prototype for a function implementing state-specific logic of parser's FSM.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
typedef parser_state_t (*parser_state_fn_t)(contract_parser_context_t *ctx, buffer_t *data);

/**
 * Checks if an explicit-length string contains only alphanumeric characters.
 *
 * @param[in] str
 *   Input string, does not need to be null-terminated.
 * @param[in] len
 *   Input string length, not including terminating null character (if it present).
 *
 * @return true if the string is alphanumeric, false otherwise
 */
static bool is_alphanum_strn(const char *str, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // Check if there are non-alphanumeric characters, including unexpected null
        if (!isalnum((int)str[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Parses JSON 53-bit integer.
 *
 * Does not support floating point values.
 *
 * @param[in] str
 *   Input string, does not need to be null-terminated.
 * @param[in] len
 *   Input string length, not including terminating null character (if it present).
 * @param[out] p_num
 *   Pointer to variable receiving decoded integer.
 *
 * @return true on success, false in case of incorrect input.
 */
static bool parse_json_integer(const char *str, size_t len, int64_t *p_num) {
    if (str && len && len <= 17 && p_num) {
        const char *p_str = str[0] == '-' ? str + 1 : str;
        size_t numeric_len = str[0] == '-' ? len - 1 : len;

        *p_num = 0;
        for (size_t i = 0; i < numeric_len; ++i) {
            if (!isdigit((int)str[i])) {
                return false;
            }
            *p_num = 10 * *p_num + p_str[i] - '0';
        }
        if (str[0] == '-') {
            *p_num = -*p_num;
        }
        return true;
    }
    return false;
}

/**
 * Handles decoded key-value pair.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in] in_quotes
 *   Flag indicating that value is enclosed in quotes.
 *
 * @return true on success, false if value is invalid.
 */
static bool handle_key_value(contract_parser_context_t *ctx, bool in_quotes) {
    if (ctx->key_len > 0 && ctx->value_len > 0) {
        ctx->key[ctx->key_len] = '\0';
        ctx->value[ctx->value_len] = '\0';

        if (0 == strncmp(ctx->key, "ticker", sizeof(ctx->key))) {
            if ( !(ctx->field_presence_flags & HAS_TICKER) && in_quotes &&
                 is_alphanum_strn(ctx->value, ctx->value_len) &&
                 ctx->value_len <= MAX_ASSET_TICKER_LENGTH ) {
                strlcpy(ctx->asset_info->ticker,
                        ctx->value,
                        sizeof(ctx->asset_info->ticker));
                ctx->field_presence_flags |= HAS_TICKER;
            } else {
                return false;
            }
        } else if (0 == strncmp(ctx->key, "precision", sizeof(ctx->key))) {
            int64_t value_num;
            if ( !(ctx->field_presence_flags & HAS_PRECISION) && !in_quotes &&
                 parse_json_integer(ctx->value, ctx->value_len, &value_num) &&
                 value_num >= LIQUID_ASSET_DECIMALS_MIN &&
                 value_num <= LIQUID_ASSET_DECIMALS_MAX ) {
                ctx->asset_info->decimals = (uint8_t)value_num;
                ctx->field_presence_flags |= HAS_PRECISION;
            } else {
                return false;
            }
        }
    }
    return true;
}

/**
 * Implements STATE_START: looking for opening '{'.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
static parser_state_t state_start(contract_parser_context_t *ctx, buffer_t *data) {
    (void)ctx;

    uint8_t byte = 0;
    if (!buffer_read_u8(data, &byte) || byte != '{') {
        return STATE_ERROR;
    }
    return STATE_KEY;
}

/**
 * Implements STATE_KEY: decoding key of a key-value pair.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
static parser_state_t state_key(contract_parser_context_t *ctx, buffer_t *data) {
    uint8_t byte;
    while (buffer_read_u8(data, &byte)) {
        if (!ctx->escape && byte == '\\') {
            ctx->escape = true;
            continue;
        }

        if (byte == '"' && !ctx->escape) {
            if (ctx->has_opening_quotes) {
                return STATE_COLON;
            }
            ctx->has_opening_quotes = true;
        } else if (ctx->key_len != -1) {
            if (!ctx->has_opening_quotes) { // key must be always in quotes
                return STATE_ERROR;
            }
            if (ctx->key_len < CONTRACT_MAX_KEY_LEN) {
                ctx->key[ctx->key_len++] = byte;
            } else {
                ctx->key_len = -1; // skip this key
            }
        }
        ctx->escape = false;
    }
    return STATE_KEY;
}

/**
 * Implements STATE_COLON: looking for ':' symbol separating key and value.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
static parser_state_t state_colon(contract_parser_context_t *ctx, buffer_t *data) {
    (void)ctx;
    uint8_t byte = 0;
    if (!buffer_read_u8(data, &byte) || byte != ':') {
        return STATE_ERROR;
    }
    return STATE_VALUE;
}

/**
 * Implements STATE_VALUE: decoding value of a key-value pair.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
static parser_state_t state_value(contract_parser_context_t *ctx, buffer_t *data) {
    uint8_t byte;
    while (buffer_read_u8(data, &byte)) {
        if (!ctx->escape && byte == '\\') {
            ctx->escape = true;
            continue;
        }

        if (byte == '"' && !ctx->escape) {
            if (ctx->has_opening_quotes) {
                return handle_key_value(ctx, true) ? STATE_SEPARATOR : STATE_ERROR;
            } else if (!ctx->value_len) {
                ctx->has_opening_quotes = true;
            } else {
                return STATE_ERROR;
            }
        } else if (byte == ',' && !ctx->has_opening_quotes) {
            return handle_key_value(ctx, false) && !ctx->escape ? STATE_KEY : STATE_ERROR;
        } else if (byte == '}' && !ctx->has_opening_quotes) {
            return handle_key_value(ctx, false) && !ctx->escape ? STATE_FINISH : STATE_ERROR;
        } else if (byte == '{' && !ctx->has_opening_quotes) {
            return !ctx->value_len && !ctx->escape ? STATE_SKIP_OBJECT : STATE_ERROR;
        } else if (byte == '[' && !ctx->has_opening_quotes) {
            return !ctx->value_len && !ctx->escape ? STATE_SKIP_ARRAY : STATE_ERROR;
        } else if (ctx->key_len != -1 && ctx->value_len != -1) {
            if (ctx->value_len < CONTRACT_MAX_VALUE_LEN) {
                ctx->value[ctx->value_len++] = byte;
            } else {
                ctx->value_len = -1; // skip this value
            }
        }
        ctx->escape = false;
    }
    return STATE_VALUE;
}

/**
 * Implements STATE_SKIP_OBJECT: skipping nested object(s).
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
static parser_state_t state_skip_object(contract_parser_context_t *ctx, buffer_t *data) {
    uint8_t byte;
    while (buffer_read_u8(data, &byte)) {
        if (!ctx->escape && byte == '\\') {
            ctx->escape = true;
            continue;
        }

        if (!ctx->escape) {
            if (byte == '"') {
                ctx->has_opening_quotes = !ctx->has_opening_quotes;
            } else if (byte == '{' && !ctx->has_opening_quotes) {
                if (++ctx->nesting_level == UINT32_MAX) {
                    return STATE_ERROR;
                }
            } else if (byte == '}' && !ctx->has_opening_quotes) {
                if (ctx->nesting_level) {
                    --ctx->nesting_level;
                } else {
                    return STATE_SEPARATOR;
                }
            }
        }
        ctx->escape = false;
    }
    return STATE_SKIP_OBJECT;
}

/**
 * Implements STATE_SKIP_ARRAY: skipping array(s).
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
static parser_state_t state_skip_array(contract_parser_context_t *ctx, buffer_t *data) {
    uint8_t byte;
    while (buffer_read_u8(data, &byte)) {
        if (!ctx->escape && byte == '\\') {
            ctx->escape = true;
            continue;
        }

        if (!ctx->escape) {
            if (byte == '"') {
                ctx->has_opening_quotes = !ctx->has_opening_quotes;
            } else if (byte == '[' && !ctx->has_opening_quotes) {
                if (++ctx->nesting_level == UINT32_MAX) {
                    return STATE_ERROR;
                }
            } else if (byte == ']' && !ctx->has_opening_quotes) {
                if (ctx->nesting_level) {
                    --ctx->nesting_level;
                } else {
                    return STATE_SEPARATOR;
                }
            }
        }
        ctx->escape = false;
    }
    return STATE_SKIP_ARRAY;
}

/**
 * Implements STATE_SEPARATOR: looking for ',' separator or closing '}'.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
static parser_state_t state_separator(contract_parser_context_t *ctx, buffer_t *data) {
    (void)ctx;
    uint8_t byte = 0;
    if (!buffer_read_u8(data, &byte)) {
        return STATE_ERROR;
    }

    if (byte == ',') {
        return STATE_KEY;
    } else if (byte == '}') {
        return STATE_FINISH;
    }
    return STATE_ERROR;
}

/// State table containg pointer to functions implementing state-specific logic
static const parser_state_fn_t state_table[] = {
    [STATE_START] = state_start,
    [STATE_KEY] = state_key,
    [STATE_COLON] = state_colon,
    [STATE_VALUE] = state_value,
    [STATE_SKIP_OBJECT] = state_skip_object,
    [STATE_SKIP_ARRAY] = state_skip_array,
    [STATE_SEPARATOR] = state_separator
    // STATE_FINISH and STATE_ERROR are not defined here because they terminate processing
};
/// Number of "active" states in the state table (table size)
static const size_t state_table_size = sizeof(state_table) / sizeof(state_table[0]);

bool contract_parser_init(contract_parser_context_t *ctx, asset_info_t *asset_info) {
    memset(ctx, 0, sizeof(contract_parser_context_t));
    memset(asset_info, 0, sizeof(asset_info_t));
    ctx->asset_info = asset_info;
    return hash_init_sha256(&ctx->sha256_context);
}

void contract_parser_process(contract_parser_context_t *ctx, buffer_t *data) {
    // Update contract hash
    buffer_snapshot_t snapshot = buffer_snapshot(data);
    uint8_t byte;
    while (buffer_read_u8(data, &byte)) {
        if (!hash_update_u8(&ctx->sha256_context.header, byte)) {
            ctx->state = STATE_ERROR;
            return;
        }
    }
    buffer_restore(data, snapshot);

    // Process all bytes of JSON running state machine until we reach STATE_FINISH or STATE_ERROR
    while (buffer_can_read(data, 1) && ctx->state < (int)state_table_size) {
        if (state_table[ctx->state]) {
            parser_state_t new_state = state_table[ctx->state](ctx, data);
            if (new_state != ctx->state) {
                // Reset state-local variables and make transition to the new state
                ctx->has_opening_quotes = false;
                ctx->escape = false;
                ctx->nesting_level = 0;
                if (STATE_KEY == new_state) {
                    ctx->key_len = 0;
                    ctx->value_len = 0;
                }
                ctx->state = new_state;
            }
        } else {
            ctx->state = STATE_ERROR; // "Hole" in state table, should never happen
        }
    }
}

bool contract_parser_finalize(contract_parser_context_t *ctx,
                              uint8_t hash[static SHA256_LEN]) {
    _Static_assert(SHA256_LEN >= 1, "Wrong hash size");

    // Check if processing is complete and all required values obtained
    if (STATE_FINISH == ctx->state &&
        HAS_ALL_REQUIRED == (ctx->field_presence_flags & HAS_ALL_REQUIRED)) {
        if (hash_digest(&ctx->sha256_context.header, hash, SHA256_LEN)) {
            // Reverse byte order of the resulting hash
            for (size_t i = 0; i < SHA256_LEN >> 1; ++i) {
                uint8_t tmp = hash[i];
                hash[i] = hash[(SHA256_LEN - 1) - i];
                hash[(SHA256_LEN - 1) - i] = tmp;
            }
            return true;
        }
    }
    return false;
}

#endif // HAVE_LIQUID
