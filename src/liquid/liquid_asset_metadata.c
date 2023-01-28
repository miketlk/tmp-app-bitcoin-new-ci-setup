#include <stdint.h>
#include <string.h>

#include "os.h"
#include "pset.h"
#include "util.h"
#include "liquid_asset_metadata.h"

#ifndef SKIP_FOR_CMOCKA
#include "stream_merkleized_map_value.h"
#endif

#ifdef SKIP_FOR_CMOCKA
    #define STATIC_NO_TEST
#else
    /// Declares symbol as static in non-test build
    #define STATIC_NO_TEST static
#endif

/// Number of bytes in prevoutIndex field (32-bit little endian uint)
#define PREVOUT_INDEX_N_BYTES 4

/// States of the parser state machine
typedef enum {
    STATE_CONTRACT_LEN,  ///< Parsing contractLen
    STATE_CONTRACT,      ///< Parsing contract
    STATE_PREVOUT_TXID,  ///< Parsing prevoutTxid
    STATE_PREVOUT_INDEX, ///< Parsing prevoutIndex
    STATE_FINISH,        ///< Processing is finished, remaining data ignored
    STATE_ERROR          ///< Error ocurred during processing
} parser_state_t;

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
typedef parser_state_t (*parser_state_fn_t)(asset_metadata_parser_context_t *ctx, buffer_t *data);

/**
 * Implements STATE_CONTRACT_LEN: parsing contractLen.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
parser_state_t state_contract_len(asset_metadata_parser_context_t *ctx, buffer_t *data) {
    uint8_t byte;
    while (buffer_read_u8(data, &byte)) {
        if (0 == ctx->read_idx++) {
            if (byte > 0 && byte <= 0xfc) {
                ctx->contract_len = byte;
                return STATE_CONTRACT;
            } else if (byte == 0xfd) {
                ctx->read_remaining = 2;
            } else if (byte == 0xfe) {
                ctx->read_remaining = 4;
            } else {
                return STATE_ERROR;
            }
        } else {
            ctx->contract_len = (ctx->contract_len << 8) | byte;
            if (0 == --ctx->read_remaining) {
                return ctx->contract_len ? STATE_CONTRACT : STATE_ERROR;
            }
        }
    }
    return STATE_CONTRACT_LEN;
}

/**
 * Implements STATE_CONTRACT: parsing contract.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
parser_state_t state_contract(asset_metadata_parser_context_t *ctx, buffer_t *data) {
    size_t proc_len = MIN(buffer_remaining(data), ctx->contract_len - ctx->read_idx);

    if (proc_len) {
        buffer_t contract_data = buffer_create(buffer_get_cur(data), proc_len);
        contract_parser_process(&ctx->contract_parser_ctx, &contract_data);
        if (!buffer_seek_cur(data, proc_len)) {
            return STATE_ERROR;
        }
        ctx->read_idx += proc_len;
    }

    return ctx->read_idx < ctx->contract_len ? STATE_CONTRACT : STATE_PREVOUT_TXID;
}

/**
 * Implements STATE_PREVOUT_TXID: parsing prevoutTxid.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
parser_state_t state_prevout_txid(asset_metadata_parser_context_t *ctx, buffer_t *data) {
    uint8_t byte;
    while (buffer_read_u8(data, &byte)) {
        ctx->prevout_txid[ctx->read_idx++] = byte;
        if (sizeof(ctx->prevout_txid) == ctx->read_idx) {
            return STATE_PREVOUT_INDEX;
        }
    }
    return STATE_PREVOUT_TXID;
}

/**
 * Implements STATE_PREVOUT_INDEX: parsing prevoutIndex.
 *
 * @param[in,out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Data buffer to process.
 *
 * @return new FSM state.
 */
parser_state_t state_prevout_index(asset_metadata_parser_context_t *ctx, buffer_t *data) {
    uint8_t byte;
    while (buffer_read_u8(data, &byte)) {
        ctx->prevout_index |= ((uint32_t)byte) << (8 * ctx->read_idx);
        if (PREVOUT_INDEX_N_BYTES == ++ctx->read_idx) {
            return STATE_FINISH;
        }
    }
    return STATE_PREVOUT_INDEX;
}

/// State table containg pointer to functions implementing state-specific logic
static const parser_state_fn_t state_table[] = {
    [STATE_CONTRACT_LEN] = state_contract_len,
    [STATE_CONTRACT] = state_contract,
    [STATE_PREVOUT_TXID] = state_prevout_txid,
    [STATE_PREVOUT_INDEX] = state_prevout_index,
    // STATE_FINISH and STATE_ERROR are not defined here because they terminate processing
};
/// Number of "active" states in the state table (table size)
static const size_t state_table_size = sizeof(state_table) / sizeof(state_table[0]);

/**
 * Initializes asset metadata parser.
 *
 * @param[out] ctx
 *   Instance of parser context to initialize.
 * @param[out] asset_info
 *   Poiter to structure instance receiving decoded values, saved in context.
 *
 * @return true on success, false in case of error.
 */
STATIC_NO_TEST bool asset_metadata_parser_init(asset_metadata_parser_context_t *ctx,
                                               asset_info_t *asset_info) {
    memset(ctx, 0, sizeof(asset_metadata_parser_context_t));
    if (!contract_parser_init(&ctx->contract_parser_ctx, asset_info)) {
        return false;
    }
    return true;
}

/**
 * Processes input asset metadata.
 *
 * @param[out] ctx
 *   Parser context.
 * @param[in,out] data
 *   Input data buffer to process.
 *
 * @return true on success, false in case of error.
 */
STATIC_NO_TEST void asset_metadata_parser_process(asset_metadata_parser_context_t *ctx,
                                                  buffer_t *data) {
    while (buffer_can_read(data, 1) && ctx->state < (int)state_table_size) {
        if (state_table[ctx->state]) {
            const parser_state_fn_t state_fn = PIC(state_table[ctx->state]);
            parser_state_t new_state = state_fn(ctx, data);
            if (new_state != ctx->state) {
                // Reset state-local variables and make transition to the new state
                ctx->read_idx = 0;
                ctx->read_remaining = 0;
                ctx->state = new_state;
            }
        } else {
            ctx->state = STATE_ERROR; // "Hole" in state table, should never happen
        }
    }
}

/**
 * Finalizes asset metadata parsing.
 *
 * @param[out] ctx
 *   Parser context.
 * @param asset_tag
 *   Reference asset tag used to verify asset metadata.
 *
 * @return true on success, false in case of error or if parsed metadata is invalid.
 */
STATIC_NO_TEST bool asset_metadata_parser_finalize(
    asset_metadata_parser_context_t *ctx,
    const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]) {

    uint8_t contract_hash[SHA256_LEN];
    uint8_t computed_asset_tag[LIQUID_ASSET_TAG_LEN];

    if (STATE_FINISH == ctx->state && ctx->contract_len) {
        bool ok = contract_parser_finalize(&ctx->contract_parser_ctx, contract_hash);
        ok = ok && liquid_compute_asset_tag(contract_hash,
                                            ctx->prevout_txid,
                                            ctx->prevout_index,
                                            computed_asset_tag);
        // Verify that metadata produces the same asset tag
        ok = ok && 0 == memcmp(computed_asset_tag, asset_tag, LIQUID_ASSET_TAG_LEN);
        return ok;
    }
    return false;
}

#ifndef SKIP_FOR_CMOCKA

/// Key of PSET field containing asset metadata
static const uint8_t pset_metadata_key[] = PSBT_ELEMENTS_HWW_GLOBAL_ASSET_METADATA;

/**
 * Callback function processing streamed asset metadata.
 *
 * @param[in,out] data
 *   Input data buffer to process.
 * @param cb_state
 *   User-provided callback state.
 */
static void cb_process_data(buffer_t *data, void *cb_state) {
    asset_metadata_parser_process((asset_metadata_parser_context_t*)cb_state, data);
}

asset_metadata_status_t liquid_get_asset_metadata(
    dispatcher_context_t *dispatcher_context,
    const merkleized_map_commitment_t *global_map,
    const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN],
    asset_info_t *asset_info) {
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    // Initialize context
    asset_metadata_parser_context_t context;
    if (!asset_metadata_parser_init(&context, asset_info)) {
        return ASSET_METADATA_ERROR;
    }

    // Compose key with keydata
    uint8_t key[sizeof(pset_metadata_key) + LIQUID_ASSET_TAG_LEN];
    memcpy(key, pset_metadata_key, sizeof(pset_metadata_key));
    reverse_copy(key + sizeof(pset_metadata_key), asset_tag, LIQUID_ASSET_TAG_LEN);

    int len = call_stream_merkleized_map_value(dispatcher_context,
                                               global_map,
                                               key,
                                               sizeof(key),
                                               /* len_callback= */ NULL,
                                               cb_process_data,
                                               &context);
    if (len < 0) {
        return ASSET_METADATA_ABSENT;
    }

    return asset_metadata_parser_finalize(&context, asset_tag) ?
        ASSET_METADATA_READY : ASSET_METADATA_ERROR;
}

#endif // SKIP_FOR_CMOCKA
