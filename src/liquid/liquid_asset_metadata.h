#pragma once

#include <stdint.h>
#include <stdbool.h>
#ifndef SKIP_FOR_CMOCKA
#include "../boilerplate/dispatcher.h"
#include "merkle.h"
#endif
#include "liquid_assets.h"
#include "contract_parser.h"

/// Status of asset metadata
typedef enum {
    /// Asset metadata is ready
    ASSET_METADATA_READY = 0,
    /// Asset metadata is absent in PSET for the given asset tag
    ASSET_METADATA_ABSENT = -1,
    /// An error occurred while retreiving asset metadata or the metadata is invalid
    ASSET_METADATA_ERROR = -2
} asset_metadata_status_t;

/// Contex of asset metadata parser
typedef struct {
    /// State of the parser's FSM
    int state;
    /// Context of contract parser
    contract_parser_context_t contract_parser_ctx;
    /// Size of the contract
    uint32_t contract_len;
    /// Prevout transaction hash
    uint8_t prevout_txid[SHA256_LEN];
    /// Zero-based index of the transaction output
    uint32_t prevout_index;
    /// Index of a byte that is currently read
    size_t read_idx;
    /// Number of bytes remaining to read
    size_t read_remaining;
} asset_metadata_parser_context_t;

#ifndef SKIP_FOR_CMOCKA

/**
 * Reads and verifies asset metadata from a PSET map for the given asset tag.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context used for I/O operations with host.
 * @param[in] global_map
 *   Commitment to merkleized key-value map of global PSET fields.
 * @param[in] asset_tag
 *   Asset tag used to search for metadata.
 * @param[out] asset_info
 *   Pointer to asset information structure filled with received asset metadata.
 *
 * @return status of asset metadata.
 *
 * NOTE: this function does _not_ check that the keys are lexicographically sorted; the sanity check
 * needs to be done before.
 */
asset_metadata_status_t liquid_get_asset_metadata(
    dispatcher_context_t *dispatcher_context,
    const merkleized_map_commitment_t *global_map,
    const uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN],
    asset_info_t *asset_info);

#endif // SKIP_FOR_CMOCKA
