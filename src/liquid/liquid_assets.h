#pragma once

#if defined HAVE_LIQUID && !defined(_LIQUID_ASSETS_H__)
#define _LIQUID_ASSETS_H__

#include <stdint.h>
#include <stdbool.h>
#include "../constants.h"

/// Ticker for unknown asset
#define UNKNOWN_ASSET_TICKER "???"
/// Number of decimal digits in fractional part of an unknown asset
#define UNKNOWN_ASSET_DECIMALS 0
/// Size of asset tag in bytes
#define LIQUID_ASSET_TAG_LEN SHA256_LEN
/// Minimum value of decimals
#define LIQUID_ASSET_DECIMALS_MIN 0
/// Maximum value of decimals
#define LIQUID_ASSET_DECIMALS_MAX 19

/// Information about an asset
typedef struct {
    /// Ticker, a text string
    char ticker[MAX_ASSET_TICKER_LENGTH + 1];
    /// Number of decimal digits in fractional part
    uint8_t decimals;
} asset_info_t;

/// Definition of an asset
typedef struct {
    /// Asset tag
    uint8_t tag[LIQUID_ASSET_TAG_LEN];
    /// Information about an asset
    asset_info_t info;
} asset_definition_t;

/**
 * Finds information about asset
 *
 * @param[in] tag asset tag for look-up
 *
 * @return pointer to asset definition structure or NULL if not found
 */
const asset_info_t* liquid_get_asset_info(const uint8_t tag[static LIQUID_ASSET_TAG_LEN]);

/**
 * Computes asset tag (asset ID).
 *
 * Contract hash should be single SHA-256 hash of canonicalized contract JSON with reverse byte
 * order (like in TXID).
 *
 * @param[in] contract_hash
 *   Ricardian contract hash, 32 bytes, SHA-256 with reverse byte order.
 * @param[in] prevout_txid
 *   Prevout transaction hash, 32 bytes.
 * @param[in] prevout_index
 *   Zero-based index of the transaction output.
 * @param[out] asset_tag
 *   Pointer to a 32-byte output buffer receiving computed asset tag.
 *
 * @return true on success, false in case of error.
 */
bool liquid_compute_asset_tag(const uint8_t contract_hash[static SHA256_LEN],
                              const uint8_t prevout_txid[static SHA256_LEN],
                              uint32_t prevout_index,
                              uint8_t asset_tag[static LIQUID_ASSET_TAG_LEN]);


#endif

