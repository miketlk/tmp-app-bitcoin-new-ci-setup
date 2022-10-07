/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2019 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#if defined HAVE_LIQUID && !defined(_LIQUID_ASSETS_H__)
#define _LIQUID_ASSETS_H__

#include <stdint.h>
#include "../constants.h"

/// Ticker for unknown asset
#define UNKNOWN_ASSET_TICKER "???"
/// Number of decimal digits in fractional part of an unknown asset
#define UNKNOWN_ASSET_DECIMALS 0

/// Information about an asset
typedef struct {
    /// Asset tag
    uint8_t tag[32];
    /// Ticker, a text string
    char ticker[MAX_ASSET_TICKER_LENGTH + 1];
    /// Number of decimal digits in fractional part
    uint8_t decimals;
} asset_definition_t;

/**
 * Finds information about asset
 *
 * @param[in] tag asset tag for look-up
 *
 * @return pointer to asset definition structure or NULL if not found
 */
const asset_definition_t* liquid_get_asset_info(const uint8_t tag[static 32]);

#endif

