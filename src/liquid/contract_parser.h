#pragma once

#ifdef HAVE_LIQUID

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "constants.h"
#include "liquid_assets.h"

#ifndef SKIP_FOR_CMOCKA
#include "cx.h"
#include "dispatcher.h"
#include "merkle.h"
#endif // SKIP_FOR_CMOCKA

typedef struct {
    /// Will contain the computed contract hash
    uint8_t contract_hash[SHA256_LEN];
    /// Ticker, a text string
    char ticker[MAX_ASSET_TICKER_LENGTH + 1];
    /// Number of decimal digits in fractional part
    uint8_t precision;
} contract_parser_outputs_t;

#ifndef SKIP_FOR_CMOCKA

bool liquid_parse_json_contract(dispatcher_context_t *dispatcher_context,
                                const merkleized_map_commitment_t *map,
                                const uint8_t *key,
                                int key_len,
                                contract_parser_outputs_t *outputs);
#endif // SKIP_FOR_CMOCKA

#endif // HAVE_LIQUID
