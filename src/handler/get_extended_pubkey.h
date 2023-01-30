#pragma once

#include "../common/bip32.h"
#include "../boilerplate/dispatcher.h"

/// State of GET_EXTENDED_PUBKEY handler
typedef struct {
    /// Machine context for command dispatcher
    machine_context_t ctx;
    /// Serialized public key
    char serialized_pubkey_str[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} get_extended_pubkey_state_t;

/**
 * Handles GET_EXTENDED_PUBKEY command.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context.
 */
void handler_get_extended_pubkey(dispatcher_context_t *dispatcher_context);
