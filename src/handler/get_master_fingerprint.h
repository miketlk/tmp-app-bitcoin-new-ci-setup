#pragma once

#include "../boilerplate/dispatcher.h"

/// State of GET_MASTER_FINGERPRINT handler
typedef struct {
    /// Machine context for command dispatcher
    machine_context_t ctx;
} get_master_fingerprint_t;

/**
 * Handles GET_MASTER_FINGERPRINT command.
 *
 * @param[in,out] dispatcher_context
 *   Dispatcher context.
 */
void handler_get_master_fingerprint(dispatcher_context_t *dispatcher_context);
