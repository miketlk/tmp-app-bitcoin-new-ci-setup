#pragma once

#include "../boilerplate/dispatcher.h"

typedef struct {
    machine_context_t ctx;
} liquid_get_blinding_key_t;

void handler_liquid_get_blinding_key(dispatcher_context_t *dispatcher_context);
