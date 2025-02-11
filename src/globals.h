#pragma once

#include <stdint.h>

#include "ux.h"

#include "boilerplate/io.h"
#include "commands.h"
#include "constants.h"

/**
 * Global buffer for interactions between SE and MCU.
 */
extern uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

/**
 * Global variable with the length of APDU response to send back.
 */
extern uint16_t G_output_len;

/**
 * Global structure to perform asynchronous UX aside IO operations.
 */
extern ux_state_t G_ux;

/**
 * Global structure with the parameters to exchange with the BOLOS UX application.
 */
extern bolos_ux_params_t G_ux_params;

#ifdef HAVE_BOLOS_APP_STACK_CANARY
/**
 * Constant used to check stack integrity.
 */
#define STACK_CANARY_CONSTANT 0xDEAD0031
/**
 * Variable placed at the end of stack to monitor its integrity.
 */
extern unsigned int app_stack_canary;
#endif
