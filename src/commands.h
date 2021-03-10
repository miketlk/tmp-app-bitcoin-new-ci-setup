#pragma once

#include "boilerplate/dispatcher.h"
#include "constants.h"
#include "handler/get_address.h"
#include "handler/get_pubkey.h"
#include "handler/get_sum_of_squares.h"

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_PUBKEY = 0x00,
    GET_ADDRESS = 0x01,
    GET_SUM_OF_SQUARES = 0xF0, /// compute the sum of the squares up to a number (I know, right?)
} command_e;

/**
 * Union of the global state for all the commands. 
 */
typedef union {
    get_address_state_t get_address_state;
    get_pubkey_state_t get_pubkey_state;
    get_sum_of_squares_state_t get_sum_of_squares_state;
    // ...state for other interruptible commands would be added here
} command_state_t;


/**
 * Since only one command can execute at the same time, we share the same global space
 * for the command state of all the commands.
 **/
extern command_state_t G_command_state;
