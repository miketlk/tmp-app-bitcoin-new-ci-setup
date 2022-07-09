#pragma once

#include "boilerplate/dispatcher.h"
#include "constants.h"
#include "handler/get_master_fingerprint.h"
#include "handler/get_extended_pubkey.h"
#include "handler/get_wallet_address.h"
#include "handler/register_wallet.h"
#include "handler/sign_psbt.h"
#include "handler/liquid_sign_pset.h"
#include "handler/sign_message.h"
#ifdef HAVE_LIQUID
#include "handler/liquid_get_master_blinding_key.h"
#include "handler/liquid_get_blinding_key.h"
#endif // HAVE_LIQUID

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_EXTENDED_PUBKEY = 0x00,
    REGISTER_WALLET = 0x02,
    GET_WALLET_ADDRESS = 0x03,
    SIGN_PSBT = 0x04,
    GET_MASTER_FINGERPRINT = 0x05,
    SIGN_MESSAGE = 0x10,
#ifdef HAVE_LIQUID
    LIQUID_GET_MASTER_BLINDING_KEY = 0xE1,
    LIQUID_GET_BLINDING_KEY = 0xE3,
#endif // HAVE_LIQUID
} command_e;

/**
 * Union of the global state for all the commands.
 */
typedef union {
    get_master_fingerprint_t get_master_fingerprint;
    get_extended_pubkey_state_t get_extended_pubkey_state;
    register_wallet_state_t register_wallet_state;
    get_wallet_address_state_t get_wallet_address_state;
#ifdef HAVE_LIQUID
    sign_pset_state_t sign_pset_state;
#else
    sign_psbt_state_t sign_psbt_state;
#endif
    sign_message_state_t sign_message_state;
#ifdef HAVE_LIQUID
    liquid_get_master_blinding_key_t liquid_get_master_blinding_key;
    liquid_get_blinding_key_t liquid_get_blinding_key;
#endif // HAVE_LIQUID
} command_state_t;

/**
 * Since only one command can execute at the same time, we share the same global space
 * for the command state of all the commands.
 **/
extern command_state_t G_command_state;
