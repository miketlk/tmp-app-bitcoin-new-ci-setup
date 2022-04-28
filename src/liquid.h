#pragma once

/**
 * The label used to derive the master blinding key according to SLIP-0077
 */
#define SLIP77_LABEL "\0SLIP-0077"
#define SLIP77_LABEL_LEN \
    (sizeof(SLIP77_LABEL) - 1)  // sizeof counts the terminating 0

/**
 * Maximum length of the 'script' field of the LIQUID_GET_BLINDING_KEY command, that is currently
 * supported
 */
#define GET_BLINDING_KEY_MAX_SCRIPT_LEN 252

/**
 * Minimum and maximum length of private key in WIF Base58 format
 */
#define WIF_PRIVATE_KEY_LENGTH_MIN 51
#define WIF_PRIVATE_KEY_LENGTH_MAX 52