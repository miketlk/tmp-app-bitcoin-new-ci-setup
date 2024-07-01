#pragma once

/**
 * Instruction class of the Bitcoin application.
 */
#define CLA_APP_LEGACY 0xE0

/**
 * Instruction class of the Bitcoin application.
 */
#define CLA_APP 0xE1

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

/**
 * Maximum length of SegWit prefix in characters
 */
#ifdef HAVE_LIQUID
#define MAX_SEGWIT_PREFIX_LENGTH 3
#else
#define MAX_SEGWIT_PREFIX_LENGTH sizeof(COIN_NATIVE_SEGWIT_PREFIX)
#endif

#ifdef HAVE_LIQUID
#define MAX_ADDRESS_LENGTH_STR (118 + MAX_SEGWIT_PREFIX_LENGTH)
#else // HAVE_LIQUID
/**
 * Maximum length of a serialized address (in characters).
 * Segwit addresses can reach 74 characters; 76 on regtest because of the longer "bcrt" prefix.
 */
#ifdef COIN_NATIVE_SEGWIT_PREFIX
#define MAX_ADDRESS_LENGTH_STR (72 + sizeof(COIN_NATIVE_SEGWIT_PREFIX))
#else
// To be removed once altcoins are moved to a separate repo, as COIN_NATIVE_SEGWIT_PREFIX
// will always be defined
#define MAX_ADDRESS_LENGTH_STR 74
#endif
#endif // HAVE_LIQUID

/**
 * Maximum transaction length (bytes).
 */
#define MAX_TRANSACTION_LEN 510

/**
 * Maximum DER-encoded signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72

/**
 * Exponent used to convert mBTC to BTC unit (N BTC = N * 10^3 mBTC).
 */
#define EXPONENT_SMALLEST_UNIT 3

/**
 * Maximum scriptPubKey length for an input that we can sign.
 */
#define MAX_PREVOUT_SCRIPTPUBKEY_LEN 34  // P2WSH's scriptPubKeys are the longest supported

/**
 * Maximum scriptPubKey length for an output that we can recognize.
 */
#define MAX_OUTPUT_SCRIPTPUBKEY_LEN 83  // max 83 for OP_RETURN; other scripts are shorter

/**
 * Maximum length of a wallet registered into the device (characters), excluding terminating NULL.
 */
#define MAX_WALLET_NAME_LENGTH 16

/**
 * Maximum length (characters) of a base58check-encoded serialized extended pubkey.
 */
#define MAX_SERIALIZED_PUBKEY_LENGTH 113

// SIGHASH flags
#define SIGHASH_ALL          0x00000001
#define SIGHASH_NONE         0x00000002
#define SIGHASH_SINGLE       0x00000003
#define SIGHASH_ANYONECANPAY 0x00000080
#ifdef HAVE_LIQUID
#define SIGHASH_RANGEPROOF   0x00000040
#endif

/**
 * Number of decimal digits in fractional part of Bitcoin amount
 * (Satoshis per Bitcoin expressed as a power of 10)
 */
#define BITCOIN_DECIMALS 8

/**
 * Maximum length (characters) of an asset ticker
 */
#ifdef HAVE_LIQUID
#define MAX_ASSET_TICKER_LENGTH 10
#else
#define MAX_ASSET_TICKER_LENGTH 5
#endif

/**
 * Number of bytes in SHA-256 hash code
 */
#define SHA256_LEN 32

/**
 * Maximum length (characters) of transaction type.
 * Currently supported types: 'transaction', 'issuance', 'reissuance', 'burn'
 */
#define MAX_TRANSACTION_TYPE_LEN 15
