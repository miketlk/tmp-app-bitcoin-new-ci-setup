#pragma once

#include "os.h"
#include "cx.h"

#define MAX_OUTPUT_TO_CHECK 100
#define MAX_COIN_ID 13
#define MAX_SHORT_COIN_ID 5

#define MAGIC_TRUSTED_INPUT 0x32
#define MAGIC_DEV_KEY 0x01

#define ZCASH_USING_OVERWINTER 0x01
#define ZCASH_USING_OVERWINTER_SAPLING 0x02

enum btchip_modes_e {
    BTCHIP_MODE_ISSUER = 0x00,
    BTCHIP_MODE_SETUP_NEEDED = 0xff,
    BTCHIP_MODE_WALLET = 0x01,
    BTCHIP_MODE_RELAXED_WALLET = 0x02,
    BTCHIP_MODE_SERVER = 0x04,
    BTCHIP_MODE_DEVELOPER = 0x08,
};

enum btchip_options_e {
    BTCHIP_OPTION_UNCOMPRESSED_KEYS = 0x01,
    BTCHIP_OPTION_DETERMINISTIC_SIGNATURE = 0x02,
    BTCHIP_OPTION_FREE_SIGHASHTYPE = 0x04,
    BTCHIP_OPTION_SKIP_2FA_P2SH = 0x08,
    BTCHIP_OPTION_ALLOW_ARBITRARY_CHANGE = 0x10
};

/**
 * Current state of an untrusted transaction hashing
 */
enum btchip_transaction_state_e {
    /** No transaction in progress */
    BTCHIP_TRANSACTION_NONE = 0x00,
    /** Transaction defined, waiting for an input to be hashed */
    BTCHIP_TRANSACTION_DEFINED_WAIT_INPUT = 0x01,
    /** Transaction defined, input hashing in progress, pending input script
       data */
    BTCHIP_TRANSACTION_INPUT_HASHING_IN_PROGRESS_INPUT_SCRIPT = 0x02,
    /** Transaction defined, input hashing done, pending output hashing for this
       input */
    BTCHIP_TRANSACTION_INPUT_HASHING_DONE = 0x03,
    /** Transaction defined, waiting for an output to be hashed */
    BTCHIP_TRANSACTION_DEFINED_WAIT_OUTPUT = 0x04,
    /** Transaction defined, output hashing in progress for a complex script,
       pending output script data */
    BTCHIP_TRANSACTION_OUTPUT_HASHING_IN_PROGRESS_OUTPUT_SCRIPT = 0x05,
    /** Transaction defined, output hashing done, pending finalization */
    BTCHIP_TRANSACTION_OUTPUT_HASHING_DONE = 0x06,
    /** Extra data present */
    BTCHIP_TRANSACTION_PROCESS_EXTRA = 0x07,
    /** Transaction parsed */
    BTCHIP_TRANSACTION_PARSED = 0x08,
    /** Transaction parsed, ready to prepare for signature after validating the
       user outputs */
    BTCHIP_TRANSACTION_PRESIGN_READY = 0x09,
    /** Transaction fully parsed, ready to be signed */
    BTCHIP_TRANSACTION_SIGN_READY = 0x0a,
};
typedef enum btchip_transaction_state_e btchip_transaction_state_t;

enum btchip_output_parsing_state_e {
    BTCHIP_OUTPUT_PARSING_NONE = 0x00,
    BTCHIP_OUTPUT_PARSING_NUMBER_OUTPUTS = 0x01,
    BTCHIP_OUTPUT_PARSING_OUTPUT = 0x02,
    BTCHIP_OUTPUT_FINALIZE_TX = 0x03,
    BTCHIP_BIP44_CHANGE_PATH_VALIDATION = 0x04
};
typedef enum btchip_output_parsing_state_e btchip_output_parsing_state_t;


typedef union multi_hash {
    cx_sha256_t sha256;
    cx_blake2b_t blake2b;
} multi_hash;

struct segwit_hash_s {
    union multi_hash hashPrevouts;
};
struct segwit_cache_s {
    unsigned char hashedPrevouts[32];
    unsigned char hashedSequence[32];
    unsigned char hashedOutputs[32];
};

/**
 * Structure defining an operation on a transaction
 */
struct btchip_transaction_context_s {
    /** Transient over signing components */

    /** Remaining number of inputs/outputs to process for this transaction */
    unsigned long int transactionRemainingInputsOutputs;
    /** Index of the currently processed input/output for this transaction */
    unsigned long int transactionCurrentInputOutput;
    /** Remaining script bytes to process for the current input or output */
    unsigned long int scriptRemaining;

    /** Persistent over signing components */

    /** State of the transaction, type btchip_transaction_state_t */
    unsigned char transactionState;
    /** Computed sum of transaction inputs or value of the output to convert to
     * a trusted input */
    unsigned char transactionAmount[8];
    /** Flag indicating if this transaction has been processed before */
    unsigned char firstSigned;
    /** If the transaction is relaxed */
    unsigned char relaxed;
    /** If the transaction consumes a P2SH input */
    unsigned char consumeP2SH;
};
typedef struct btchip_transaction_context_s btchip_transaction_context_t;

struct btchip_tmp_output_s {
    /** Change address if initialized */
    unsigned char changeAddress[20];
    /** Flag set if the change address was initialized */
    unsigned char changeInitialized;
    /** Flag set if the change address was checked */
    unsigned char changeChecked;
    /** Flag set if the change address can be submitted */
    unsigned char changeAccepted;
    /** Flag set if the outputs have been fragmented */
    unsigned char multipleOutput;
};
typedef struct btchip_tmp_output_s btchip_tmp_output_t;


/**
 * Structure to configure the bitcoin application for a given altcoin
 *
 */
typedef enum btchip_coin_flags_e {
    FLAG_PEERCOIN_UNITS=1,
    FLAG_PEERCOIN_SUPPORT=2,
    FLAG_SEGWIT_CHANGE_SUPPORT=4
} btchip_coin_flags_t;

typedef enum btchip_coin_kind_e {
    COIN_KIND_BITCOIN_TESTNET,
    COIN_KIND_BITCOIN,
    COIN_KIND_BITCOIN_CASH,
    COIN_KIND_BITCOIN_GOLD,
    COIN_KIND_LITECOIN,
    COIN_KIND_DOGE,
    COIN_KIND_DASH,
    COIN_KIND_ZCASH,
    COIN_KIND_KOMODO,
    COIN_KIND_RFU,
    COIN_KIND_STRATIS,
    COIN_KIND_PEERCOIN,
    COIN_KIND_PIVX,
    COIN_KIND_STEALTH,
    COIN_KIND_VIACOIN,
    COIN_KIND_VERTCOIN,
    COIN_KIND_DIGIBYTE,
    COIN_KIND_QTUM,
    COIN_KIND_BITCOIN_PRIVATE,
    COIN_KIND_XRHODIUM,
    COIN_KIND_HORIZEN,
    COIN_KIND_GAMECREDITS,
    COIN_KIND_FIRO,
    COIN_KIND_ZCLASSIC,
    COIN_KIND_XSN,
    COIN_KIND_NIX,
    COIN_KIND_LBRY,
    COIN_KIND_RESISTANCE,
    COIN_KIND_RAVENCOIN,
    COIN_KIND_HYDRA
} btchip_coin_kind_t;

// TODO: remove !!!
typedef struct global_context_s {
    // new app
    unsigned long bip32_pubkey_version;

    // legacy
    unsigned short bip44_coin_type;
    unsigned short bip44_coin_type2;
    unsigned short p2pkh_version;
    unsigned short p2sh_version;
    unsigned char family;
    //unsigned char* iconsuffix;// will use the icon provided on the stack (maybe)
    char coinid[14]; // used coind id for message signature prefix
    char name[16]; // for ux displays
    char name_short[6]; // for unit in ux displays
    char native_segwit_prefix_val[5];
    const char* native_segwit_prefix; // null if no segwit prefix
    unsigned int forkid;
    unsigned int zcash_consensus_branch_id;
    btchip_coin_kind_t kind;
    unsigned int flags;
} global_context_t;
