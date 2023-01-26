#ifdef HAVE_LIQUID

#include <stdlib.h>
#include <string.h>

#include "cx.h"
#include "../util.h"

#include "pset_parse_rawtx.h"

#include "get_merkleized_map_value_hash.h"
#include "stream_preimage.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"

#include "../../common/buffer.h"
#include "../../common/parser.h"
#include "../../common/read.h"
#include "../../common/varint.h"
#include "../../crypto.h"

// Maximum size of a single transaction element
#define MAX_ELEMENT_LENGTH (16*1024*1024)
// Maximum number of elements in a vector
#define MAX_VECTOR_N_ELEMENTS 1024

// Flag of vout filed: pegin operation
#define VOUT_FLAG_IS_PEGIN (1LU << 30)
// Flag of vout filed: input has asset issuance data
#define VOUT_FLAG_HAS_ISSUANCE (1LU << 31)
// Bitmask used to remove issue and pegin flags
#define VOUT_VALUE_MASK 0x3FFFFFFFLU

// Identifiers of commitment field within transaction input
typedef enum {
    AMOUNT_COMMITMENT = 0,
    TOKEN_COMMITMENT,
    ASSET_ISSUANCE_N_COMMITMENTS // last value to define number of commitments
} asset_issuance_commitment_id_t;

// Values of byte defining commitment kind of asset issuance field
typedef enum {
    COMMITMENT_NONE = 0x00,
    COMMITMENT_NONCONFIDENTIAL = 0x01,
    COMMITMENT_CONFIDENTIAL, // any other byte values
} commitment_kind_t;

// Identifiers of "proof" records within input witness
typedef enum {
    AMOUNT_PROOF = 0,
    TOKEN_PROOF,
    TXIN_WITNESS_N_PROOFS // last value to define number of proofs
} txin_witness_proof_id_t;

// Identifiers of vector-type records within input witness
typedef enum {
    SCRIPT_WITNESS_VECTOR = 0,
    PEGIN_WITNESS_VECTOR,
    TXIN_WITNESS_N_VECTORS // last value to define number of vector records
} txin_witness_vector_id_t;

// Identifiers of "proof" records within output witness
typedef enum {
    SURJECTION_PROOF = 0,
    RANGE_PROOF,
    TXOUT_WITNESS_N_PROOFS // last value to define number of proofs
} txout_witness_proof_id_t;

struct parse_rawtx_state_s;  // forward declaration

typedef struct {
    struct parse_rawtx_state_s *parent_state;      // subparsers can access parent's state
    unsigned int scriptsig_size;                   // max 10_000 bytes
    unsigned int scriptsig_counter;                // counter of scriptsig bytes already received
    uint32_t vout;                                 // raw vout value including flags
    asset_issuance_commitment_id_t commitment_id;  // identifier of commitment within asset issuance
} parse_rawtxinput_state_t;

typedef struct {
    struct parse_rawtx_state_s *parent_state;
    unsigned int scriptpubkey_size;     // max 10_000 bytes
    unsigned int scriptpubkey_counter;  // counter of scriptpubkey bytes already received
} parse_rawtxoutput_state_t;

typedef struct {
    struct parse_rawtx_state_s *parent_state;
    union {
        txin_witness_proof_id_t proof_id;     // identifier of a currently parsed proof field
        txin_witness_vector_id_t witness_id;  // identifier of a currently parsed witness field
    };
    unsigned int vector_n_elements;  // number of vector elements
    unsigned int vector_index;       // index of the vector element in the witness field
    unsigned int element_length;     // size of the current element
    unsigned int element_bytes_read; // number of bytes read of the current element
    bool is_element_length_read;
} parse_in_witness_state_t;

typedef struct {
    struct parse_rawtx_state_s *parent_state;
    txout_witness_proof_id_t proof_id;  // identifier of a currently parsed field
    unsigned int field_length;          // size of the current field in bytes
    unsigned int field_bytes_read;      // number of bytes read of the current field
} parse_out_witness_state_t;

typedef struct parse_rawtx_state_s {
    cx_sha256_t *hash_context;
    cx_sha256_t *issuance_hash_context;

    bool is_segwit;
    unsigned int n_inputs;
    unsigned int n_outputs;

    union {
        // since the parsing stages of inputs, outputs and witnesses are disjoint, we reuse the same
        // space in memory
        struct {
            unsigned int in_counter; // index of input being read
            parser_context_t input_parser_context;
            parse_rawtxinput_state_t input_parser_state;
        };
        struct {
            unsigned int out_counter; // index of output being read
            parser_context_t output_parser_context;
            parse_rawtxoutput_state_t output_parser_state;
        };
        struct {
            unsigned int in_wit_counter;  // index of witness field being read
            parser_context_t in_witness_parser_context;
            parse_in_witness_state_t in_witness_parser_state;
        };
        struct {
            unsigned int out_wit_counter;  // index of witness field being read
            parser_context_t out_witness_parser_context;
            parse_out_witness_state_t out_witness_parser_state;
        };
    };

    int output_index;  // index of queried output, or -1

    txid_parser_outputs_t *parser_outputs;
    txid_parser_vout_t *parser_output_vout;

} parse_rawtx_state_t;

typedef struct pset_parse_rawtx_state_s {
    // internal state
    uint8_t store[33];               // buffer for unparsed data
    unsigned int store_data_length;  // size of data currently in store
    parse_rawtx_state_t parser_state;
    parser_context_t parser_context;
    bool parser_error;  // set to true if there was an error during parsing
} pset_parse_rawtx_state_t;

/*   PARSER FOR A RAWTX INPUT */

// parses the 32-bytes txid of an input in a rawtx
static int parse_rawtxinput_txid(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    uint8_t txid[32];
    bool result = dbuffer_read_bytes(buffers, txid, 32);
    if (result) {
        crypto_hash_update(&state->parent_state->hash_context->header, txid, 32);
    }
    return result;
}

// parses the 4-bytes vout of an input in a rawtx
static int parse_rawtxinput_vout(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    uint8_t vout_bytes[4];
    bool result = dbuffer_read_bytes(buffers, vout_bytes, 4);
    if (result) {
        parse_rawtx_state_t *parent = state->parent_state;
        state->vout = read_u32_le(vout_bytes, 0);
        crypto_hash_update(&parent->hash_context->header, vout_bytes, 4);
        if (parent->issuance_hash_context && !(state->vout & VOUT_FLAG_HAS_ISSUANCE)) {
            crypto_hash_update_u8(&parent->issuance_hash_context->header, 0x00);
        }
    }
    return result;
}

static int parse_rawtxinput_scriptsig_size(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    uint64_t scriptsig_size;
    bool result = dbuffer_read_varint(buffers, &scriptsig_size);

    if (result) {
        state->scriptsig_size = (unsigned int) scriptsig_size;

        crypto_hash_update_varint(&state->parent_state->hash_context->header, scriptsig_size);
    }
    return result;
}

// Does not read any bytes; only initializing the state before the next step
static int parse_rawtxinput_scriptsig_init(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    state->scriptsig_counter = 0;

    return 1;
}

static int parse_rawtxinput_scriptsig(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    uint8_t data[32];

    while (true) {
        unsigned int remaining_len = state->scriptsig_size - state->scriptsig_counter;

        // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32
        // unparsed bytes
        unsigned int data_len = MIN(32, remaining_len);

        bool read_result = dbuffer_read_bytes(buffers, data, data_len);
        if (!read_result) {
            return 0;  // could not read enough data
        }

        crypto_hash_update(&state->parent_state->hash_context->header, data, data_len);

        state->scriptsig_counter += data_len;

        if (state->scriptsig_counter == state->scriptsig_size) {
            return 1;  // done
        }
    }
}

static int parse_rawtxinput_sequence(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    uint8_t sequence_bytes[4];

    bool result = dbuffer_read_bytes(buffers, sequence_bytes, 4);
    if (result) {
        crypto_hash_update(&state->parent_state->hash_context->header, sequence_bytes, 4);
    }
    return result;
}

static int parse_rawtxinput_asset_issuance_nonce(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    if (!(state->vout & VOUT_FLAG_HAS_ISSUANCE)) {
        return 1;  // no asset issuance
    }

    uint8_t nonce[32];
    bool result = dbuffer_read_bytes(buffers, nonce, 32);
    if (result) {
        parse_rawtx_state_t *parent = state->parent_state;
        crypto_hash_update(&parent->hash_context->header, nonce, 32);
        if (parent->issuance_hash_context) {
            crypto_hash_update(&parent->issuance_hash_context->header, nonce, 32);
        }
    }
    return result;
}

static int parse_rawtxinput_asset_issuance_entropy(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    if (!(state->vout & VOUT_FLAG_HAS_ISSUANCE)) {
        return 1;  // no asset issuance
    }

    uint8_t entropy[32];
    bool result = dbuffer_read_bytes(buffers, entropy, 32);
    if (result) {
        parse_rawtx_state_t *parent = state->parent_state;
        crypto_hash_update(&parent->hash_context->header, entropy, 32);
        if (parent->issuance_hash_context) {
            crypto_hash_update(&parent->issuance_hash_context->header, entropy, 32);
        }
    }
    return result;
}

static int parse_rawtxinput_asset_issuance_commitments_init(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    state->commitment_id = AMOUNT_COMMITMENT; // begin with first commitment
    return 1;
}

static int parse_rawtxinput_asset_issuance_commitment(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    if (!(state->vout & VOUT_FLAG_HAS_ISSUANCE)) {
        return 1;  // no asset issuance
    }

    uint8_t data[33];
    size_t data_len = 0;

    uint8_t kind;
    bool result = dbuffer_peek(buffers, &kind); // peek first byte

    if(result) {
        if (kind == COMMITMENT_NONE) {
            data_len = 1;
        }
        else if (kind == COMMITMENT_NONCONFIDENTIAL) {
            data_len = 9;
        } else {
            kind = COMMITMENT_CONFIDENTIAL;
            data_len = 33;
        }
        result = dbuffer_read_bytes(buffers, data, data_len);
        if (result) {
            // handle commitment here if needed
            // state->commitment_id = {AMOUNT_COMMITMENT, TOKEN_COMMITMENT}
            parse_rawtx_state_t *parent = state->parent_state;
            crypto_hash_update(&parent->hash_context->header, data, data_len);
            if (parent->issuance_hash_context) {
                crypto_hash_update(&parent->issuance_hash_context->header, data, data_len);
            }
            ++state->commitment_id;
        }
    }
    return result ? 1 : 0;
}

static const parsing_step_t parse_rawtxinput_steps[] = {
    (parsing_step_t) parse_rawtxinput_txid,
    (parsing_step_t) parse_rawtxinput_vout,
    (parsing_step_t) parse_rawtxinput_scriptsig_size,
    (parsing_step_t) parse_rawtxinput_scriptsig_init,
    (parsing_step_t) parse_rawtxinput_scriptsig,
    (parsing_step_t) parse_rawtxinput_sequence,
    (parsing_step_t) parse_rawtxinput_asset_issuance_nonce,
    (parsing_step_t) parse_rawtxinput_asset_issuance_entropy,
    (parsing_step_t) parse_rawtxinput_asset_issuance_commitments_init,
    (parsing_step_t) parse_rawtxinput_asset_issuance_commitment, // amount commitment
    (parsing_step_t) parse_rawtxinput_asset_issuance_commitment  // token commitment
};

const int n_parse_rawtxinput_steps =
    sizeof(parse_rawtxinput_steps) / sizeof(parse_rawtxinput_steps[0]);

/*   PARSER FOR A RAWTX OUTPUT */

static int parse_rawtxoutput_asset(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    uint8_t header;
    bool result = dbuffer_peek(buffers, &header); // peek first byte

    if (result) {
        if (header != 0x01 && header != 0x0a && header != 0x0b) {
            return -1; // parser error
        }

        uint8_t asset[33];
        result = dbuffer_read_bytes(buffers, asset, sizeof(asset));

        if (result) {
            parse_rawtx_state_t *parent = state->parent_state;
            if (parent->hash_context) {
                crypto_hash_update(&parent->hash_context->header, asset, sizeof(asset));
            }
            if (parent->output_index != -1 &&
                parent->out_counter == (unsigned int) parent->output_index) {
                txid_parser_vout_t *vout = parent->parser_output_vout;
                if (header == 0x01) {
                    vout->asset.is_blinded = false;
                    reverse_copy(vout->asset.tag, asset + 1, sizeof(vout->asset.tag));
                } else {
                    vout->asset.is_blinded = true;
                    memcpy(vout->asset.commitment, asset, sizeof(vout->asset.commitment));
                }
            }
        }
    }
    return result;
}

static int parse_rawtxoutput_value(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    uint8_t header;
    bool result = dbuffer_peek(buffers, &header); // peek first byte
    if(result) {
        if (header != 0x01 && header != 0x08 && header != 0x09) {
            return -1; // parser error
        }

        uint8_t data[33];
        size_t data_len = (header == 0x01) ? 9 : 33;
        result = dbuffer_read_bytes(buffers, data, data_len);

        if (result) {
            parse_rawtx_state_t *parent = state->parent_state;
            txid_parser_vout_t *vout = parent->parser_output_vout;
            if(parent->hash_context) {
                crypto_hash_update(&parent->hash_context->header, data, data_len);
            }
            if (parent->output_index != -1 &&
                parent->out_counter == (unsigned int) parent->output_index) {
                if (data_len == 9) {
                    vout->amount.is_blinded = false;
                    vout->amount.value = read_u64_be(data, 1);
                } else {
                    vout->amount.is_blinded = true;
                    memcpy(vout->amount.commitment, data, sizeof(vout->amount.commitment));
                }
            }
        }
    }
    return result ? 1 : 0;
}

static int parse_rawtxoutput_ecdh_pubkey(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    uint8_t data[33];
    size_t data_len = 0;

    uint8_t flag;
    bool result = dbuffer_peek(buffers, &flag); // peek first byte
    if(result) {
        parse_rawtx_state_t *parent = state->parent_state;
        if (flag == 0x00) { // no ECDH public key
            data_len = 1;
        } else { // ECDH public key is provided
            data_len = 33;
        }
        result = dbuffer_read_bytes(buffers, data, data_len);
        if (result) {
            if(parent->hash_context) {
                crypto_hash_update(&parent->hash_context->header, data, data_len);
            }
#if RAWTX_DECODE_ECDH_PUBKEY
            txid_parser_vout_t *vout = parent->parser_output_vout;
            if (parent->output_index != -1) {
                if (parent->out_counter == (unsigned int) parent->output_index) {
                    if (data_len == 33) {
                        memcpy(vout->ecdh_pubkey, data, sizeof(vout->ecdh_pubkey));
                        vout->ecdh_pubkey_valid = true;
                    } else {
                        vout->ecdh_pubkey_valid = false;
                    }
                }
            }
#endif // RAWTX_DECODE_ECDH_PUBKEY
        }
    }
    return result ? 1 : 0;
}

static int parse_rawtxoutput_scriptpubkey_size(parse_rawtxoutput_state_t *state,
                                               buffer_t *buffers[2]) {
    uint64_t scriptpubkey_size;
    bool result = dbuffer_read_varint(buffers, &scriptpubkey_size);
    if (result) {
        state->scriptpubkey_size = (unsigned int) scriptpubkey_size;

        if(state->parent_state->hash_context) {
            crypto_hash_update_varint(&state->parent_state->hash_context->header, scriptpubkey_size);
        }

        if (state->parent_state->output_index != -1) {
            unsigned int relevant_output_index = (unsigned int) state->parent_state->output_index;
            if (state->parent_state->out_counter == relevant_output_index) {
                state->parent_state->parser_output_vout->scriptpubkey_len =
                    (unsigned int) scriptpubkey_size;
            }
        }
    }
    return result ? 1 : 0;
}

// Does not read any bytes; only initializing the state before the next step
static int parse_rawtxoutput_scriptpubkey_init(parse_rawtxoutput_state_t *state,
                                               buffer_t *buffers[2]) {
    (void) buffers;

    state->scriptpubkey_counter = 0;
    return 1;
}

static int parse_rawtxoutput_scriptpubkey(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    uint8_t data[32];

    while (true) {
        unsigned int remaining_len = state->scriptpubkey_size - state->scriptpubkey_counter;

        // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32
        // unparsed bytes
        unsigned int data_len = MIN(32, remaining_len);

        bool read_result = dbuffer_read_bytes(buffers, data, data_len);
        if (!read_result) {
            return 0;  // could not read enough data
        }

        if(state->parent_state->hash_context) {
            crypto_hash_update(&state->parent_state->hash_context->header, data, data_len);
        }

        if (state->parent_state->output_index != -1) {
            unsigned int relevant_output_index = (unsigned int) state->parent_state->output_index;
            if (state->parent_state->out_counter == relevant_output_index) {
                unsigned int scriptpubkey_len =
                    state->parent_state->parser_output_vout->scriptpubkey_len;
                if (scriptpubkey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
                    return -1;  // not expecting any scriptPubkey larger than
                                // MAX_PREVOUT_SCRIPTPUBKEY_LEN
                }

                if (state->scriptpubkey_counter + data_len <=
                    sizeof(state->parent_state->parser_output_vout->scriptpubkey)) {
                    memcpy(state->parent_state->parser_output_vout->scriptpubkey +
                           state->scriptpubkey_counter,
                           data,
                           data_len);
                } else {
                    return -1;  // unexpected buffer overflow
                }
            }
        }

        state->scriptpubkey_counter += data_len;

        if (state->scriptpubkey_counter == state->scriptpubkey_size) {
            return 1;  // done
        }
    }
}

static const parsing_step_t parse_rawtxoutput_steps[] = {
    (parsing_step_t) parse_rawtxoutput_asset,
    (parsing_step_t) parse_rawtxoutput_value,
    (parsing_step_t) parse_rawtxoutput_ecdh_pubkey,
    (parsing_step_t) parse_rawtxoutput_scriptpubkey_size,
    (parsing_step_t) parse_rawtxoutput_scriptpubkey_init,
    (parsing_step_t) parse_rawtxoutput_scriptpubkey,
};

const int n_parse_rawtxoutput_steps =
    sizeof(parse_rawtxoutput_steps) / sizeof(parse_rawtxoutput_steps[0]);

/*   PARSER FOR TRANSACTION INPUT WITNESS */

static int parse_in_witness_proofs_init(parse_in_witness_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    state->proof_id = AMOUNT_PROOF; // begin with amount proof

    return 1;
}

static int parse_in_witness_proof_length(parse_in_witness_state_t *state, buffer_t *buffers[2]) {
    uint64_t proof_length;
    bool result = dbuffer_read_varint(buffers, &proof_length);

    if (result) {
        if(proof_length > MAX_ELEMENT_LENGTH) {
            return -1;
        }
        state->element_length = (unsigned int) proof_length;
        state->element_bytes_read = 0;
    }
    return result ? 1 : 0;
}

static int parse_in_witness_proof(parse_in_witness_state_t *state, buffer_t *buffers[2]) {
    uint8_t data[32];

    while (true) {
        unsigned int remaining_len = state->element_length - state->element_bytes_read;

        // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32
        // unparsed bytes
        unsigned int data_len = MIN(32, remaining_len);

        bool read_result = dbuffer_read_bytes(buffers, data, data_len);
        if (!read_result) {
            return 0;  // could not read enough data
        }

        state->element_bytes_read += data_len;

        if (state->element_bytes_read == state->element_length) {
            // handle proof here if needed
            // state->proof_id = {AMOUNT_PROOF, TOKEN_PROOF}
            ++state->proof_id;
            return 1;  // done
        }
    }
}

static int parse_in_witness_vectors_init(parse_in_witness_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    state->witness_id = SCRIPT_WITNESS_VECTOR; // begin with script witness

    return 1;
}

static int parse_in_witness_vector_size(parse_in_witness_state_t *state, buffer_t *buffers[2]) {
    uint64_t vector_n_elements;
    bool result = dbuffer_read_varint(buffers, &vector_n_elements);

    if (result) {
        if(vector_n_elements > MAX_VECTOR_N_ELEMENTS) {
            return -1;
        }
        state->vector_n_elements = (unsigned int) vector_n_elements;
        state->vector_index = 0;
        state->is_element_length_read = false;
    }
    return result ? 1 : 0;
}

static int parse_in_witness_vector_elements(parse_in_witness_state_t *state, buffer_t *buffers[2]) {
    // read vector_n_elements elements
    while (state->vector_index < state->vector_n_elements) {
        // read the length of the current stack element (if not already read)
        if (!state->is_element_length_read) {
            // read the length of the next stack elements
            uint64_t element_length;
            if (!dbuffer_read_varint(buffers, &element_length)) {
                return 0;  // incomplete, read more data
            }
            if (element_length > MAX_ELEMENT_LENGTH) {
                return -1; // size of an element is outside of allowed boundaries
            }
            state->is_element_length_read = true;
            state->element_length = (unsigned int) element_length;
            state->element_bytes_read = 0;
        }

        while (state->element_bytes_read < state->element_length) {
            uint8_t data[32];
            unsigned int remaining_len = state->element_length - state->element_bytes_read;

            // We read in chunks of at most 32 bytes, so that we can always interrupt with less
            // than 32 unparsed bytes
            unsigned int data_len = MIN(32, remaining_len);
            if (!dbuffer_read_bytes(buffers, data, data_len)) {
                return 0;
            }
            state->element_bytes_read += data_len;
        }

        ++state->vector_index;
        state->is_element_length_read = false;
    }
    // handle witness field here if needed
    // state->witness_id = {SCRIPT_WITNESS_VECTOR, PEGIN_WITNESS_VECTOR}
    ++state->witness_id;
    return 1;
}

static const parsing_step_t parse_in_witness_steps[] = {
    (parsing_step_t) parse_in_witness_proofs_init,
    (parsing_step_t) parse_in_witness_proof_length,    // size of amount proof
    (parsing_step_t) parse_in_witness_proof,           // amount proof
    (parsing_step_t) parse_in_witness_proof_length,    // size of token proof
    (parsing_step_t) parse_in_witness_proof,           // token proof
    (parsing_step_t) parse_in_witness_vectors_init,
    (parsing_step_t) parse_in_witness_vector_size,     // number of elements in script witness
    (parsing_step_t) parse_in_witness_vector_elements, // elements of script witness
    (parsing_step_t) parse_in_witness_vector_size,     // number of elements in pegin witness
    (parsing_step_t) parse_in_witness_vector_elements  // elements of pegin witness
};

const int n_parse_in_witness_steps =
    sizeof(parse_in_witness_steps) / sizeof(parse_in_witness_steps[0]);

/*   PARSER FOR TRANSACTION OUTPUT WITNESS */

static int parse_out_witness_proofs_init(parse_out_witness_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    state->proof_id = SURJECTION_PROOF; // begin with amount proof

    return 1;
}

static int parse_out_witness_proof_length(parse_out_witness_state_t *state, buffer_t *buffers[2]) {
    uint64_t proof_length;
    bool result = dbuffer_read_varint(buffers, &proof_length);

    if (result) {
        if(proof_length > MAX_ELEMENT_LENGTH) {
            return -1;
        }
        state->field_length = (unsigned int) proof_length;
        state->field_bytes_read = 0;
    }
    return result ? 1 : 0;
}

static int parse_out_witness_proof(parse_out_witness_state_t *state, buffer_t *buffers[2]) {
    uint8_t data[32];

    while (true) {
        unsigned int remaining_len = state->field_length - state->field_bytes_read;

        // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32
        // unparsed bytes
        unsigned int data_len = MIN(32, remaining_len);

        bool read_result = dbuffer_read_bytes(buffers, data, data_len);
        if (!read_result) {
            return 0;  // could not read enough data
        }

        state->field_bytes_read += data_len;

        if (state->field_bytes_read == state->field_length) {
            // handle proof here if needed
            // state->proof_id = {AMOUNT_PROOF, TOKEN_PROOF}
            ++state->proof_id;
            return 1;  // done
        }
    }
}

static const parsing_step_t parse_out_witness_steps[] = {
    (parsing_step_t) parse_out_witness_proofs_init,
    (parsing_step_t) parse_out_witness_proof_length, // size of surjection proof
    (parsing_step_t) parse_out_witness_proof,        // surjection proof
    (parsing_step_t) parse_out_witness_proof_length, // size of range proof
    (parsing_step_t) parse_out_witness_proof,        // range proof
};

const int n_parse_out_witness_steps =
    sizeof(parse_out_witness_steps) / sizeof(parse_out_witness_steps[0]);

/*   PARSER FOR A FULL RAWTX */

static int parse_rawtx_version(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    uint8_t version_bytes[4];

    bool result = dbuffer_read_bytes(buffers, version_bytes, 4);
    if (result) {
        crypto_hash_update(&state->hash_context->header, version_bytes, 4);
    }
    return result;
}

// Checks if this transaction has a segregated witness defined by a flag which
// is for Elements transactions: 0x00 - non-segwit, 0x01 - segwit.
// The flag is added to the hash computation as 0x00 to produce txid.
static int parse_rawtx_check_segwit(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    uint8_t flag;
    bool result = dbuffer_read_u8(buffers, &flag);
    if (result) {
        if (flag == 0x00) {
            state->is_segwit = false;
        }
        else if (flag == 0x01) {
            state->is_segwit = true;
        } else {
            PRINTF("Unexpected flag while parsing a transaction: %02x.\n", flag);
            return -1;
        }
        crypto_hash_update_u8(&state->hash_context->header, 0x00);
    }
    return result;
}

static int parse_rawtx_input_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    uint64_t n_inputs;
    bool result = dbuffer_read_varint(buffers, &n_inputs);
    if (result) {
        state->n_inputs = (unsigned int) n_inputs;

        crypto_hash_update_varint(&state->hash_context->header, n_inputs);
    }
    return result;
}

static int parse_rawtx_inputs_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    state->in_counter = 0;

    parser_init_context(&state->input_parser_context, &state->input_parser_state);

    state->input_parser_state.parent_state = state;
    return 1;
}

static int parse_rawtx_inputs(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    while (state->in_counter < state->n_inputs) {
        while (true) {
            bool result = parser_run(parse_rawtxinput_steps,
                                     n_parse_rawtxinput_steps,
                                     &state->input_parser_context,
                                     buffers,
                                     pic);
            if (result != 1) {
                return result;  // stream exhausted, or error
            } else {
                break;  // completed parsing input
            }
        }

        ++state->in_counter;
        parser_init_context(&state->input_parser_context, &state->input_parser_state);
    }
    return 1;
}

static int parse_rawtx_output_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    uint64_t n_outputs;
    bool result = dbuffer_read_varint(buffers, &n_outputs);
    if (result) {
        state->n_outputs = (unsigned int) n_outputs;

        crypto_hash_update_varint(&state->hash_context->header, n_outputs);
    }
    return result;
}

static int parse_rawtx_outputs_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    state->out_counter = 0;
    parser_init_context(&state->output_parser_context, &state->output_parser_state);

    state->output_parser_state.parent_state = state;
    return 1;
}

static int parse_rawtx_outputs(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    while (state->out_counter < state->n_outputs) {
        while (true) {
            bool result = parser_run(parse_rawtxoutput_steps,
                                     n_parse_rawtxoutput_steps,
                                     &state->output_parser_context,
                                     buffers,
                                     pic);
            if (result != 1) {
                return result;  // stream exhausted, or error
            } else {
                break;  // completed parsing output
            }
        }

        ++state->out_counter;
        parser_init_context(&state->output_parser_context, &state->output_parser_state);
    }
    return 1;
}

static int parse_rawtx_locktime(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    uint8_t locktime_bytes[4];
    bool result = dbuffer_read_bytes(buffers, locktime_bytes, 4);
    if (result) {
        crypto_hash_update(&state->hash_context->header, locktime_bytes, 4);
    }
    return result;
}

static int parse_rawtx_in_witnesses_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    // only relevant for segwit txs
    state->in_wit_counter = 0;
    parser_init_context(&state->in_witness_parser_context, &state->in_witness_parser_state);
    state->in_witness_parser_state.parent_state = state;
    return 1;
}

// Parses the inputs' witness data; currently, no use is made of that data.
static int parse_rawtx_in_witnesses(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    if (!state->is_segwit) {
        return 1;  // no witnesses to parse
    }

    while (state->in_wit_counter < state->n_inputs) {
        while (true) {
            bool result = parser_run(parse_in_witness_steps,
                                     n_parse_in_witness_steps,
                                     &state->in_witness_parser_context,
                                     buffers,
                                     pic);
            if (result != 1) {
                return result;  // stream exhausted, or error
            } else {
                break;  // completed parsing input
            }
        }

        ++state->in_wit_counter;
        parser_init_context(&state->in_witness_parser_context, &state->in_witness_parser_state);
    }
    return 1;
}

static int parse_rawtx_out_witnesses_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    (void) buffers;

    // only relevant for segwit txs
    state->out_wit_counter = 0;
    parser_init_context(&state->out_witness_parser_context, &state->out_witness_parser_state);
    state->out_witness_parser_state.parent_state = state;
    return 1;
}

// Parses the inputs' witness data; currently, no use is made of that data.
static int parse_rawtx_out_witnesses(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    if (!state->is_segwit) {
        return 1;  // no witnesses to parse
    }

    while (state->out_wit_counter < state->n_outputs) {
        while (true) {
            bool result = parser_run(parse_out_witness_steps,
                                     n_parse_out_witness_steps,
                                     &state->out_witness_parser_context,
                                     buffers,
                                     pic);
            if (result != 1) {
                return result;  // stream exhausted, or error
            } else {
                break;  // completed parsing input
            }
        }

        ++state->out_wit_counter;
        parser_init_context(&state->out_witness_parser_context, &state->out_witness_parser_state);
    }
    return 1;
}

static const parsing_step_t parse_rawtx_steps[] = {(parsing_step_t) parse_rawtx_version,
                                                   (parsing_step_t) parse_rawtx_check_segwit,
                                                   (parsing_step_t) parse_rawtx_input_count,
                                                   (parsing_step_t) parse_rawtx_inputs_init,
                                                   (parsing_step_t) parse_rawtx_inputs,
                                                   (parsing_step_t) parse_rawtx_output_count,
                                                   (parsing_step_t) parse_rawtx_outputs_init,
                                                   (parsing_step_t) parse_rawtx_outputs,
                                                   (parsing_step_t) parse_rawtx_locktime,
                                                   (parsing_step_t) parse_rawtx_in_witnesses_init,
                                                   (parsing_step_t) parse_rawtx_in_witnesses,
                                                   (parsing_step_t) parse_rawtx_out_witnesses_init,
                                                   (parsing_step_t) parse_rawtx_out_witnesses };

const int n_parse_rawtx_steps = sizeof(parse_rawtx_steps) / sizeof(parse_rawtx_steps[0]);

static void cb_process_data(buffer_t *data, void *cb_state) {
    pset_parse_rawtx_state_t *state = (pset_parse_rawtx_state_t *) cb_state;

    if (state->parser_error) {
        // there was already a parsing error, ignore any additional data received
        return;
    }

    buffer_t store_buf = buffer_create(state->store, state->store_data_length);
    buffer_t *buffers[] = {&store_buf, data};

    int result =
        parser_run(parse_rawtx_steps, n_parse_rawtx_steps, &state->parser_context, buffers, pic);
    if (result == 0) {
        parser_consolidate_buffers(buffers, sizeof(state->store));
        state->store_data_length = store_buf.size;
    } else if (result < 0) {
        PRINTF("Parser error\n");
        state->parser_error = true;  // abort any remaining parsing
    }
}

int call_pset_parse_rawtx(dispatcher_context_t *dispatcher_context,
                          const merkleized_map_commitment_t *map,
                          const uint8_t *key,
                          int key_len,
                          int output_index,
                          txid_parser_outputs_t *outputs,
                          cx_sha256_t *issuance_hash_context) {
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);

    pset_parse_rawtx_state_t flow_state;

    // init parser

    flow_state.store_data_length = 0;
    flow_state.parser_error = false;
    parser_init_context(&flow_state.parser_context, &flow_state.parser_state);

    flow_state.parser_state.output_index = output_index;

    uint8_t value_hash[32];
    int res = call_get_merkleized_map_value_hash(dispatcher_context, map, key, key_len, value_hash);
    if (res < 0) {
        return -1;
    }

    // init the state of the parser (global)
    flow_state.parser_state.hash_context = &hash_context;
    flow_state.parser_state.issuance_hash_context = issuance_hash_context;

    memset(outputs, 0, sizeof(txid_parser_outputs_t));
    flow_state.parser_state.parser_outputs = outputs;
    flow_state.parser_state.parser_output_vout = &outputs->vout;

    res = call_stream_preimage(dispatcher_context, value_hash, NULL, cb_process_data, &flow_state);
    if (res < 0 || flow_state.parser_error) {
        return -1;
    }

    crypto_hash_digest(&hash_context.header, outputs->txid, 32);
    cx_hash_sha256(outputs->txid, 32, outputs->txid, 32);
    return 0;
}

static void cb_process_single_output_data(buffer_t *data, void *cb_state) {
    pset_parse_rawtx_state_t *state = (pset_parse_rawtx_state_t *) cb_state;

    if (state->parser_error) {
        // there was already a parsing error, ignore any additional data received
        return;
    }

    buffer_t store_buf = buffer_create(state->store, state->store_data_length);
    buffer_t *buffers[] = {&store_buf, data};

    int result =
        parser_run(parse_rawtxoutput_steps, n_parse_rawtxoutput_steps, &state->parser_context,
                   buffers, pic);
    if (result == 0) {
        parser_consolidate_buffers(buffers, sizeof(state->store));
        state->store_data_length = store_buf.size;
    } else if (result < 0) {
        PRINTF("Parser error\n");
        state->parser_error = true;  // abort any remaining parsing
    }
}

int call_pset_parse_rawtx_single_output(dispatcher_context_t *dispatcher_context,
                                        const merkleized_map_commitment_t *map,
                                        const uint8_t *key,
                                        int key_len,
                                        txid_parser_vout_t *output,
                                        cx_sha256_t *hash_context) {
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    pset_parse_rawtx_state_t flow_state;

    // init parser
    flow_state.store_data_length = 0;
    flow_state.parser_error = false;
    parser_init_context(&flow_state.parser_context, &flow_state.parser_state.output_parser_state);

    // init the state of the parser (global)
    memset(&flow_state.parser_state, 0, sizeof(flow_state.parser_state));
    flow_state.parser_state.hash_context = hash_context;
    flow_state.parser_state.output_index = flow_state.parser_state.out_counter = 0;
    flow_state.parser_state.output_parser_state.parent_state = &flow_state.parser_state;

    uint8_t value_hash[32];
    int res = call_get_merkleized_map_value_hash(dispatcher_context, map, key, key_len, value_hash);
    if (res < 0) {
        return -1;
    }

    memset(output, 0, sizeof(txid_parser_vout_t));
    flow_state.parser_state.parser_outputs = NULL;
    flow_state.parser_state.parser_output_vout = output;

    res = call_stream_preimage(dispatcher_context,
                               value_hash,
                               NULL,
                               cb_process_single_output_data,
                               &flow_state);
    if (res < 0 || flow_state.parser_error) {
        return -1;
    }

    return 0;
}

#endif // HAVE_LIQUID