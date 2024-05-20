/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "boilerplate/io.h"
#include "boilerplate/sw.h"
#include "../common/base58.h"
#include "../common/buffer.h"
#include "../common/merkle.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/segwit_addr.h"
#include "../common/wallet.h"
#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "lib/policy.h"
#include "lib/get_preimage.h"

#include "get_wallet_address.h"
#include "client_commands.h"

/// State of the callback function obtaining `scriptPubKey` of the processed descriptor.
typedef struct {
    /// Dispatcher context.
    dispatcher_context_t *dc;
    /// State of the parent handler (GET_WALLET_ADDRESS handler)
    get_wallet_address_state_t *parent;
} get_script_callback_state_t;

/**
 * Computes wallet address.
 *
 * This step was separated from the main handler to optimize stack usage.
 *
 * @param[in,out] dc
 *   Dispatcher context.
 */
static void compute_address(dispatcher_context_t *dc);

/**
 * Sends response APDU.
 *
 * @param[in,out] dc
 *   Dispatcher context.
 */
static void send_response(dispatcher_context_t *dc);

/**
 * Obtains public key information information.
 *
 * @param[in,out] dc
 *   Dispatcher context.
 * @param[in,out] state
 *   State of GET_WALLET_ADDRESS handler.
 * @param[in] key_index
 *   Key index, zero-based.
 * @param[out] key_info
 *   Pointer to structure instance receiving key information.
 *
 * @return true if successful, false otherwise.
 */
static bool get_key_info(dispatcher_context_t *dc,
                         get_wallet_address_state_t *state,
                         uint32_t key_index,
                         policy_map_key_info_t *key_info) {
    int key_info_len = call_get_merkle_leaf_element(dc,
                                                    state->wallet_header_keys_info_merkle_root,
                                                    state->wallet_header_n_keys,
                                                    key_index,
                                                    state->key_info_str,
                                                    sizeof(state->key_info_str));
    if (key_info_len < 0) {
        return false;
    }

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(state->key_info_str, key_info_len);

    return 0 == parse_policy_map_key_info(&key_info_buffer, key_info);
}

void handler_get_wallet_address(dispatcher_context_t *dc) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    get_wallet_address_state_t *state = (get_wallet_address_state_t *) &G_command_state;

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

#ifdef HAVE_LIQUID
    state->pubkey_wildcard_id = KEY_WILDCARD_NONE;
#endif

    if (!buffer_read_u8(&dc->read_buffer, &state->display_address) ||
        !buffer_read_bytes(&dc->read_buffer, state->wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, state->wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    // change
    if (!buffer_read_u8(&dc->read_buffer, &state->is_change)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (state->is_change != 0 && state->is_change != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // address index
    if (!buffer_read_u32(&dc->read_buffer, &state->address_index, BE)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

#ifdef HAVE_LIQUID
    if (state->address_index > LIQUID_LAST_ADDRESS_INDEX) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
#endif

    // Fetch the serialized wallet policy from the client
    int serialized_wallet_policy_len = call_get_preimage(dc,
                                                         state->wallet_id,
                                                         state->serialized_wallet_policy,
                                                         sizeof(state->serialized_wallet_policy));
    if (serialized_wallet_policy_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    buffer_t serialized_wallet_policy_buf =
        buffer_create(state->serialized_wallet_policy, serialized_wallet_policy_len);
    if ((read_policy_map_wallet(&serialized_wallet_policy_buf, &state->wallet_header)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    memcpy(state->wallet_header_keys_info_merkle_root,
           state->wallet_header.keys_info_merkle_root,
           sizeof(state->wallet_header_keys_info_merkle_root));
    state->wallet_header_n_keys = state->wallet_header.n_keys;

    buffer_t policy_map_buffer =
        buffer_create(&state->wallet_header.policy_map, state->wallet_header.policy_map_len);

    {
        int ret = parse_policy_map(&policy_map_buffer,
                                   state->wallet_policy_map_bytes,
                                   sizeof(state->wallet_policy_map_bytes),
                                   BIP32_PUBKEY_VERSION,
                                   BIP32_PRIVKEY_VERSION);
        if (ret < 0) {
            PRINTF("Failure parsing policy map, error=%i\n", ret);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    // the binary OR of all the hmac bytes (so == 0 iff the hmac is identically 0)
    uint8_t hmac_or = 0;
    for (int i = 0; i < 32; i++) {
        hmac_or = hmac_or | state->wallet_hmac[i];
    }

    if (hmac_or == 0) {
        // No hmac, verify that the policy is a canonical one that is allowed by default
        state->address_type = get_policy_address_type(&state->wallet_policy_map);
        if (state->address_type == -1) {
            PRINTF("Non-standard policy, and no hmac provided\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

        if (state->wallet_header.n_keys != 1) {
            PRINTF("Standard wallets must have exactly 1 key\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // we check if the key is indeed internal
        uint32_t master_key_fingerprint = crypto_get_master_key_fingerprint();

        // Get infomation about the first and only public key
        policy_map_key_info_t key_info;
        if (!get_key_info(dc, state, 0, &key_info)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (!validate_policy_map_extended_pubkey(&key_info, BIP32_PUBKEY_VERSION)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (read_u32_be(key_info.master_key_fingerprint, 0) != master_key_fingerprint) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // generate pubkey and check if it matches
        char pubkey_derived[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
        int serialized_pubkey_len =
            get_serialized_extended_pubkey_at_path(key_info.master_key_derivation,
                                                   key_info.master_key_derivation_len,
                                                   BIP32_PUBKEY_VERSION,
                                                   pubkey_derived);
        if (serialized_pubkey_len == -1) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }

        if (strncmp(key_info.ext_pubkey, pubkey_derived, MAX_SERIALIZED_PUBKEY_LENGTH) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // check if derivation path is indeed standard

        // Based on the address type, we set the expected bip44 purpose for this canonical wallet
        int bip44_purpose = get_bip44_purpose(state->address_type);

        if (key_info.master_key_derivation_len != 3) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint32_t coin_types[2] = {BIP44_COIN_TYPE, BIP44_COIN_TYPE_2};

        uint32_t bip32_path[5];
        for (int i = 0; i < 3; i++) {
            bip32_path[i] = key_info.master_key_derivation[i];
        }
        bip32_path[3] = state->is_change ? 1 : 0;
        bip32_path[4] = state->address_index;

        if (!is_address_path_standard(bip32_path, 5, bip44_purpose, coin_types, 2, -1)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

#ifdef HAVE_LIQUID
        state->pubkey_wildcard_id = key_info.wildcard_id;
#endif

        state->is_wallet_canonical = true;
    } else {
        // Verify hmac

        if (!check_wallet_hmac(state->wallet_id, state->wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

#ifdef HAVE_LIQUID
        // Get infomation about the first public key to obtain its wildcad.
        policy_map_key_info_t key_info;
        if (!get_key_info(dc, state, 0, &key_info)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        state->pubkey_wildcard_id = key_info.wildcard_id;
#endif

        state->is_wallet_canonical = false;
    }

    // Compute the wallet id (sha256 of the serialization)
    get_policy_wallet_id(&state->wallet_header, state->computed_wallet_id);

    if (memcmp(state->wallet_id, state->computed_wallet_id, sizeof(state->wallet_id)) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    dc->next(compute_address);
}

#ifdef HAVE_LIQUID
/**
 * Callback function obtaining `scriptPubKey` of the processed descriptor.
 *
 * If `p_key_wildcard_to_verify` is not NULL, this function assumes it points to a constant which
 * must be compared with each of the wallet's public key's wildcard identifier. This parameter is
 * optional. If wildcard verification is not required it should be set to NULL.
 *
 * @param[in,out] state_in
 *   Callback state, stores necessary properties of the processed descriptor.
 * @param[in] bip44_change
 *   Change element of the derivation path, defined according to BIP 44.
 * @param[in] bip44_address_index
 *   Address index element of the derivation path, defined according to BIP 44.
 * @param[out] out_buffer
 *   Buffer receiving `scriptPubKey`.
 * @param[in] p_key_wildcard_to_verify
 *   If not NULL, requests to verify all wallet's public key wildcard IDs to be equal to value,
 *   pointed by this parameter.
 *
 * @return true if successful, false if error.
 */
static bool get_script_callback(void *state_in,
                                uint32_t bip44_change,
                                uint32_t bip44_address_index,
                                buffer_t *out_buffer,
                                const policy_map_key_wildcard_id_t *p_key_wildcard_to_verify) {
    get_script_callback_state_t *state = (get_script_callback_state_t *)state_in;

    return 0 < call_get_wallet_script(state->dc,
                                      liquid_policy_unwrap_ct(&state->parent->wallet_policy_map),
                                      state->parent->wallet_header_keys_info_merkle_root,
                                      state->parent->wallet_header_n_keys,
                                      bip44_change,
                                      bip44_address_index,
                                      out_buffer,
                                      p_key_wildcard_to_verify);
}
#endif

/**
 * Returns script address with support of ct() tag in wallet policy.
 *
 * @param[in,out] dc
 *   Dispatcher context.
 * @param[in,out] state
 *   Handler state.
 *
 * @return length of produced address in bytes.
 */
static inline int get_script_address_wrapper(dispatcher_context_t *dc,
                                             get_wallet_address_state_t *state) {
#ifdef HAVE_LIQUID
    if (liquid_policy_is_blinded(&state->wallet_policy_map)) {
        // Derive blinding public key from script
        uint8_t blinding_pubkey[33];
        get_script_callback_state_t callback_state = { .dc = dc, .parent = state };
        if(!liquid_get_blinding_public_key(&state->wallet_policy_map,
                                           state->script,
                                           state->script_len,
                                           state->pubkey_wildcard_id,
                                           get_script_callback,
                                           &callback_state,
                                           blinding_pubkey)) {
            return -1;
        }

        int addr_len = liquid_get_script_confidential_address(state->script,
                                                              state->script_len,
                                                              &G_liquid_network_config,
                                                              blinding_pubkey,
                                                              sizeof(blinding_pubkey),
                                                              state->address,
                                                              sizeof(state->address));

        explicit_bzero(blinding_pubkey, sizeof(blinding_pubkey));
        return addr_len;
    }
#endif // HAVE_LIQUID

    return get_script_address(state->script,
                              state->script_len,
                              state->address,
                              sizeof(state->address));
}

// stack-intensive, split from the previous function to optimize stack usage
static void compute_address(dispatcher_context_t *dc) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    get_wallet_address_state_t *state = (get_wallet_address_state_t *) &G_command_state;
    buffer_t script_buf = buffer_create(state->script, sizeof(state->script));

    state->script_len = call_get_wallet_script(dc,
#ifdef HAVE_LIQUID
                                               liquid_policy_unwrap_ct(&state->wallet_policy_map),
#else
                                               &state->wallet_policy_map
#endif
                                               state->wallet_header_keys_info_merkle_root,
                                               state->wallet_header_n_keys,
                                               state->is_change,
                                               state->address_index,
                                               &script_buf,
                                               NULL);
    if (state->script_len < 0) {
        SEND_SW(dc, SW_BAD_STATE);  // unexpected
        return;
    }

    state->address_len = get_script_address_wrapper(dc, state);

    if (state->address_len < 0) {
        SEND_SW(dc, SW_BAD_STATE);  // unexpected
        return;
    }

    if (state->display_address == 0) {
        dc->next(send_response);
    } else {
        ui_display_wallet_address(dc,
                                  state->is_wallet_canonical ? NULL : state->wallet_header.name,
                                  state->address,
                                  send_response);
    }
}

static void send_response(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    SEND_RESPONSE(dc, state->address, state->address_len, SW_OK);
}
