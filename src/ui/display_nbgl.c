#ifdef HAVE_NBGL

#include <stdint.h>

#include "nbgl_use_case.h"
#include "./display.h"
#include "./menu.h"
#include "io.h"

typedef struct {
    const char *confirm;           // text displayed in last transaction page
    const char *confirmed_status;  // text displayed in confirmation page (after long press)
    const char *rejected_status;   // text displayed in rejection page (after reject confirmed)
    nbgl_layoutTagValue_t tagValuePair[3];
    nbgl_layoutTagValueList_t tagValueList;
    nbgl_pageInfoLongPress_t infoLongPress;
    int extOutputCount;
    int currentOutput;
    bool displayPrompt;
} TransactionContext_t;

enum {
    CANCEL_TOKEN = 0,
    CONFIRM_TOKEN,
    SILENT_CONFIRM_TOKEN,
    BACK_TOKEN_TRANSACTION,   // for most transactions
    BACK_TOKEN_SELFTRANSFER,  // special case when it's a self-transfer (no external outputs)
    BACK_TOKEN_MESSAGE,
    MESSAGE_DISPLAYABLE_TOKEN,
    MESSAGE_NON_DISPLAYABLE_TOKEN,
    MESSAGE_CANCEL_TOKEN,

};

extern bool G_was_processing_screen_shown;
static TransactionContext_t transactionContext;

// ux_flow_response
static void ux_flow_response_false(void) {
    set_ux_flow_response(false);
}

static void ux_flow_response_true(void) {
    set_ux_flow_response(true);
}

static void ux_flow_response(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
    } else {
        ux_flow_response_false();
    }
}

// Statuses
static void status_confirmation_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseStatus(transactionContext.confirmed_status, true, ui_menu_main);
    } else {
        ux_flow_response_false();
        nbgl_useCaseStatus(transactionContext.rejected_status, false, ui_menu_main);
    }
}

static void status_cancel(void) {
    status_confirmation_callback(false);
}

static void confirm_cancel(void) {
    nbgl_useCaseConfirm("Reject transaction?",
                        "",
                        "Yes, Reject",
                        "Go back to transaction",
                        status_cancel);
}

static void confirm_message_cancel(void) {
    nbgl_useCaseConfirm("Reject message?", "", "Yes, Reject", "Go back to message", status_cancel);
}

static void start_processing_callback_light(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseSpinner("Processing");
    } else {
        ux_flow_response_false();
        nbgl_useCaseStatus(transactionContext.rejected_status, false, ui_menu_main);
    }
}

static void start_processing_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseSpinner("Processing");
    } else {
        confirm_cancel();
    }
}

static void start_processing_message_callback(bool confirm) {
    if (confirm) {
        ux_flow_response_true();
        nbgl_useCaseSpinner("Processing");
    } else {
        confirm_message_cancel();
    }
}

static void transaction_confirm_callback(int token, uint8_t index) {
    (void) index;

    switch (token) {
        case CANCEL_TOKEN:
            confirm_cancel();
            break;
        case CONFIRM_TOKEN:
            start_processing_callback(true);
            break;
        case SILENT_CONFIRM_TOKEN:
            ux_flow_response(true);
            break;
        case BACK_TOKEN_TRANSACTION:
            ui_accept_transaction_flow(false);
            break;
        case BACK_TOKEN_SELFTRANSFER:
            ui_accept_transaction_flow(true);
            break;
        case BACK_TOKEN_MESSAGE:
            decrease_streaming_index();
            ux_flow_response(true);
            break;
        case MESSAGE_DISPLAYABLE_TOKEN:
            increase_streaming_index();
            ux_flow_response(true);
            break;
        case MESSAGE_NON_DISPLAYABLE_TOKEN:
            ui_sign_message_confirm_flow();
            break;
        case MESSAGE_CANCEL_TOKEN:
            confirm_message_cancel();
            break;
        default:
            PRINTF("Unhandled token : %d", token);
    }
}

// Continue callbacks
static void continue_light_notify_callback(void) {
    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;

    transactionContext.infoLongPress.icon = &APP_MAIN_ICON_64PX;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = CONFIRM_TOKEN;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = transactionContext.confirm;

    nbgl_useCaseStaticReviewLight(&transactionContext.tagValueList,
                                  &transactionContext.infoLongPress,
                                  "Cancel",
                                  status_confirmation_callback);
}

static void continue_light_processing_callback(void) {
    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;

    transactionContext.infoLongPress.icon = &APP_MAIN_ICON_64PX;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = CONFIRM_TOKEN;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = transactionContext.confirm;

    nbgl_useCaseStaticReviewLight(&transactionContext.tagValueList,
                                  &transactionContext.infoLongPress,
                                  "Cancel",
                                  start_processing_callback_light);
}

static void continue_callback(void) {
    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;

    transactionContext.infoLongPress.icon = &APP_MAIN_ICON_64PX;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = CONFIRM_TOKEN;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = transactionContext.confirm;

    nbgl_useCaseStaticReview(&transactionContext.tagValueList,
                             &transactionContext.infoLongPress,
                             "Cancel",
                             start_processing_callback);
}

static void continue_message_callback(void) {
    transactionContext.tagValueList.pairs = transactionContext.tagValuePair;

    transactionContext.infoLongPress.icon = &APP_MAIN_ICON_64PX;
    transactionContext.infoLongPress.longPressText = "Approve";
    transactionContext.infoLongPress.longPressToken = CONFIRM_TOKEN;
    transactionContext.infoLongPress.tuneId = TUNE_TAP_CASUAL;
    transactionContext.infoLongPress.text = transactionContext.confirm;

    nbgl_useCaseStaticReview(&transactionContext.tagValueList,
                             &transactionContext.infoLongPress,
                             "Cancel",
                             start_processing_message_callback);
}

// Transaction flow
static void transaction_confirm(int token, uint8_t index) {
    (void) index;

    // If it's a self-transfer, the UX is slightly different
    int backToken =
        transactionContext.extOutputCount == 0 ? BACK_TOKEN_SELFTRANSFER : BACK_TOKEN_TRANSACTION;

    if (token == CONFIRM_TOKEN) {
        nbgl_pageNavigationInfo_t info = {.activePage = transactionContext.extOutputCount + 1,
                                          .nbPages = transactionContext.extOutputCount + 2,
                                          .navType = NAV_WITH_TAP,
                                          .progressIndicator = true,
                                          .navWithTap.backButton = true,
                                          .navWithTap.backToken = backToken,
                                          .navWithTap.nextPageText = NULL,
                                          .navWithTap.quitText = "Reject transaction",
                                          .quitToken = CANCEL_TOKEN,
                                          .tuneId = TUNE_TAP_CASUAL};

        nbgl_pageContent_t content = {.type = INFO_LONG_PRESS,
                                      .infoLongPress.icon = &APP_MAIN_ICON_64PX,
                                      .infoLongPress.text = transactionContext.confirm,
                                      .infoLongPress.longPressText = "Hold to sign",
                                      .infoLongPress.longPressToken = CONFIRM_TOKEN,
                                      .infoLongPress.tuneId = TUNE_TAP_NEXT};

        nbgl_pageDrawGenericContent(&transaction_confirm_callback, &info, &content);
        nbgl_refresh();
    } else {
        confirm_cancel();
    }
}

void ui_accept_transaction_flow(bool is_self_transfer) {
    if (!is_self_transfer) {
        transactionContext.tagValuePair[0].item = "Fees";
        transactionContext.tagValuePair[0].value = g_ui_state.validate_transaction.fee;

        transactionContext.tagValueList.nbPairs = 1;
    } else {
        transactionContext.tagValuePair[0].item = "Amount";
        transactionContext.tagValuePair[0].value = "Self-transfer";
        transactionContext.tagValuePair[1].item = "Fees";
        transactionContext.tagValuePair[1].value = g_ui_state.validate_transaction.fee;

        transactionContext.tagValueList.nbPairs = 2;
    }

    transactionContext.confirm =
#ifdef HAVE_LIQUID
        "Sign transaction\nto send asset?";
#else
        "Sign transaction\nto send Bitcoin?";
#endif
    transactionContext.confirmed_status = "TRANSACTION\nSIGNED";
    transactionContext.rejected_status = "Transaction rejected";

    nbgl_pageNavigationInfo_t info = {.activePage = transactionContext.extOutputCount,
                                      .nbPages = transactionContext.extOutputCount + 2,
                                      .navType = NAV_WITH_TAP,
                                      .progressIndicator = true,
                                      .navWithTap.backButton = false,
                                      .navWithTap.nextPageText = "Tap to continue",
                                      .navWithTap.nextPageToken = CONFIRM_TOKEN,
                                      .navWithTap.quitText = "Reject transaction",
                                      .quitToken = CANCEL_TOKEN,
                                      .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {.type = TAG_VALUE_LIST,
                                  .tagValueList.nbPairs = transactionContext.tagValueList.nbPairs,
                                  .tagValueList.pairs = transactionContext.tagValuePair};

    nbgl_pageDrawGenericContent(&transaction_confirm, &info, &content);
    nbgl_refresh();
}

void ui_display_transaction_prompt(const int external_outputs_total_count) {
    transactionContext.currentOutput = 0;
    transactionContext.extOutputCount = external_outputs_total_count;

    transactionContext.rejected_status = "Transaction rejected";

    nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
#ifdef HAVE_LIQUID
                            "Review transaction\nto send asset",
#else
                            "Review transaction\nto send Bitcoin",
#endif
                            "",
                            "Reject transaction",
                            ux_flow_response_true,
                            confirm_cancel);
}

// Display outputs
static void display_output(void) {
    transactionContext.rejected_status = "Transaction rejected";

    nbgl_pageNavigationInfo_t info = {.activePage = transactionContext.currentOutput - 1,
                                      .nbPages = transactionContext.extOutputCount + 2,
                                      .navType = NAV_WITH_TAP,
                                      .progressIndicator = true,
                                      .navWithTap.backButton = false,
                                      .navWithTap.nextPageText = "Tap to continue",
                                      .navWithTap.nextPageToken = SILENT_CONFIRM_TOKEN,
                                      .navWithTap.quitText = "Reject transaction",
                                      .quitToken = CANCEL_TOKEN,
                                      .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {.type = TAG_VALUE_LIST,
                                  .tagValueList.nbMaxLinesForValue = 8,
                                  .tagValueList.nbPairs = transactionContext.tagValueList.nbPairs,
                                  .tagValueList.pairs = transactionContext.tagValuePair};

    nbgl_pageDrawGenericContent(&transaction_confirm_callback, &info, &content);
    nbgl_refresh();
}

void ui_display_output_address_amount_flow(int index) {
#ifdef HAVE_LIQUID
#error Not implemented
#endif
    snprintf(g_ui_state.validate_output.index,
             sizeof(g_ui_state.validate_output.index),
             "#%d",
             index);

    transactionContext.currentOutput++;

    transactionContext.tagValuePair[0].item = "Output";
    transactionContext.tagValuePair[0].value = g_ui_state.validate_output.index;

    transactionContext.tagValuePair[1].item = "Amount";
    transactionContext.tagValuePair[1].value = g_ui_state.validate_output.amount;

    transactionContext.tagValuePair[2].item = "Address";
    transactionContext.tagValuePair[2].value = g_ui_state.validate_output.address_or_description;

    transactionContext.tagValueList.nbPairs = 3;

    display_output();
}

void ui_display_output_address_amount_no_index_flow(int index) {
#ifdef HAVE_LIQUID
#error Not implemented
#endif
    (void) index;
    transactionContext.currentOutput++;

    transactionContext.tagValuePair[0].item = "Amount";
    transactionContext.tagValuePair[0].value = g_ui_state.validate_output.amount;

    transactionContext.tagValuePair[1].item = "Address";
    transactionContext.tagValuePair[1].value = g_ui_state.validate_output.address_or_description;

    transactionContext.tagValueList.nbPairs = 2;

    display_output();
}

// Continue light notify callback
void ui_display_pubkey_flow(void) {
    transactionContext.tagValuePair[0].item = "Path";
    transactionContext.tagValuePair[0].value = g_ui_state.path_and_pubkey.bip32_path_str;

    transactionContext.tagValuePair[1].item = "Public key";
    transactionContext.tagValuePair[1].value = g_ui_state.path_and_pubkey.pubkey;
    transactionContext.tagValueList.nbPairs = 2;

    transactionContext.confirm = "Approve public key";
    transactionContext.confirmed_status = "PUBLIC KEY\nAPPROVED";
    transactionContext.rejected_status = "Public key rejected";

    nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
                            "Confirm public key",
                            "",
                            "Cancel",
                            continue_light_notify_callback,
                            status_cancel);
}

void ui_display_receive_in_wallet_flow(void) {
    transactionContext.tagValuePair[0].item = "Wallet name";
    transactionContext.tagValuePair[0].value = g_ui_state.wallet.wallet_name;

    transactionContext.tagValuePair[1].item = "Wallet Address";
    transactionContext.tagValuePair[1].value = g_ui_state.wallet.address;

    transactionContext.tagValueList.nbPairs = 2;

    transactionContext.confirm = "Confirm address";
    transactionContext.confirmed_status = "ADDRESS\nCONFIRMED";
    transactionContext.rejected_status = "Address rejected";

    nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
                            "Receive\nin known wallet",
                            "",
                            "Cancel",
                            continue_light_notify_callback,
                            status_cancel);
}

void ui_display_policy_map_cosigner_pubkey_flow(void) {
    transactionContext.tagValuePair[0].item = "Index";
    transactionContext.tagValuePair[0].value = g_ui_state.cosigner_pubkey_and_index.signer_index;

    transactionContext.tagValuePair[1].item = "Public key";
    transactionContext.tagValuePair[1].value = g_ui_state.cosigner_pubkey_and_index.pubkey;

    transactionContext.tagValueList.nbPairs = 2;

    transactionContext.confirm = "Confirm cosigner";
    transactionContext.confirmed_status = "COSIGNER\nREGISTERED";
    transactionContext.rejected_status = "Cosigner rejected";

    nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
                            "Register cosigner",
                            "",
                            "Cancel",
                            continue_light_notify_callback,
                            ux_flow_response_false);
}

static void suspicious_pubkey_warning(void) {
    nbgl_useCaseReviewStart(&C_round_warning_64px,
                            "WARNING",
                            "The derivation path\nis unusual",
                            "Cancel",
                            continue_light_notify_callback,
                            ux_flow_response_false);
}

void ui_display_pubkey_suspicious_flow(void) {
    transactionContext.tagValuePair[0].item = "Path";
    transactionContext.tagValuePair[0].value = g_ui_state.path_and_pubkey.bip32_path_str;

    transactionContext.tagValuePair[1].item = "Public key";
    transactionContext.tagValuePair[1].value = g_ui_state.path_and_pubkey.pubkey;

    transactionContext.tagValueList.nbPairs = 2;

    transactionContext.confirm = "Approve public key";
    transactionContext.confirmed_status = "PUBLIC KEY\nAPPROVED";
    transactionContext.rejected_status = "Public key rejected";
    nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
                            "Confirm public key",
                            "",
                            "Cancel",
                            suspicious_pubkey_warning,
                            status_cancel);
}

// Continue light processing callback
void ui_display_register_wallet_flow(void) {
    transactionContext.tagValuePair[0].item = "Name";
    transactionContext.tagValuePair[0].value = g_ui_state.wallet.wallet_name;

    transactionContext.tagValuePair[1].item = "Policy map";
    transactionContext.tagValuePair[1].value = g_ui_state.wallet.descriptor_template;

    transactionContext.tagValueList.nbPairs = 2;

    transactionContext.confirm = "Register Wallet";
    transactionContext.confirmed_status = "WALLET\nREGISTERED";
    transactionContext.rejected_status = "Wallet rejected";

    nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
                            "Register wallet",
                            "",
                            "Cancel",
                            continue_light_processing_callback,
                            ux_flow_response_false);
}

static void ui_display_message_content_flow(bool displayable, uint8_t pageCount) {
    uint8_t token;
    if (displayable) {
        token = MESSAGE_DISPLAYABLE_TOKEN;
    } else {
        token = MESSAGE_NON_DISPLAYABLE_TOKEN;
    }

    nbgl_pageNavigationInfo_t info = {
        .activePage = get_streaming_index(),
        .nbPages = pageCount + 1,
        .navType = NAV_WITH_TAP,
        .progressIndicator = true,
        .navWithTap.backButton = displayable && get_streaming_index() != 0,
        .navWithTap.backToken = BACK_TOKEN_MESSAGE,
        .navWithTap.nextPageText = "Tap to continue",
        .navWithTap.nextPageToken = token,
        .navWithTap.quitText = "Reject message",
        .quitToken = MESSAGE_CANCEL_TOKEN,
        .tuneId = TUNE_TAP_CASUAL};

    nbgl_pageContent_t content = {.type = TAG_VALUE_LIST,
                                  .tagValueList.nbPairs = transactionContext.tagValueList.nbPairs,
                                  .tagValueList.pairs = transactionContext.tagValuePair,
                                  .tagValueList.wrapping = true};

    transactionContext.tagValueList.nbPairs = 0;
    nbgl_pageDrawGenericContent(&transaction_confirm_callback, &info, &content);
    nbgl_refresh();
}

void ui_set_display_prompt(void) {
    transactionContext.displayPrompt = true;
}

static void display_message_content(void) {
    ui_display_message_content_flow(true, transactionContext.extOutputCount);
}

void ui_sign_message_content_flow(uint8_t pageCount) {
    transactionContext.rejected_status = "Message rejected";

    if (get_streaming_index() == 0) {
        transactionContext.tagValuePair[0].item = "Path";
        transactionContext.tagValuePair[0].value = g_ui_state.path_and_message.bip32_path_str;
        transactionContext.tagValueList.nbPairs = 1;
    }

    transactionContext.tagValuePair[transactionContext.tagValueList.nbPairs].item =
        "Message content";
    transactionContext.tagValuePair[transactionContext.tagValueList.nbPairs].value =
        g_ui_state.path_and_message.message;

    transactionContext.tagValueList.nbPairs++;

    transactionContext.extOutputCount = pageCount;

    if (transactionContext.displayPrompt) {
        nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
                                "Review message",
                                "",
                                "Cancel",
                                display_message_content,
                                status_cancel);
        transactionContext.displayPrompt = false;
    } else {
        display_message_content();
    }
}

void ui_sign_message_path_hash_and_confirm_flow(void) {
    transactionContext.rejected_status = "Message rejected";

    transactionContext.tagValuePair[0].item = "Path";
    transactionContext.tagValuePair[0].value = g_ui_state.path_and_message.bip32_path_str;
    transactionContext.tagValuePair[1].item = "Message hash";
    transactionContext.tagValuePair[1].value = g_ui_state.path_and_message.message;

    transactionContext.tagValueList.nbPairs = 2;

    ui_display_message_content_flow(false, 0);
}

void ui_sign_message_confirm_flow(void) {
    transactionContext.tagValueList.nbPairs = 0;
    transactionContext.confirm = "Sign Message";
    transactionContext.confirmed_status = "MESSAGE\nSIGNED";
    transactionContext.rejected_status = "Message rejected";

    continue_message_callback();
}

void ui_display_spend_from_wallet_flow(void) {
    transactionContext.tagValuePair[0].item = "Wallet name";
    transactionContext.tagValuePair[0].value = g_ui_state.wallet.wallet_name;

    transactionContext.tagValueList.nbPairs = 1;

    transactionContext.confirm = "Confirm wallet name";
    transactionContext.confirmed_status = "WALLET NAME\nCONFIRMED";
    transactionContext.rejected_status = "Wallet name rejected";

    nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
                            "Spend from\nknown wallet",
                            "",
                            "Cancel",
                            continue_callback,
                            ux_flow_response_false);
}

// Address flow
static void address_display(void) {
    nbgl_useCaseAddressConfirmation(g_ui_state.wallet.address, status_confirmation_callback);
}

void ui_display_default_wallet_address_flow(void) {
    transactionContext.confirm = "Confirm address";
    transactionContext.confirmed_status = "ADDRESS\nVERIFIED";
    transactionContext.rejected_status = "Address verification\ncancelled";

    nbgl_useCaseReviewStart(&APP_MAIN_ICON_64PX,
#ifdef HAVE_LIQUID
                            "Verify\naddress",
#else
                            "Verify Bitcoin\naddress",
#endif
                            "",
                            "Cancel",
                            address_display,
                            status_cancel);
}

// Warning Flows
void ui_warn_high_fee_flow(void) {
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "Warning",
                       "Fees are above 10%\n of total amount",
                       "Continue",
                       "Reject",
                       ux_flow_response);
}

void ui_display_warning_external_inputs_flow(void) {
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "Warning",
                       "There are external inputs",
                       "Continue",
                       "Reject if not sure",
                       ux_flow_response);
}

void ui_display_unverified_segwit_inputs_flows(void) {
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "Warning",
                       "Unverified inputs\nUpdate Ledger Live or\nthird party wallet software",
                       "Continue",
                       "Reject if not sure",
                       ux_flow_response);
}

void ui_display_nondefault_sighash_flow(void) {
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "Warning",
                       "Non-default sighash",
                       "Continue",
                       "Reject if not sure",
                       ux_flow_response);
}

// Statuses
void ui_display_post_processing_confirm_message(bool success) {
    if (success) {
        nbgl_useCaseStatus("MESSAGE\nSIGNED", true, ux_flow_response_true);
    } else {
        nbgl_useCaseStatus("Message rejected", false, ux_flow_response_false);
    }
}

void ui_display_post_processing_confirm_wallet_registation(bool success) {
    if (success) {
        nbgl_useCaseStatus("WALLET\nREGISTERED", true, ux_flow_response_true);
    } else {
        nbgl_useCaseStatus("Wallet rejected", false, ux_flow_response_false);
    }
}

void ui_display_post_processing_confirm_transaction(bool success) {
    if (success) {
        nbgl_useCaseStatus("TRANSACTION\nSIGNED", true, ux_flow_response_true);
    } else {
        nbgl_useCaseStatus("Transaction rejected", false, ux_flow_response_false);
    }
}

void ui_display_post_processing_confirm_wallet_spend(bool success) {
    if (success) {
        nbgl_useCaseStatus("WALLET NAME\nCONFIRMED", true, ux_flow_response_true);
    } else {
        nbgl_useCaseStatus("Wallet name rejected", false, ux_flow_response_false);
    }
}

#ifdef HAVE_LIQUID

void ui_display_output_address_amount_flow_ext(int index,
                                               bool display_asset_tag,
                                               bool asset_is_reissuance_token) {
#error Not implemented
}

void ui_warn_unknown_asset_flow(void) {
#error Not implemented
}

void ui_display_validate_asset_flow(void) {
#error Not implemented
}

#endif  // HAVE_LIQUID

#endif  // HAVE_NBGL
