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

#include <stdint.h>  // uint*_t
#include <string.h>  // memset, explicit_bzero

#include <assert.h>

#include "os.h"
#include "ux.h"

#include "globals.h"
#include "io.h"
#include "sw.h"
#include "ui/menu.h"
#include "boilerplate/apdu_parser.h"
#include "boilerplate/constants.h"
#include "boilerplate/dispatcher.h"

#include "commands.h"

// common declarations between legacy and new code; will refactor it out later
#include "swap/swap_lib_calls.h"
#include "swap/swap_globals.h"
#include "swap/handle_swap_sign_transaction.h"
#include "swap/handle_get_printable_amount.h"
#include "swap/handle_check_address.h"
#include "main.h"
#include "tests.h"

#ifdef HAVE_BOLOS_APP_STACK_CANARY
extern unsigned int app_stack_canary;
#endif

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

command_state_t G_command_state;
dispatcher_context_t G_dispatcher_context;

uint8_t G_app_mode;

// clang-format off
const command_descriptor_t COMMAND_DESCRIPTORS[] = {
    {
        .cla = CLA_APP,
        .ins = GET_EXTENDED_PUBKEY,
        .handler = (command_handler_t)handler_get_extended_pubkey
    },
    {
        .cla = CLA_APP,
        .ins = GET_WALLET_ADDRESS,
        .handler = (command_handler_t)handler_get_wallet_address
    },
    {
        .cla = CLA_APP,
        .ins = REGISTER_WALLET,
        .handler = (command_handler_t)handler_register_wallet
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_PSBT,
#ifdef HAVE_LIQUID
        .handler = (command_handler_t)handler_liquid_sign_pset
#else
        .handler = (command_handler_t)handler_sign_psbt
#endif
    },
    {
        .cla = CLA_APP,
        .ins = GET_MASTER_FINGERPRINT,
        .handler = (command_handler_t)handler_get_master_fingerprint
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_MESSAGE,
        .handler = (command_handler_t)handler_sign_message
    },
#ifdef HAVE_LIQUID
    {
        .cla = CLA_APP,
        .ins = LIQUID_GET_MASTER_BLINDING_KEY,
        .handler = (command_handler_t)handler_liquid_get_master_blinding_key
    },
    {
        .cla = CLA_APP,
        .ins = LIQUID_GET_BLINDING_KEY,
        .handler = (command_handler_t)handler_liquid_get_blinding_key
    },
#endif // HAVE_LIQUID
};
// clang-format on

void app_main() {
    for (;;) {
        // Length of APDU command received in G_io_apdu_buffer
        int input_len = 0;
        // Structured APDU command
        command_t cmd;

        // Reset length of APDU response
        G_output_len = 0;

        // Receive command bytes in G_io_apdu_buffer

        input_len = io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);

        if (input_len < 0) {
            PRINTF("=> io_exchange error\n");
            return;
        }

        // if not Bitcoin or Bitcoin-testnet, we only support the legacy APDUS.
        // to be removed once the apps are split
        if (BIP32_PUBKEY_VERSION != 0x0488B21E &&
            BIP32_PUBKEY_VERSION != 0x043587CF) {
            io_send_sw(SW_CLA_NOT_SUPPORTED);
            return;
        }

        if (G_app_mode != APP_MODE_NEW) {
            explicit_bzero(&G_command_state, sizeof(G_command_state));

            G_app_mode = APP_MODE_NEW;
        }

        // Reset structured APDU command
        memset(&cmd, 0, sizeof(cmd));
        // Parse APDU command from G_io_apdu_buffer
        if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
            PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
            io_send_sw(SW_WRONG_DATA_LENGTH);
            return;
        }

        LOG_APDU(&cmd);

        if (G_swap_state.called_from_swap &&
            (cmd.ins != SIGN_PSBT && cmd.ins != GET_MASTER_FINGERPRINT)) {
            PRINTF("Only SIGN_PSBT and GET_MASTER_FINGERPRINT can be called during swap\n");
            io_send_sw(SW_INS_NOT_SUPPORTED);
            return;
        }

        // Dispatch structured APDU command to handler
        apdu_dispatcher(COMMAND_DESCRIPTORS,
                        sizeof(COMMAND_DESCRIPTORS) / sizeof(COMMAND_DESCRIPTORS[0]),
                        (machine_context_t *) &G_command_state,
                        sizeof(G_command_state),
                        ui_menu_main,
                        &cmd);

        if (G_swap_state.called_from_swap && G_swap_state.should_exit) {
            os_sched_exit(0);
        }
    }
}

/**
 * Exit the application and go back to the dashboard.
 */
void app_exit() {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

static void initialize_app_globals() {
    io_reset_timeouts();
    memset(&G_swap_state, 0, sizeof(G_swap_state));
}

/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void coin_main() {
#ifdef HAVE_BOLOS_APP_STACK_CANARY
    // Sometimes this initialization is skipped in SDK
    app_stack_canary = 0xDEAD0031;
#endif
    PRINT_STACK_POINTER();

    initialize_app_globals();

    // assumptions on the length of data structures

    _Static_assert(sizeof(cx_sha256_t) <= 108, "cx_sha256_t too large");
    _Static_assert(sizeof(policy_map_key_info_t) <= 148, "policy_map_key_info_t too large");

    // we assume in display.c that the ticker size is at most 5 characters (+ null)
    _Static_assert(sizeof(COIN_COINID_SHORT) <= 6, "COIN_COINID_SHORT too large");

    G_app_mode = APP_MODE_UNINITIALIZED;

#if defined(HAVE_PRINT_STACK_POINTER) && defined(HAVE_BOLOS_APP_STACK_CANARY)
    PRINTF("STACK CANARY ADDRESS: %08x\n", &app_stack_canary);
#endif

#ifdef HAVE_SEMIHOSTED_PRINTF
    PRINTF("APDU State size: %d\n", sizeof(command_state_t));
#endif

    // Reset dispatcher state
    explicit_bzero(&G_dispatcher_context, sizeof(G_dispatcher_context));

    memset(G_io_apdu_buffer, 0, 255);  // paranoia

    // If the app is built with RUN_ON_DEVICE_TESTS this function runs on-device tests and
    // terminates Speculos session. Otherwise, does nothing.
    run_on_device_tests();

    // Process the incoming APDUs

    for (;;) {
        UX_INIT();
        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX

                USB_power(0);
                USB_power(1);

                ui_menu_main();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif  // HAVE_BLE

                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX
                CLOSE_TRY;
                continue;
            }
            CATCH_ALL {
                CLOSE_TRY;
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();
}

static void swap_library_main_helper(struct libargs_s *args) {
    check_api_level(CX_COMPAT_APILEVEL);
    PRINTF("Inside a library \n");
    switch (args->command) {
        case CHECK_ADDRESS:
            // ensure result is zero if an exception is thrown
            args->check_address->result = 0;
            args->check_address->result =
                handle_check_address(args->check_address);
            break;
        case SIGN_TRANSACTION:
            initialize_app_globals();
            if (copy_transaction_parameters(args->create_transaction)) {
                // never returns

                G_app_mode = APP_MODE_UNINITIALIZED;
                G_swap_state.called_from_swap = 1;

                io_seproxyhal_init();
                UX_INIT();
                ux_stack_push();

                USB_power(0);
                USB_power(1);
                // ui_idle();
                PRINTF("USB power ON/OFF\n");
#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX
#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif  // HAVE_BLE
                app_main();
            }
            break;
        case GET_PRINTABLE_AMOUNT:
            // ensure result is zero if an exception is thrown (compatibility breaking, disabled
            // until LL is ready)
            // args->get_printable_amount->result = 0;
            // args->get_printable_amount->result =
            handle_get_printable_amount(args->get_printable_amount);
            break;
        default:
            break;
    }
}

void swap_library_main(struct libargs_s *args) {
    bool end = false;
    /* This loop ensures that swap_library_main_helper and os_lib_end are called
     * within a try context, even if an exception is thrown */
    while (1) {
        BEGIN_TRY {
            TRY {
                if (!end) {
                    swap_library_main_helper(args);
                }
                os_lib_end();
            }
            FINALLY {
                end = true;
            }
        }
        END_TRY;
    }
}

__attribute__((section(".boot"))) int main(int arg0) {
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    if (!arg0) {
        // Bitcoin application launched from dashboard
        coin_main();
        return 0;
    }

    struct libargs_s *args = (struct libargs_s *) arg0;
    if (args->id != 0x100 || args->command == RUN_APPLICATION) {
        app_exit();
        return 0;
    }

#if !defined(HAVE_LIQUID) || defined(LIQUID_HAS_SWAP)
    // Called as Bitcoin library during swap
    swap_library_main(args);
#else
    app_exit();
#endif

    return 0;
}
