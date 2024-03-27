# ****************************************************************************
#    Ledger App for Bitcoin
#    (c) 2021 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifdef DEBUG
ifndef DEBUG_LOG_LEVEL
DEBUG_LOG_LEVEL := $(DEBUG)
endif
endif

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

# TODO: compile with the right path restrictions
# APP_LOAD_PARAMS  = --curve secp256k1
APP_LOAD_PARAMS  = $(COMMON_LOAD_PARAMS)
APP_PATH = ""

APPVERSION_M = 2
APPVERSION_N = 0
APPVERSION_P = 4
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"


APP_STACK_SIZE = 1500

# simplify for tests
ifndef COIN
COIN=liquid_regtest
endif

# Flags: BOLOS_SETTINGS, GLOBAL_PIN, DERIVE_MASTER
# Dependency to Bitcoin app (for altcoins)
APP_LOAD_FLAGS=--appFlags 0xa50 --dep Bitcoin:$(APPVERSION)

ifeq ($(COIN),bitcoin_testnet)

# we're not using the lib :)
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

# Bitcoin testnet (can also be used for signet)
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP32_PRIVKEY_VERSION=0x04358394
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=196
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"tb\"
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\"
DEFINES   += COIN_COINID_SHORT=\"TEST\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN_TESTNET
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT

APPNAME = "Bitcoin Test"

else ifeq ($(COIN),bitcoin)

# we're not using the lib :)
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

# Bitcoin mainnet
DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
DEFINES   += BIP32_PRIVKEY_VERSION=0x0488ADE4
DEFINES   += BIP44_COIN_TYPE=0
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=0
DEFINES   += COIN_P2SH_VERSION=5
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"bc\"
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\\x20Testnet\"
DEFINES   += COIN_COINID_SHORT=\"BTC\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT

APPNAME = "Bitcoin"

else ifeq ($(COIN),bitcoin_regtest)
# This target can be used to compile a version of the app that uses regtest addresses

# we're not using the lib :)
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

# Bitcoin regtest test network
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP32_PRIVKEY_VERSION=0x04358394
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=196
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"bcrt\"
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\"
DEFINES   += COIN_COINID_SHORT=\"TEST\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN_TESTNET
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME = "Bitcoin Regtest"

else ifeq ($(COIN),liquid_regtest)

# we're not using the lib :)
DEFINES_LIB=
# Flags: DERIVE_MASTER, GLOBAL_PIN, BOLOS_SETTINGS
APP_LOAD_FLAGS=--appFlags 0x250

# Liquid regtest
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP32_PRIVKEY_VERSION=0x04358394
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=75
DEFINES   += COIN_PREFIX_CONFIDENTIAL=4
DEFINES   += HAVE_LIQUID
DEFINES   += HAVE_LIQUID_TEST
DEFINES   += COIN_BLINDED_VERSION=4
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\"
DEFINES   += COIN_COINID_SHORT=\"BTC\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"ert\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL=\"el\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME = "Liquid Regtest"
# -disabled- APP_LOAD_PARAMS += --curve secp256k1

else ifeq ($(COIN),liquid_regtest_headless)

# we're not using the lib :)
DEFINES_LIB=
# Flags: DERIVE_MASTER, GLOBAL_PIN, BOLOS_SETTINGS
APP_LOAD_FLAGS=--appFlags 0x250

# Liquid regtest headless
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP32_PRIVKEY_VERSION=0x04358394
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=75
DEFINES   += COIN_PREFIX_CONFIDENTIAL=4
DEFINES   += HAVE_LIQUID
DEFINES   += HAVE_LIQUID_TEST
DEFINES   += COIN_BLINDED_VERSION=4
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\"
DEFINES   += COIN_COINID_SHORT=\"BTC\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"ert\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL=\"el\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
DEFINES   += HAVE_LIQUID_HEADLESS
APPNAME = "Liquid Regtest Hless"
# -disabled- APP_LOAD_PARAMS += --curve secp256k1

else ifeq ($(COIN),liquid)

# we're not using the lib :)
DEFINES_LIB=
# Flags: DERIVE_MASTER, GLOBAL_PIN, BOLOS_SETTINGS
APP_LOAD_FLAGS=--appFlags 0x250

# Liquid
DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
DEFINES   += BIP32_PRIVKEY_VERSION=0x0488ADE4
DEFINES   += BIP44_COIN_TYPE=1776
DEFINES   += BIP44_COIN_TYPE_2=1776
DEFINES   += COIN_P2PKH_VERSION=57
DEFINES   += COIN_P2SH_VERSION=39
DEFINES   += COIN_PREFIX_CONFIDENTIAL=12
DEFINES   += HAVE_LIQUID
DEFINES   += COIN_BLINDED_VERSION=12
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\"
DEFINES   += COIN_COINID_SHORT=\"BTC\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"ex\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL=\"lq\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME = "Liquid"
# -disabled- APP_LOAD_PARAMS += --curve secp256k1

else ifeq ($(COIN),liquid_headless)

# we're not using the lib :)
DEFINES_LIB=
# Flags: DERIVE_MASTER, GLOBAL_PIN, BOLOS_SETTINGS
APP_LOAD_FLAGS=--appFlags 0x250

# Liquid Headless
DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
DEFINES   += BIP32_PRIVKEY_VERSION=0x0488ADE4
DEFINES   += BIP44_COIN_TYPE=1776
DEFINES   += BIP44_COIN_TYPE_2=1776
DEFINES   += COIN_P2PKH_VERSION=57
DEFINES   += COIN_P2SH_VERSION=39
DEFINES   += COIN_PREFIX_CONFIDENTIAL=12
DEFINES   += HAVE_LIQUID
DEFINES   += COIN_BLINDED_VERSION=12
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COLOR_HDR=0xFCB653
DEFINES   += COIN_COLOR_DB=0xFEDBA9
DEFINES   += COIN_COINID_NAME=\"Bitcoin\"
DEFINES   += COIN_COINID_SHORT=\"BTC\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"ex\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX_CONFIDENTIAL=\"lq\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
DEFINES   += HAVE_LIQUID_HEADLESS
APPNAME = "Liquid Hless"
# -disabled- APP_LOAD_PARAMS += --curve secp256k1

else
ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use bitcoin_testnet, bitcoin, bitcoin_regtest, liquid_regtest, liquid_regtest_headless, liquid, liquid_headless)
endif
endif

APP_LOAD_PARAMS += $(APP_LOAD_FLAGS)
DEFINES += $(DEFINES_LIB)

ifeq ($(TARGET_NAME),TARGET_NANOS)
ICONNAME=icons/nanos_app_$(COIN).gif
else
ICONNAME=icons/nanox_app_$(COIN).gif
endif

all: default

# TODO: double check if all those flags are still relevant/needed (was copied from legacy app-bitcoin)

DEFINES   += APPVERSION=\"$(APPVERSION)\"
DEFINES   += MAJOR_VERSION=$(APPVERSION_M) MINOR_VERSION=$(APPVERSION_N) PATCH_VERSION=$(APPVERSION_P)
DEFINES   += OS_IO_SEPROXYHAL
DEFINES   += HAVE_BAGL HAVE_SPRINTF HAVE_SNPRINTF_FORMAT_U
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P) TCS_LOADER_PATCH_VERSION=0
DEFINES   += HAVE_UX_FLOW

DEFINES   += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"

DEFINES   += HAVE_BOLOS_APP_STACK_CANARY


ifeq ($(TARGET_NAME),TARGET_NANOS)
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=72
DEFINES       += HAVE_WALLET_ID_SDK
else
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES       += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES       += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES       += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
DEFINES       += HAVE_BLE_APDU # basic ledger apdu transport over BLE
endif

ifeq ($(TARGET_NAME),TARGET_NANOS)
    # enables optimizations using the shared 1K CXRAM region
    DEFINES   += USE_CXRAM_SECTION
endif

# debugging helper functions and macros
CFLAGS    += -include debug-helpers/debug.h

# DEFINES   += HAVE_PRINT_STACK_POINTER

ifeq ($(TEST),1)
    $(warning On-device tests should only be run with Speculos!)
    DEBUG_LOG_LEVEL = 10
    DEFINES += RUN_ON_DEVICE_TESTS
endif

ifndef DEBUG_LOG_LEVEL
    DEBUG_LOG_LEVEL = 0
endif

ifeq ($(DEBUG_LOG_LEVEL),0)
        DEFINES   += PRINTF\(...\)=
else
        ifeq ($(DEBUG_LOG_LEVEL),10)
                $(warning Using semihosted PRINTF. Only run with Speculos!)
                DEFINES += HAVE_PRINTF HAVE_SEMIHOSTED_PRINTF PRINTF=semihosted_printf
                #DEFINES += HAVE_LOG_PROCESSOR
                #DEFINES += HAVE_APDU_LOG
                #DEFINES += HAVE_PRINT_STACK_POINTER
        else ifeq ($(DEBUG_LOG_LEVEL),11)
                $(warning CCMD PRINTF is used! APDU exchage is affected.)
                DEFINES += HAVE_CCMD_PRINTF
        else
                ifeq ($(TARGET_NAME),TARGET_NANOS)
                        DEFINES += HAVE_PRINTF PRINTF=screen_printf
                else
                        DEFINES += HAVE_PRINTF PRINTF=mcu_usb_printf
                endif
        endif
endif


# Needed to be able to include the definition of G_cx
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src


ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
else
$(info BOLOS_ENV is not set: falling back to CLANGPATH and GCCPATH)
endif
ifeq ($(CLANGPATH),)
$(info CLANGPATH is not set: clang will be used from PATH)
endif
ifeq ($(GCCPATH),)
$(info GCCPATH is not set: arm-none-eabi-* will be used from PATH)
endif

CC      := $(CLANGPATH)clang
AS      := $(GCCPATH)arm-none-eabi-gcc
LD      := $(GCCPATH)arm-none-eabi-gcc
LDLIBS  += -lm -lgcc -lc

ifeq ($(DEBUG_LOG_LEVEL),0)
    $(info *** Release version is being built ***)
    CFLAGS  += -Oz
    LDFLAGS += -O3 -Os
else
    $(info *** Debug version is being built ***)
    CFLAGS  += -Og -g
    LDFLAGS += -Og
endif

include $(BOLOS_SDK)/Makefile.glyphs

APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl lib_ux

ifeq ($(TARGET_NAME),TARGET_NANOX)
    SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl
endif

load: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

load-offline: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS) --offline

load-no-build:
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

load-offline-no-build:
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS) --offline

delete:
	python3 -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile


# Temporary restriction until we a Resistance Nano X icon
ifeq ($(TARGET_NAME),TARGET_NANOS)
listvariants:
	@echo VARIANTS COIN bitcoin_testnet bitcoin bitcoin_cash bitcoin_gold litecoin dogecoin dash zcash horizen komodo stratis peercoin pivx viacoin vertcoin stealth digibyte qtum bitcoin_private firo gamecredits zclassic xsn nix lbry ravencoin resistance hydra hydra_testnet xrhodium
else
listvariants:
	@echo VARIANTS COIN bitcoin_testnet bitcoin bitcoin_cash bitcoin_gold litecoin dogecoin dash zcash horizen komodo stratis peercoin pivx viacoin vertcoin stealth digibyte qtum bitcoin_private firo gamecredits zclassic xsn nix lbry ravencoin hydra hydra_testnet xrhodium
endif


# Makes a detailed report of code and data size in debug/size-report.txt
# More useful for production builds with DEBUG=0
size-report: bin/app.elf
	arm-none-eabi-nm --print-size --size-sort --radix=d bin/app.elf >debug/size-report.txt
