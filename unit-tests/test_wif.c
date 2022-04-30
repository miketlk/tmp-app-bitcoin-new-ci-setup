#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/wif.h"

static void test_wif_decode_private_key_mainnet(void **state) {
    (void) state;
    const char wif_key[] = "L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA";
    const uint8_t ref_key[] = {
        0x90,0x5C,0xFE,0x33,0xA3,0xDF,0xB3,0x7D,0xB5,0x13,0xD1,0x07,0x8C,0x16,0xBC,0xFD,
        0xF9,0x06,0xEC,0xD9,0x44,0xC5,0xDD,0xD3,0x7F,0xDF,0xBC,0xC5,0xE6,0x19,0xC1,0x41
    };
    uint8_t out_key[sizeof(ref_key)] = {0};
    uint32_t flags = 0;
    bool ret = wif_decode_private_key(wif_key,
                                      sizeof(wif_key) - 1,
                                      out_key,
                                      sizeof(out_key),
                                      &flags);

    assert_true(ret);
    assert_memory_equal(out_key, ref_key, sizeof(out_key));
    assert_int_equal(flags, WIF_FLAG_MAINNET|WIF_FLAG_COMPRESSION);
}

static void test_wif_decode_private_key_testnet(void **state) {
    (void) state;
    char wif_key[] = "92gVjDpgf9L6XZQ7XfRa9oisT3NgnFXio4ooMx9gHBhLjzMhjG2";
    const uint8_t ref_key[] = {
        0x90,0x5C,0xFE,0x33,0xA3,0xDF,0xB3,0x7D,0xB5,0x13,0xD1,0x07,0x8C,0x16,0xBC,0xFD,
        0xF9,0x06,0xEC,0xD9,0x44,0xC5,0xDD,0xD3,0x7F,0xDF,0xBC,0xC5,0xE6,0x19,0xC1,0x41
    };
    uint8_t out_key[sizeof(ref_key)] = {0};
    uint32_t flags = 0;
    bool ret = wif_decode_private_key(wif_key,
                                      sizeof(wif_key) - 1,
                                      out_key,
                                      sizeof(out_key),
                                      &flags);

    assert_true(ret);
    assert_memory_equal(out_key, ref_key, sizeof(out_key));
    assert_int_equal(flags, WIF_FLAG_TESTNET);
}

static void test_wif_verify_private_key(void **state) {
    (void) state;
    const char ref_key[] = "L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA";

    // Verify reference key
    assert_true(wif_verify_private_key(ref_key, sizeof(ref_key) - 1, NULL));

    // On first iteration verify a correct key.
    // On each other iteration corrupt one character and ensure that decoding fails.
    char key[sizeof(ref_key)];
    for(int i = 0; i < sizeof(key); ++i) {
        memcpy(key, ref_key, sizeof(key));
        if(i >= 1) {
            ++key[i - 1];
        }
        bool ret = wif_verify_private_key(key, sizeof(key) - 1, NULL);
        if(i == 0) {
            assert_true(ret);
        } else {
            assert_false(ret);
        }
    }

    // Verify without last character
    assert_false(wif_verify_private_key(ref_key, sizeof(ref_key) - 2, NULL));
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wif_decode_private_key_mainnet),
        cmocka_unit_test(test_wif_decode_private_key_testnet),
        cmocka_unit_test(test_wif_verify_private_key)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
