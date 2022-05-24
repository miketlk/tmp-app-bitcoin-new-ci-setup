#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "liquid/liquid.h"

// in unit tests, size_t integers are currently 8 compiled as 8 bytes; therefore, in the app
// about half of the memory would be needed
#define MAX_POLICY_MAP_MEMORY_SIZE 512

const liquid_network_config_t config_elementsregtest = {
    .p2pkh_version = 0x6F,
    .p2sh_version = 0x4B,
    .prefix_confidential = 0x04,
    .segwit_prefix = "ert",
    .segwit_prefix_confidential = "el"
};

static void test_liquid_get_script_confidential_address_segwit(void **state) {
    (void) state;

    const uint8_t blinding_key[] = {
        0x03, 0xB8, 0x45, 0xC0, 0x3A, 0x30, 0xC1, 0x7E, 0x5B, 0x95, 0xC0, 0x00, 0x95, 0xB7, 0xB0,
        0x62, 0x74, 0xDD, 0x0E, 0xC6, 0x97, 0xC6, 0x92, 0xBC, 0x2B, 0xDC, 0x75, 0xE7, 0xAC, 0xCA,
        0x0D, 0x9D, 0xF4
    };
    // blinded(slip77(MBK),wsh(...))
    const uint8_t script[] = {
        0x00, 0x20, 0xDB, 0xDF, 0x82, 0xD0, 0x2C, 0xB4, 0x82, 0x5F, 0x25, 0x90, 0x74, 0x3E, 0xF2,
        0xCB, 0xC1, 0x42, 0xFD, 0x4D, 0xD2, 0xB0, 0x18, 0xA1, 0xC5, 0x10, 0xFE, 0x77, 0x79, 0xE6,
        0x55, 0x51, 0x02, 0xAC
    };
    const char ref_addr[] = "el1qqwuytsp6xrqhuku4cqqftdasvf6d6rkxjlrf90ptm3670tx2pkwlfk7lstgzedyzt"\
        "ujeqap77t9uzshafhftqx9pc5g0uameue24zq4vcu0n02rjs05c";
    char addr[sizeof(ref_addr)] = "";

    int addr_len = liquid_get_script_confidential_address(script,
                                                          sizeof(script),
                                                          &config_elementsregtest,
                                                          blinding_key,
                                                          sizeof(blinding_key),
                                                          addr,
                                                          sizeof(addr));

    assert_int_equal(addr_len, sizeof(ref_addr) - 1);
    assert_string_equal(addr, ref_addr);
}

static void test_liquid_get_script_confidential_address_p2sh(void **state) {
    (void) state;

    const uint8_t blinding_key[] = {
        0x03, 0x03, 0xE2, 0xAC, 0xCC, 0x2B, 0x85, 0x98, 0x61, 0xAE, 0x0D, 0x43, 0x93, 0xF9, 0x7D,
        0xB5, 0xE2, 0x4C, 0xA5, 0x4D, 0x53, 0x8A, 0x77, 0x13, 0x01, 0xA6, 0x27, 0x95, 0x01, 0x2A,
        0x05, 0xC5, 0x56
    };
    // blinded(slip77(MBK),sh(wpkh(...)))
    const uint8_t script[] = {
        0xA9, 0x14, 0x9A, 0x73, 0x7C, 0x68, 0x56, 0xFD, 0x6C, 0x65, 0x6D, 0x3F, 0x2C, 0x9E, 0xF4,
        0xE7, 0x32, 0x4D, 0x35, 0x00, 0xF5, 0xD0, 0x87
    };
    const char ref_addr[] =
        "Azpr1TWL4x4zfj7SuzvpiT7b7fwEwBaS4ZamSbrzahbfduBkoBJHcrj2WkrjWWi4aKKyKtbugyEC1dxf";
    char addr[sizeof(ref_addr)] = "";

    int addr_len = liquid_get_script_confidential_address(script,
                                                          sizeof(script),
                                                          &config_elementsregtest,
                                                          blinding_key,
                                                          sizeof(blinding_key),
                                                          addr,
                                                          sizeof(addr));

    assert_int_equal(addr_len, sizeof(ref_addr) - 1);
    assert_string_equal(addr, ref_addr);
}

static void test_policy_unwrap_blinded(void **state) {
    (void) state;

    uint8_t policy_bytes[MAX_POLICY_MAP_MEMORY_SIZE];
    const char *policy_str = "blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA),wpkh(@0))";
    buffer_t policy_buf = buffer_create((void *)policy_str, strlen(policy_str));
    const uint8_t ref_mbk[] = {
        0x90, 0x5C, 0xFE, 0x33, 0xA3, 0xDF, 0xB3, 0x7D, 0xB5, 0x13, 0xD1, 0x07, 0x8C, 0x16, 0xBC,
        0xFD, 0xF9, 0x06, 0xEC, 0xD9, 0x44, 0xC5, 0xDD, 0xD3, 0x7F, 0xDF, 0xBC, 0xC5, 0xE6, 0x19,
        0xC1, 0x41
    };
    assert_int_equal(parse_policy_map(&policy_buf, policy_bytes, sizeof(policy_bytes)), 0);

    const policy_node_t *policy = (const policy_node_t *)policy_bytes;
    bool is_blinded = false;
    uint8_t mbk[sizeof(ref_mbk)] = {0};
    uint32_t flags = 0;
    liquid_blinding_key_type_t key_type = BLINDING_KEY_UNKNOWN;
    bool ret = liquid_policy_unwrap_blinded(&policy, &is_blinded, mbk, sizeof(mbk), &flags, &key_type);

    assert_true(ret);
    assert_non_null(policy);
    assert_true(policy != (policy_node_t *)policy_bytes);
    assert_int_equal(policy->type, TOKEN_WPKH); // inside blinded()
    assert_true(is_blinded);
    assert_memory_equal(mbk, ref_mbk, sizeof(mbk));
    assert_int_equal(flags, WIF_FLAG_MAINNET | WIF_FLAG_COMPRESSION);
    assert_int_equal(key_type, BLINDING_KEY_SLIP77);
}

static void test_policy_unwrap_blinded_noop(void **state) {
    (void) state;

    uint8_t policy_bytes[MAX_POLICY_MAP_MEMORY_SIZE];
    const char *policy_str = "wpkh(@0)";
    buffer_t policy_buf = buffer_create((void *)policy_str, strlen(policy_str));
    assert_int_equal(parse_policy_map(&policy_buf, policy_bytes, sizeof(policy_bytes)), 0);

    const policy_node_t *policy = (const policy_node_t *)policy_bytes;
    bool is_blinded = false;
    uint8_t mbk[32] = {0};
    liquid_blinding_key_type_t key_type = BLINDING_KEY_UNKNOWN;
    bool ret = liquid_policy_unwrap_blinded(&policy, &is_blinded, mbk, sizeof(mbk), NULL, &key_type);

    assert_true(ret);
    assert_non_null(policy);
    assert_true(policy == (policy_node_t *)policy_bytes); // unchanged
    assert_int_equal(policy->type, TOKEN_WPKH);
    assert_false(is_blinded);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_liquid_get_script_confidential_address_segwit),
        cmocka_unit_test(test_liquid_get_script_confidential_address_p2sh),
        cmocka_unit_test(test_policy_unwrap_blinded),
        cmocka_unit_test(test_policy_unwrap_blinded_noop)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
