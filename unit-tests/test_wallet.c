#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <cmocka.h>

// missing definitions to make it compile without the SDK
unsigned int pic(unsigned int linked_address) {
    return linked_address;
}

#define PRINTF(...) printf
#define PIC(x)      (x)

#include "common/wallet.h"

// in unit tests, size_t integers are currently 8 compiled as 8 bytes; therefore, in the app
// about half of the memory would be needed
#define MAX_POLICY_MAP_MEMORY_SIZE 512

static void test_parse_policy_map_singlesig_1(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "pkh(@0)";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_key_t *node_1 = (policy_node_with_key_t *) out;

    assert_int_equal(node_1->type, TOKEN_PKH);
    assert_int_equal(node_1->key_index, 0);
}

static void test_parse_policy_map_singlesig_2(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "sh(wpkh(@0))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->type, TOKEN_SH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) root->script;

    assert_int_equal(inner->type, TOKEN_WPKH);
    assert_int_equal(inner->key_index, 0);
}

static void test_parse_policy_map_singlesig_3(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "sh(wsh(pkh(@0)))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) root->script;

    assert_int_equal(mid->type, TOKEN_WSH);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) mid->script;

    assert_int_equal(inner->type, TOKEN_PKH);
    assert_int_equal(inner->key_index, 0);
}

static void test_parse_policy_map_multisig_1(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "sortedmulti(2,@0,@1,@2)";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_multisig_t *node_1 = (policy_node_multisig_t *) out;

    assert_int_equal(node_1->type, TOKEN_SORTEDMULTI);
    assert_int_equal(node_1->k, 2);
    assert_int_equal(node_1->n, 3);
    assert_int_equal(node_1->key_indexes[0], 0);
    assert_int_equal(node_1->key_indexes[1], 1);
    assert_int_equal(node_1->key_indexes[2], 2);
}

static void test_parse_policy_map_multisig_2(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "wsh(multi(3,@0,@1,@2,@3,@4))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) root->script;
    assert_int_equal(inner->type, TOKEN_MULTI);

    assert_int_equal(inner->k, 3);
    assert_int_equal(inner->n, 5);
    for (int i = 0; i < 5; i++) assert_int_equal(inner->key_indexes[i], i);
}

static void test_parse_policy_map_multisig_3(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "sh(wsh(sortedmulti(3,@0,@1,@2,@3,@4)))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);
    policy_node_with_script_t *root = (policy_node_with_script_t *) out;

    assert_int_equal(root->type, TOKEN_SH);

    policy_node_with_script_t *mid = (policy_node_with_script_t *) root->script;
    assert_int_equal(mid->type, TOKEN_WSH);

    policy_node_multisig_t *inner = (policy_node_multisig_t *) mid->script;
    assert_int_equal(inner->type, TOKEN_SORTEDMULTI);

    assert_int_equal(inner->k, 3);
    assert_int_equal(inner->n, 5);
    for (int i = 0; i < 5; i++) assert_int_equal(inner->key_indexes[i], i);
}

#ifdef HAVE_LIQUID

static void test_parse_policy_map_blinded_singlesig(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA),wpkh(@0))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);

    policy_node_blinded_t *root = (policy_node_blinded_t *)out;
    assert_non_null(root);
    assert_int_equal(root->type, TOKEN_BLINDED);
    assert_non_null(root->mbk_script);
    assert_non_null(root->script);

    policy_node_blinding_key_t *mbk = (policy_node_blinding_key_t*) root->mbk_script;
    assert_int_equal(mbk->type, TOKEN_SLIP77);
    static const char ref_mbk[] = "L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA";
    assert_int_equal(mbk->key_str_len, sizeof(ref_mbk) - 1);
    assert_memory_equal(mbk->key_str, ref_mbk, mbk->key_str_len);

    policy_node_with_key_t *inner = (policy_node_with_key_t *) root->script;
    assert_int_equal(inner->type, TOKEN_WPKH);
    assert_int_equal(inner->key_index, 0);
}

static void test_parse_policy_map_blinded_multisig(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    int res;

    char *policy = "blinded(slip77(L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N),"\
        "sh(wsh(sortedmulti(13,@0,@1,@2,@3,@4,@5,@6,@7,@8,@9,@10,@11,@12,@13,@14))))";
    buffer_t policy_buf = buffer_create((void *) policy, strlen(policy));

    res = parse_policy_map(&policy_buf, out, sizeof(out));
    assert_int_equal(res, 0);

    policy_node_blinded_t *root = (policy_node_blinded_t *)out;
    assert_non_null(root);
    assert_int_equal(root->type, TOKEN_BLINDED);
    assert_non_null(root->mbk_script);
    assert_non_null(root->script);

    policy_node_blinding_key_t *mbk = (policy_node_blinding_key_t*) root->mbk_script;
    assert_int_equal(mbk->type, TOKEN_SLIP77);
    static const char ref_mbk[] = "L1XvKmnKWuC4a5sbz3Ez6LCfMCbaXMBCcQk7C62ziN5NjoEgjN5N";
    assert_int_equal(mbk->key_str_len, sizeof(ref_mbk) - 1);
    assert_memory_equal(mbk->key_str, ref_mbk, mbk->key_str_len);

    policy_node_with_script_t *inner1 = (policy_node_with_script_t *) root->script;
    assert_int_equal(inner1->type, TOKEN_SH);
    assert_non_null(inner1->script);

    policy_node_with_script_t *inner2 = (policy_node_with_script_t *) inner1->script;
    assert_int_equal(inner2->type, TOKEN_WSH);
    assert_non_null(inner2->script);

    policy_node_multisig_t *inner3 = (policy_node_multisig_t *) inner2->script;
    assert_int_equal(inner3->type, TOKEN_SORTEDMULTI);
    assert_int_equal(inner3->k, 13);
    assert_int_equal(inner3->n, 15);
    for (int i = 0; i < 15; i++) {
        assert_int_equal(inner3->key_indexes[i], i);
    }
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
    bool ret = policy_unwrap_blinded(&policy, &is_blinded, mbk, sizeof(mbk), &flags);

    assert_true(ret);
    assert_non_null(policy);
    assert_true(policy != (policy_node_t *)policy_bytes);
    assert_int_equal(policy->type, TOKEN_WPKH); // inside blinded()
    assert_true(is_blinded);
    assert_memory_equal(mbk, ref_mbk, sizeof(mbk));
    assert_int_equal(flags, WIF_FLAG_MAINNET | WIF_FLAG_COMPRESSION);
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
    bool ret = policy_unwrap_blinded(&policy, &is_blinded, mbk, sizeof(mbk), NULL);

    assert_true(ret);
    assert_non_null(policy);
    assert_true(policy == (policy_node_t *)policy_bytes); // unchanged
    assert_int_equal(policy->type, TOKEN_WPKH);
    assert_false(is_blinded);
}

#endif // HAVE_LIQUID

// convenience function to parse as one liners

static int parse_policy(const char *policy, size_t policy_len, uint8_t *out, size_t out_len) {
    buffer_t in_buf = buffer_create((void *) policy, policy_len);
    return parse_policy_map(&in_buf, out, out_len);
}

#define PARSE_POLICY(policy, out, out_len) parse_policy(policy, sizeof(policy) - 1, out, out_len)

static void test_failures(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // excess byte not allowed
    assert_true(0 > PARSE_POLICY("pkh(@0) ", out, sizeof(out)));

    // missing closing parenthesis
    assert_true(0 > PARSE_POLICY("pkh(@0", out, sizeof(out)));

    // unknown token
    assert_true(0 > PARSE_POLICY("yolo(@0)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("Pkh(@0)", out, sizeof(out)));  // case-sensitive

    // missing or invalid key identifier
    assert_true(0 > PARSE_POLICY("pkh()", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("pkh(@)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("pkh(0)", out, sizeof(out)));

    // sh not top-level
    assert_true(0 > PARSE_POLICY("sh(sh(pkh(@0)))", out, sizeof(out)));

    // wsh can only be inside sh
    assert_true(0 > PARSE_POLICY("wsh(wsh(pkh(@0)))", out, sizeof(out)));

    // wpkh can only be inside sh
    assert_true(0 > PARSE_POLICY("wsh(wpkh(@0)))", out, sizeof(out)));

    // multi with invalid threshold
    assert_true(
        0 > PARSE_POLICY("multi(6,@0,@1,@2,@3,@4)", out, sizeof(out)));  // threshold larger than n
    assert_true(0 > PARSE_POLICY("multi(0,@0,@1,@2,@3,@4)", out, sizeof(out)));
    // missing threshold or keys in multisig
    assert_true(0 > PARSE_POLICY("multi(@0,@1,@2,@3,@4)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("multi(1)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("multi(1,)", out, sizeof(out)));
}

#ifdef HAVE_LIQUID

static void test_failures_blinded(void **state) {
    (void) state;

    uint8_t out[MAX_POLICY_MAP_MEMORY_SIZE];

    // blinded() must be top-level
    assert_true(0 > PARSE_POLICY("sh(blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA),wpkh(@0)))",
                                 out, sizeof(out)));

    // Broken format
    assert_true(0 > PARSE_POLICY("blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA)wpkh(@0))",
                                 out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA) wpkh(@0))",
                                 out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA,wpkh(@0))",
                                 out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA),wpkh(@0)",
                                 out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("blinded(slip77(L-4LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA),wpkh(@0))",
                                 out, sizeof(out)));

    // Master blinding key script is required for blinded() tag
    assert_true(0 > PARSE_POLICY("blinded(wpkh(@0))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("blinded(,wpkh(@0))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("blinded(wpkh(@0),wpkh(@1))", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("blinded(slip77(),wpkh(@0))", out, sizeof(out)));

    // slip77() should not be used outside of blinded() tag
    assert_true(0 > PARSE_POLICY("slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmA)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("slip77(@0)", out, sizeof(out)));
    assert_true(0 > PARSE_POLICY("slip77(wpkh(@0))", out, sizeof(out)));

    // Master blinding key in WIF format must be 51-52 characters
    const char mbk_0char[] = "blinded(slip77(),wpkh(@0))";
    const char mbk_1char[] = "blinded(slip77(L),wpkh(@0))";
    const char mbk_50char[] = "blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHM),wpkh(@0))";
    const char mbk_53char[] = "blinded(slip77(L24LLSbccJ52ESXkRvnKxYik3iBJvH2uQHf6X3xnsKZ3sw8RHMmAA),wpkh(@0))";
    assert_true(0 > PARSE_POLICY(mbk_0char, out, sizeof(out)));
    assert_true(0 > PARSE_POLICY(mbk_1char, out, sizeof(out)));
    assert_true(0 > PARSE_POLICY(mbk_50char, out, sizeof(out)));
    assert_true(0 > PARSE_POLICY(mbk_53char, out, sizeof(out)));
}

#endif // HAVE_LIQUID

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_policy_map_singlesig_1),
        cmocka_unit_test(test_parse_policy_map_singlesig_2),
        cmocka_unit_test(test_parse_policy_map_singlesig_3),
        cmocka_unit_test(test_parse_policy_map_multisig_1),
        cmocka_unit_test(test_parse_policy_map_multisig_2),
        cmocka_unit_test(test_parse_policy_map_multisig_3),
        cmocka_unit_test(test_failures),
#ifdef HAVE_LIQUID
        cmocka_unit_test(test_parse_policy_map_blinded_singlesig),
        cmocka_unit_test(test_parse_policy_map_blinded_multisig),
        cmocka_unit_test(test_policy_unwrap_blinded),
        cmocka_unit_test(test_policy_unwrap_blinded_noop),
        cmocka_unit_test(test_failures_blinded)
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
