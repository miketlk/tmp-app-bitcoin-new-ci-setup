#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "common/buffer.h"
#include "liquid/contract_parser.h"

typedef struct {
    const char *contract_str;
    contract_parser_outputs_t ref_outs;
} contract_test_data_t;

static const contract_test_data_t contract_test_data[] = {
    // tether.to USDt (Tether USD)
    {
        .contract_str =
            "{\"entity\":{\"domain\":\"tether.to\"},"\
            "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","\
            "\"name\":\"Tether USD\","\
            "\"precision\":8,"\
            "\"ticker\":\"USDt\","\
            "\"version\":0}",
        .ref_outs = {
            .contract_hash = {
                0x3c, 0x7f, 0x0a, 0x53, 0xc2, 0xff, 0x5b, 0x99,
                0x59, 0x06, 0x20, 0xd7, 0xf6, 0x60, 0x4a, 0x7a,
                0x3a, 0x7b, 0xfb, 0xaa, 0xa6, 0xaa, 0x61, 0xf7,
                0xbf, 0xc7, 0x83, 0x3c, 0xa0, 0x3c, 0xde, 0x82
            },
            .ticker = "USDt",
            .precision = 8
        }
    },
    // liquid.beer ASP (Atomic Swap Pint)
    {
        .contract_str =
            "{\"entity\":{\"domain\":\"liquid.beer\"},"\
            "\"issuer_pubkey\":\"02436437ab5ecb6966b7dea1333fad14a658ae185d8ced00aa598af5997b55cd24\","\
            "\"name\":\"Atomic Swap Pint\","\
            "\"precision\":2,"\
            "\"ticker\":\"ASP\","\
            "\"version\":0}",
        .ref_outs = {
            .contract_hash = {
                0x0b, 0xba, 0x2b, 0x02, 0xe5, 0xa9, 0x39, 0xf3,
                0xcb, 0xdc, 0x87, 0xc7, 0x0b, 0xa0, 0x9b, 0x3d,
                0x64, 0xeb, 0x43, 0x4e, 0xef, 0x25, 0xb3, 0xf3,
                0x14, 0xaf, 0xcf, 0x0c, 0x0a, 0xd7, 0x07, 0x3f
            },
            .ticker = "ASP",
            .precision = 2
        }
    }
};

static bool parse_contract(const char *contract, contract_parser_outputs_t *outputs) {
    contract_parser_context_t ctx;
    buffer_t contract_buffer = buffer_create((void*)contract, strlen(contract));

    if (contract_parser_init(&ctx, outputs)) {
        contract_parser_process(&ctx, &contract_buffer);
        return contract_parser_finalize(&ctx);
    }
    return false;
}

static void test_contract_parser_valid(void **state) {
    (void) state;

    int n_vectors = sizeof(contract_test_data) / sizeof(contract_test_data[0]);
    const contract_test_data_t *p_vect = contract_test_data;

    contract_parser_outputs_t outs;
    for(int i = 0; i < n_vectors; ++i, p_vect++) {
        memset(&outs, 0xee, sizeof(outs));
        bool res = parse_contract(p_vect->contract_str, &outs);
        assert_true(res);
        assert_memory_equal(outs.contract_hash,
                            p_vect->ref_outs.contract_hash,
                            sizeof(outs.contract_hash));
        assert_string_equal(outs.ticker, p_vect->ref_outs.ticker);
        assert_int_equal((int)outs.precision, (int)p_vect->ref_outs.precision);
    }
}

static void test_contract_parser_missing_fields(void **state) {
    (void) state;
    static const char complete[] =
        "{\"entity\":{\"domain\":\"tether.to\"},"\
        "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","\
        "\"name\":\"Tether USD\","\
        "\"precision\":8,"\
        "\"ticker\":\"USDt\","\
        "\"version\":0}";

    static const char missing_precision[] =
        "{\"entity\":{\"domain\":\"tether.to\"},"\
        "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","\
        "\"name\":\"Tether USD\","\
        "\"ticker\":\"USDt\","\
        "\"version\":0}";

    static const char missing_ticker[] =
        "{\"entity\":{\"domain\":\"tether.to\"},"\
        "\"issuer_pubkey\":\"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904\","\
        "\"name\":\"Tether USD\","\
        "\"precision\":8,"\
        "\"version\":0}";

    contract_parser_outputs_t outs;
    assert_true(parse_contract(complete, &outs));
    assert_false(parse_contract(missing_precision, &outs));
    assert_false(parse_contract(missing_ticker, &outs));
}

static void test_contract_parser_skip_nested_arrays(void **state) {
    (void) state;

    static const char contract[] =
        "{\"entity\":{\"domain\":\"liquid.beer\"},"\
        "\"issuer_pubkey\":\"02436437ab5ecb6966b7dea1333fad14a658ae185d8ced00aa598af5997b55cd24\","\
        "\"name\":\"Atomic Swap Pint\","\
        "\"arr\":[1,2,3,[\"a\",\"b\",[\"x\",\"y\",\"z\"],[],\"c\"],4,[]],"\
        "\"precision\":2,"\
        "\"ticker\":\"ASP\","\
        "\"version\":0}";

    contract_parser_outputs_t outs;
    assert_true(parse_contract(contract, &outs));
    assert_string_equal(outs.ticker, "ASP");
    assert_int_equal((int)outs.precision, 2);
}

static void test_contract_parser_skip_nested_objects(void **state) {
    (void) state;

    static const char contract[] =
        "{\"entity\":{\"domain\":\"liquid.beer\"},"\
        "\"issuer_pubkey\":\"02436437ab5ecb6966b7dea1333fad14a658ae185d8ced00aa598af5997b55cd24\","\
        "\"name\":\"Atomic Swap Pint\","\
        "\"precision\":2,"\
        "\"obj\":{\"a\":1,\"b\":{\"x\":{\"xx\":true},\"y\"},\"c\":{}},"\
        "\"ticker\":\"ASP\","\
        "\"version\":0}";

    contract_parser_outputs_t outs;
    assert_true(parse_contract(contract, &outs));
    assert_string_equal(outs.ticker, "ASP");
    assert_int_equal((int)outs.precision, 2);
}

static void test_contract_parser_limits(void **state) {
    (void) state;
    contract_parser_outputs_t outs;

    { // Maximum values
        static const char contract[] =
            "{\"precision\":19,"\
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_true(parse_contract(contract, &outs));
        assert_string_equal(outs.ticker, "ABCDEFGHIJ");
        assert_int_equal((int)outs.precision, 19);
    }

    { // Minimum values
        static const char contract[] =
            "{\"precision\":0,"\
            "\"ticker\":\"A\"}";
        assert_true(parse_contract(contract, &outs));
        assert_string_equal(outs.ticker, "A");
        assert_int_equal((int)outs.precision, 0);
    }

    { // Precision higher than allowed
        static const char contract[] =
            "{\"precision\":20,"\
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }

    { // Precision lower than allowed
        static const char contract[] =
            "{\"precision\":-1,"\
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }
}

static void test_contract_parser_corrupted(void **state) {
    (void) state;
    contract_parser_outputs_t outs;

    { // Missing opening curly bracket
        static const char contract[] =
            "\"precision\":19,"\
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }

    { // Missing closing curly bracket
        static const char contract[] =
            "{\"precision\":19,"\
            "\"ticker\":\"ABCDEFGHIJ\"";
        assert_false(parse_contract(contract, &outs));
    }

    { // Missing comma
        static const char contract[] =
            "{\"precision\":19"\
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }

    { // Unexpected whitespace
        static const char contract[] =
            "{ \"precision\":19,"\
            "\"ticker\":\"ABCDEFGHIJ\"}";
        assert_false(parse_contract(contract, &outs));
    }
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_contract_parser_valid),
        cmocka_unit_test(test_contract_parser_missing_fields),
        cmocka_unit_test(test_contract_parser_skip_nested_arrays),
        cmocka_unit_test(test_contract_parser_skip_nested_objects),
        cmocka_unit_test(test_contract_parser_limits),
        cmocka_unit_test(test_contract_parser_corrupted),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
