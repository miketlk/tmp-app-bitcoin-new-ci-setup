#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "sha-256.h"
#include "liquid/liquid_assets.h"

extern const asset_definition_t liquid_assets[];
extern const size_t n_liquid_assets;

static void test_liquid_get_asset_info(void **state) {
    (void) state;

    // Scan through all asset values in table
    asset_definition_t asset;
    const asset_definition_t *result = NULL;
    for(int i = 0; i < n_liquid_assets; ++i) {
        asset = liquid_assets[i];
        result = liquid_get_asset_info(asset.tag);
        assert_non_null(result);
        assert_ptr_not_equal(result, &asset);
        assert_memory_equal(result->tag, asset.tag, sizeof(asset.tag));
        assert_string_equal(result->ticker, asset.ticker);
        assert_true(result->decimals == asset.decimals);
    }

    // Try to find an asset by passing random asset tag
    // SHA-256 is used as PRNG function
    uint8_t tag[SIZE_OF_SHA_256_HASH] = { 0 };
    assert_null( liquid_get_asset_info(tag) );
    memset(tag, 0xFF, sizeof(tag));
    for (int i = 0; i < 100000; ++i) {
        assert_null( liquid_get_asset_info(tag) );
        calc_sha_256(tag, tag, sizeof(tag));
    }

    // Try passing NULL as asset tag
    const uint8_t *null_tag = NULL;
    assert_null( liquid_get_asset_info(null_tag) );
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_liquid_get_asset_info),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
