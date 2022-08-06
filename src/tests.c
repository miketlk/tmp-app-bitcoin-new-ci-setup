#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "tests.h"
#include "debug.h"

#ifdef IMPLEMENT_ON_DEVICE_TESTS

extern void io_seproxyhal_se_reset(void);

/// Defines a test suite
#define TEST_SUITE(suite) { .fn = suite, .name = #suite }

/// One entry in test suite table
typedef struct {
    test_fn_t fn;
    const char *name;
} test_suite_t;

#ifdef HAVE_LIQUID
extern void test_suite_liquid_proofs(test_ctx_t *test_ctx);
#endif

/// Table listing all test suites
static const test_suite_t test_suites[] = {
#ifdef HAVE_LIQUID
    TEST_SUITE(test_suite_liquid_proofs),
#endif
};
/// Number of test suites to run
static const size_t n_suites = sizeof(test_suites) / sizeof(test_suites[0]);


void run_on_device_tests(void) {
    test_ctx_t test_ctx = (test_ctx_t){ 0 };

    PRINTF("\nRunning tests...\n");

    for(size_t idx = 0; idx < n_suites; ++idx) {
        test_ctx.suite_name = test_suites[idx].name;
        test_suites[idx].fn(&test_ctx);
        if(test_ctx.global_error) {
            break;
        }
    }

    PRINTF("============================================================================\n");
    if(test_ctx.global_error) {
        PRINTF("Testing aborted because of error\n\n");
    } else {
        PRINTF("Test summary: %i test passed, %i test failed out of %i\n\n",
            test_ctx.n_passed,
            test_ctx.n_tests - test_ctx.n_passed,
            test_ctx.n_tests);
    }

    // Send "SE_POWER_OFF" signal to exit Speculos
    io_seproxyhal_se_reset();
    while(1); // Never returns
}

void test_run_internal(test_ctx_t *test_ctx, test_fn_t test_fn, const char *test_name) {
    if(test_ctx->global_error) {
        return;
    }

    if(test_ctx->n_tests == INT_MAX || test_ctx->n_passed == INT_MAX) {
        PRINTF("ERROR: test counter overflow");
        test_ctx->global_error = true;
    }

    if(test_ctx->lock) {
        PRINTF("ERROR: %s/%s: nested tests are not supported!\n", test_ctx->suite_name, test_name);
        test_ctx->global_error = true;
        return;
    }

    test_ctx->assert_fails = 0;

    test_ctx->lock = true;
    test_fn(test_ctx);
    test_ctx->lock = false;

    if(!test_ctx->global_error) {
        PRINTF(test_ctx->assert_fails ? "FAIL" : "PASS");
        PRINTF(": %s/%s\n", test_ctx->suite_name, test_name);
        ++test_ctx->n_tests;
        test_ctx->n_passed += (0 == test_ctx->assert_fails);
    }
}

void test_handle_assert_fail(test_ctx_t *test_ctx,
                             const char *condition,
                             const char *file,
                             int line) {
    PRINTF("%s:%i: test condition failed: %s\n", file, line, condition);
    if(test_ctx->assert_fails < INT_MAX) {
        ++test_ctx->assert_fails;
    } else {
        PRINTF("ERROR: assert counter overflow");
        test_ctx->global_error = true;
    }
}

#endif // IMPLEMENT_ON_DEVICE_TESTS