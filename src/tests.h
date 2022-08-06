/**
 * Runner for the unit tests executing on-device.
 *
 * The tests are intended to be run only on virtual device i.e. Speculos, not
 * the real hardware wallet.
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>

/// Context of test environment
typedef struct test_ctx_s {
    int n_tests;              ///< Counter of tests
    int n_passed;             ///< Counter of passed tests
    int assert_fails;         ///< Counter of failed asserts
    bool lock;                ///< Lock flag to detect nested tests
    bool global_error;        ///< Flag indicating global error in test environment
    const char *suite_name;   ///< Pointer to string with test suite name
} test_ctx_t;

/**
 * Prototype for function implementing a test or a test suite
 *
 * @param test_ctx
 *   Test context.
 */
typedef void (*test_fn_t)(test_ctx_t *test_ctx);

#if defined(HAVE_SEMIHOSTED_PRINTF) && defined(RUN_ON_DEVICE_TESTS)

/// Macro used to enable sections of code implementing on-device tests
#define IMPLEMENT_ON_DEVICE_TESTS

/// Runs a single test
#define RUN_TEST(fn) test_run_internal(test_ctx, fn, #fn)

/// Tests a condition and breaks test execution if failed
#define TEST_ASSERT(cond) do { if(!(cond)) { \
                                   test_handle_assert_fail(test_ctx, #cond, __FILE__, __LINE__); \
                                   return; \
                               } \
                          } while(0)

/**
 * Test runner
 *
 * This test runner is a wrapper for all module-specific test suites.
 * Once the tests are complete the application is terminated by calling
 * io_seproxyhal_se_reset().
 */
extern void run_on_device_tests(void);

/**
 * Internal function running a single test.
 * Do not call directly, use RUN_TEST() macro instead!
 *
 * @param[in,out] test_ctx
 *   Context of test environment.
 * @param[in] test_fn
 *   Pointer of function implementing the test.
 * @param[in] test_name
 *   Name of the test.
 */
extern void test_run_internal(test_ctx_t *test_ctx, test_fn_t test_fn, const char *test_name);

/**
 * Internal function handling a failed assertion.
 * Do not call directly, use TEST_ASSERT() macro instead!
 *
 * @param[in,out] test_ctx
 *   Context of test environment.
 * @param[in] condition
 *   Evaluated condition as a text string.
 * @param[in] file
 *   Name of source code file.
 * @param[in] line
 *   Line in the source file.
 */
extern void test_handle_assert_fail(test_ctx_t *test_ctx,
                                    const char *condition,
                                    const char *file,
                                    int line);

#else // defined(HAVE_SEMIHOSTED_PRINTF) && defined(RUN_ON_DEVICE_TESTS)

#ifdef IMPLEMENT_ON_DEVICE_TESTS
#error On-device tests require semihosted IO and must be run only on Speculos!
#endif

#define RUN_TEST(fn)
#define TEST_ASSERT(cond)

static inline void run_on_device_tests(void) {
}

#endif // defined(HAVE_SEMIHOSTED_PRINTF) && defined(RUN_ON_DEVICE_TESTS)