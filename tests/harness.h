#ifndef SSTP_TEST_HARNESS_H
#define SSTP_TEST_HARNESS_H

#include <stdio.h>
#include <string.h>

static int g_test_failures = 0;
static int g_test_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        g_test_failures++; \
    } else { \
        g_test_passed++; \
    } \
} while (0)

#define TEST_ASSERT_EQ_MEM(a, b, n, msg) do { \
    if (memcmp((a), (b), (n)) != 0) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        g_test_failures++; \
    } else { \
        g_test_passed++; \
    } \
} while (0)

#define TEST_ASSERT_STREQ(a, b, msg) do { \
    if (strcmp((a), (b)) != 0) { \
        fprintf(stderr, "FAIL %s:%d: %s (got '%s', want '%s')\n", \
                __FILE__, __LINE__, (msg), (a), (b)); \
        g_test_failures++; \
    } else { \
        g_test_passed++; \
    } \
} while (0)

static int test_report(const char *suite)
{
    if (g_test_failures == 0) {
        printf("OK %s (%d assertions)\n", suite, g_test_passed);
        return 0;
    }
    fprintf(stderr, "FAILED %s: %d failed, %d passed\n",
            suite, g_test_failures, g_test_passed);
    return 1;
}

#endif
