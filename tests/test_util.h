/*
 * test_util.h — Minimal check-and-report harness.
 *
 * Small enough not to need a test framework: each test file includes this,
 * calls CHECK() as it goes, and ends with return test_report().
 */

#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdio.h>

static int tests_checked = 0;
static int tests_failed  = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        tests_checked++;                                                  \
        if (!(cond)) {                                                    \
            tests_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s\n",                         \
                    __FILE__, __LINE__, #cond);                           \
        }                                                                 \
    } while (0)

#define CHECK_EQ_INT(actual, expected)                                    \
    do {                                                                  \
        long a_ = (long)(actual);                                         \
        long e_ = (long)(expected);                                       \
        tests_checked++;                                                  \
        if (a_ != e_) {                                                   \
            tests_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s == %ld, expected %ld\n",    \
                    __FILE__, __LINE__, #actual, a_, e_);                 \
        }                                                                 \
    } while (0)

/* Returns a process exit status: 0 if everything passed. */
static int test_report(void)
{
    printf("  %d checks, %d failed\n", tests_checked, tests_failed);
    return (tests_failed == 0) ? 0 : 1;
}

#endif /* TEST_UTIL_H */
