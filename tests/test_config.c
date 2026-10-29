/*
 * test_config.c — Config file parsing and validation.
 *
 * The point of most of these is that a bad value must never be applied
 * quietly. A config file is the one place an operator can get the knock
 * sequence wrong, and a daemon listening on a port the file does not name
 * is indistinguishable from a daemon that is broken.
 */

#include "config.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_util.h"

static char g_cfg_path[] = "/tmp/knockd_test_cfg_XXXXXX";

/* Sentinels: valid values that are not the built-in defaults, so a test
 * can tell "the file was applied" from "the value was left alone" from
 * "the value was reset to its default". */
#define SENTINEL_PORT        2022
#define SENTINEL_TIMEOUT     11
#define SENTINEL_WINDOW      7
#define SENTINEL_MAX_CLIENTS 9
#define SENTINEL_SEQ_0       1111
#define SENTINEL_SEQ_1       2222
#define SENTINEL_SEQ_2       3333

static int write_config(const char *contents)
{
    FILE *f = fopen(g_cfg_path, "w");

    if (f == NULL) {
        fprintf(stderr, "could not write %s\n", g_cfg_path);
        return -1;
    }
    fputs(contents, f);
    fclose(f);
    return 0;
}

static void set_known_state(void)
{
    KNOCK_SEQ_LEN     = 3;
    KNOCK_SEQUENCE[0] = SENTINEL_SEQ_0;
    KNOCK_SEQUENCE[1] = SENTINEL_SEQ_1;
    KNOCK_SEQUENCE[2] = SENTINEL_SEQ_2;
    PROTECTED_PORT    = SENTINEL_PORT;
    ACCESS_TIMEOUT    = SENTINEL_TIMEOUT;
    KNOCK_WINDOW      = SENTINEL_WINDOW;
    MAX_CLIENTS       = SENTINEL_MAX_CLIENTS;
    KNOCK_INTERFACE[0] = '\0';

    /* Warnings are expected in most of these tests; keep them off stdout
     * so a failure is easy to spot. */
    LOG_LEVEL = LEVEL_ERROR;
}

static int sequence_is_unchanged(void)
{
    return KNOCK_SEQ_LEN == 3 &&
           KNOCK_SEQUENCE[0] == SENTINEL_SEQ_0 &&
           KNOCK_SEQUENCE[1] == SENTINEL_SEQ_1 &&
           KNOCK_SEQUENCE[2] == SENTINEL_SEQ_2;
}

static int sequence_is_default(void)
{
    return KNOCK_SEQ_LEN == 3 &&
           KNOCK_SEQUENCE[0] == 7000 &&
           KNOCK_SEQUENCE[1] == 8000 &&
           KNOCK_SEQUENCE[2] == 9000;
}

/* Load a config file and return config_load()'s result. */
static int load(const char *contents)
{
    set_known_state();
    if (write_config(contents) != 0) {
        return -99;
    }
    return config_load(g_cfg_path);
}

static void test_valid_file(void)
{
    puts("a valid file is applied in full");

    CHECK_EQ_INT(load("log_level = 1\n"
                      "sequence = 1234, 2345, 3456\n"
                      "port = 2244\n"
                      "timeout = 45\n"
                      "window = 20\n"
                      "max_clients = 128\n"
                      "interface = lo\n"), 0);

    CHECK_EQ_INT(KNOCK_SEQ_LEN, 3);
    CHECK_EQ_INT(KNOCK_SEQUENCE[0], 1234);
    CHECK_EQ_INT(KNOCK_SEQUENCE[1], 2345);
    CHECK_EQ_INT(KNOCK_SEQUENCE[2], 3456);
    CHECK_EQ_INT(PROTECTED_PORT, 2244);
    CHECK_EQ_INT(ACCESS_TIMEOUT, 45);
    CHECK_EQ_INT(KNOCK_WINDOW, 20);
    CHECK_EQ_INT(MAX_CLIENTS, 128);
    CHECK_EQ_INT(LOG_LEVEL, 1);
    CHECK(strcmp(KNOCK_INTERFACE, "lo") == 0);
}

static void test_whitespace_and_comments(void)
{
    puts("trailing whitespace and end-of-line comments are tolerated");

    /* A value with a comment or stray spaces after it still has to parse;
     * rejecting "port = 22 " as non-numeric would be worse than useless. */
    CHECK_EQ_INT(load("port = 2244   # the real ssh port\n"
                      "timeout   =   45   \n"
                      "\n"
                      "# a comment on its own line\n"
                      "   sequence = 1234,2345 , 3456\n"), 0);

    CHECK_EQ_INT(PROTECTED_PORT, 2244);
    CHECK_EQ_INT(ACCESS_TIMEOUT, 45);
    CHECK_EQ_INT(KNOCK_SEQ_LEN, 3);
    CHECK_EQ_INT(KNOCK_SEQUENCE[2], 3456);
}

static void test_out_of_range_knock_port_is_rejected(void)
{
    puts("a knock port above 65535 is rejected, not truncated");

    /*
     * atoi() would have made 70000 into port 4464, and the daemon would
     * have listened on a port the operator never wrote down. The whole
     * sequence is rejected instead, leaving the previous value — which in
     * the daemon is the built-in default.
     */
    CHECK_EQ_INT(load("sequence = 7000, 70000, 9000\n"), 0);
    CHECK(sequence_is_unchanged());

    CHECK_EQ_INT(load("sequence = 7000, 0, 9000\n"), 0);
    CHECK(sequence_is_unchanged());

    CHECK_EQ_INT(load("sequence = 7000, http, 9000\n"), 0);
    CHECK(sequence_is_unchanged());
}

static void test_oversized_sequence_is_rejected(void)
{
    puts("a sequence longer than the maximum is rejected");

    CHECK_EQ_INT(load("sequence = 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17\n"),
                 0);
    CHECK(sequence_is_unchanged());
}

static void test_unusable_sequence_falls_back_to_default(void)
{
    puts("a sequence that could never be completed falls back to the default");

    /* The duplicate filter would swallow the second 7000, so this sequence
     * can never be finished. Better to say so and use the default. */
    CHECK_EQ_INT(load("sequence = 7000, 8000, 7000\n"), 0);
    CHECK(sequence_is_default());

    /* One port is not a sequence. */
    CHECK_EQ_INT(load("sequence = 7000\n"), 0);
    CHECK(sequence_is_default());
}

static void test_non_numeric_values_are_ignored(void)
{
    puts("a non-numeric value leaves the previous one in place");

    /* atoi() turned anything unparseable into 0, which validation then
     * "corrected" to the default — so a typo silently moved the protected
     * port to 22. */
    CHECK_EQ_INT(load("port = ssh\n"
                      "timeout = 30s\n"), 0);
    CHECK_EQ_INT(PROTECTED_PORT, SENTINEL_PORT);
    CHECK_EQ_INT(ACCESS_TIMEOUT, SENTINEL_TIMEOUT);
}

static void test_out_of_range_values_reset_to_defaults(void)
{
    puts("out-of-range values are reset to their defaults");

    CHECK_EQ_INT(load("port = 70000\n"
                      "timeout = -5\n"
                      "window = 0\n"
                      "max_clients = 0\n"), 0);
    CHECK_EQ_INT(PROTECTED_PORT, 22);
    CHECK_EQ_INT(ACCESS_TIMEOUT, 30);
    CHECK_EQ_INT(KNOCK_WINDOW, 15);
    CHECK_EQ_INT(MAX_CLIENTS, 64);
}

static void test_unknown_key_does_not_stop_parsing(void)
{
    puts("an unknown key is ignored and the rest of the file is read");

    CHECK_EQ_INT(load("not_a_real_key = 1\n"
                      "port = 2244\n"), 0);
    CHECK_EQ_INT(PROTECTED_PORT, 2244);
}

static void test_oversized_interface_is_ignored(void)
{
    puts("an interface name that does not fit is ignored");

    CHECK_EQ_INT(load("interface = "
                      "this_interface_name_is_far_too_long_to_fit_in_the_"
                      "buffer\n"), 0);
    CHECK_EQ_INT(KNOCK_INTERFACE[0], '\0');
}

static void test_missing_file_keeps_working_config(void)
{
    puts("a missing file is reported without leaving an unusable config");

    set_known_state();
    CHECK_EQ_INT(config_load("/nonexistent/directory/knockd.conf"), -1);

    /* Still usable: the daemon treats this as a warning on the default
     * path, so the values left behind have to be valid. */
    CHECK(KNOCK_SEQ_LEN >= 2);
    CHECK(PROTECTED_PORT >= 1 && PROTECTED_PORT <= 65535);
    CHECK(ACCESS_TIMEOUT > 0);
    CHECK(KNOCK_WINDOW > 0);
    CHECK(MAX_CLIENTS > 0);
}

int main(void)
{
    int fd;

    logger_init(0);
    LOG_LEVEL = LEVEL_ERROR;

    fd = mkstemp(g_cfg_path);
    if (fd < 0) {
        fprintf(stderr, "could not create a temporary config file\n");
        return 1;
    }
    close(fd);

    test_valid_file();
    test_whitespace_and_comments();
    test_out_of_range_knock_port_is_rejected();
    test_oversized_sequence_is_rejected();
    test_unusable_sequence_falls_back_to_default();
    test_non_numeric_values_are_ignored();
    test_out_of_range_values_reset_to_defaults();
    test_unknown_key_does_not_stop_parsing();
    test_oversized_interface_is_ignored();
    test_missing_file_keeps_working_config();

    unlink(g_cfg_path);
    logger_close();

    return test_report();
}
