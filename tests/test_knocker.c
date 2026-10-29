/*
 * test_knocker.c — Knock sequence state machine.
 *
 * Covers the paths that are easy to get wrong and hard to notice in
 * production: duplicate knocks from SYN retransmits, out-of-order knocks,
 * and what happens once the client table is full.
 *
 * Nothing here needs root, a network or iptables; the state machine only
 * depends on the config globals, which the tests set directly.
 */

#include "config.h"
#include "knocker.h"
#include "logger.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "test_util.h"

/* Three distinct knock ports, matching the shipped default sequence. */
#define P1 7000
#define P2 8000
#define P3 9000

static uint32_t ip(const char *dotted)
{
    struct in_addr addr;

    if (inet_pton(AF_INET, dotted, &addr) != 1) {
        fprintf(stderr, "bad test IP %s\n", dotted);
        return 0;
    }
    return addr.s_addr;
}

/* Start each test from an empty table. */
static void reset_state(void)
{
    knocker_shutdown();
    if (knocker_init() != 0) {
        fprintf(stderr, "knocker_init() failed\n");
    }
}

static void test_full_sequence_completes(void)
{
    uint32_t client = ip("192.0.2.10");

    puts("full sequence completes");
    reset_state();

    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P3), KNOCK_COMPLETE);

    /* The entry is released on completion, so the same client has to send
     * the whole sequence again rather than re-triggering on one knock. */
    CHECK_EQ_INT(knocker_process(client, P3), KNOCK_RESET);
    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P3), KNOCK_COMPLETE);
}

static void test_wrong_port_resets(void)
{
    uint32_t client = ip("192.0.2.11");

    puts("a wrong port throws progress away");
    reset_state();

    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P3), KNOCK_RESET);

    /* Progress is gone: P2 is no longer accepted, only a fresh start. */
    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_RESET);
    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);
}

static void test_sequence_must_start_at_first_port(void)
{
    uint32_t client = ip("192.0.2.12");

    puts("an untracked client is only started by the first port");
    reset_state();

    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_RESET);
    CHECK_EQ_INT(knocker_process(client, P3), KNOCK_RESET);

    /* Those knocks must not have left a half-open entry behind: starting
     * properly now has to work. */
    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P3), KNOCK_COMPLETE);
}

static void test_duplicate_knock_is_ignored(void)
{
    uint32_t client = ip("192.0.2.13");

    puts("a repeated knock on the same port is ignored");
    reset_state();

    /*
     * The kernel retransmits an unanswered SYN a second or so later. The
     * duplicate must not count as an out-of-order knock, or no client
     * behind a firewall that drops the knock ports could ever get in.
     */
    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);

    /* Still at step 1, so the rest of the sequence completes normally. */
    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P3), KNOCK_COMPLETE);
}

static void test_restart_does_not_swallow_next_knock(void)
{
    uint32_t client = ip("192.0.2.14");

    puts("restarting mid-sequence keeps accepting the following knocks");
    reset_state();

    /*
     * Regression test. A retransmit of the first port arriving after the
     * client has moved on restarts the sequence at step 1. If that restart
     * path forgets to record which port it accepted, the duplicate filter
     * is left pointing at the previous step's port — and then discards the
     * client's next legitimate knock, which fails the whole sequence one
     * step later.
     */
    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_IN_PROGRESS);

    /* Late retransmit of P1: back to step 1. */
    CHECK_EQ_INT(knocker_process(client, P1), KNOCK_IN_PROGRESS);

    /* P2 has to be accepted here, taking the client to step 2. */
    CHECK_EQ_INT(knocker_process(client, P2), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(client, P3), KNOCK_COMPLETE);
}

static void test_clients_are_independent(void)
{
    uint32_t a = ip("192.0.2.20");
    uint32_t b = ip("192.0.2.21");

    puts("clients progress independently");
    reset_state();

    CHECK_EQ_INT(knocker_process(a, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(b, P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(a, P2), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(b, P3), KNOCK_RESET);   /* b went wrong */
    CHECK_EQ_INT(knocker_process(a, P3), KNOCK_COMPLETE); /* a unaffected */
}

static void test_full_table_protects_live_sequences(void)
{
    int saved_max = MAX_CLIENTS;

    puts("a full table does not evict sequences in progress");

    MAX_CLIENTS = 2;
    reset_state();

    CHECK_EQ_INT(knocker_process(ip("192.0.2.30"), P1), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(ip("192.0.2.31"), P1), KNOCK_IN_PROGRESS);

    /*
     * Both slots hold a sequence that is still within its window. A third
     * address must be turned away rather than evicting one of them: source
     * addresses are spoofable, so eviction-on-arrival would let anyone
     * knock a real client out of the table at will.
     */
    CHECK_EQ_INT(knocker_process(ip("192.0.2.32"), P1), KNOCK_RESET);

    /* And the two that were already there still finish. */
    CHECK_EQ_INT(knocker_process(ip("192.0.2.30"), P2), KNOCK_IN_PROGRESS);
    CHECK_EQ_INT(knocker_process(ip("192.0.2.30"), P3), KNOCK_COMPLETE);

    MAX_CLIENTS = saved_max;
    reset_state();
}

int main(void)
{
    /* Keep the daemon's own logging out of the test output. */
    logger_init(0);
    LOG_LEVEL = LEVEL_ERROR;

    KNOCK_SEQ_LEN   = 3;
    KNOCK_SEQUENCE[0] = P1;
    KNOCK_SEQUENCE[1] = P2;
    KNOCK_SEQUENCE[2] = P3;
    KNOCK_WINDOW    = 15;
    MAX_CLIENTS     = 8;

    if (knocker_init() != 0) {
        fprintf(stderr, "knocker_init() failed\n");
        return 1;
    }

    test_full_sequence_completes();
    test_wrong_port_resets();
    test_sequence_must_start_at_first_port();
    test_duplicate_knock_is_ignored();
    test_restart_does_not_swallow_next_knock();
    test_clients_are_independent();
    test_full_table_protects_live_sequences();

    knocker_shutdown();
    logger_close();

    return test_report();
}
