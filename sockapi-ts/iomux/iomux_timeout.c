/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * I/O Multiplexing
 */

/** @page iomux-iomux_timeout IOMUX function times out
 *
 * @objective Check that I/O Multiplexing functions terminate after
 *            supplied timeout expires when no events are observed,
 *            and report no events in such case.
 *
 * @type conformance, compatibility
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 * @param type          Socket type:
 *                      - @c SOCK_STREAM
 *                      - @c SOCK_DGRAM
 * @param iomux         Type of I/O Multiplexing function:
 *                      - @b select
 *                      - @b pselect
 *                      - @b poll
 *                      - @b ppoll
 *                      - @b epoll
 *                      - @b epoll_pwait
 *                      - @b epoll_pwait2
 *                      - @b oo_epoll
 * @param timeout       Iomux timeout in milliseconds:
 *                      - @c 1
 *                      - @c 5000
 *
 * @note When @b pselect() / @b ppoll() / @b epoll_pwait() / @b epoll_pwait2()
 *       functions are tested, @c NULL is passed as @a sigmask parameter.
 *
 * @par Scenario:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "iomux/iomux_timeout"

#include "sockapi-test.h"
#include "iomux.h"

#define  TST_CONNECTIONS         10

/*
 * If timeout is not greater than this number of milliseconds,
 * call iomux multiple times.
 */
#define SMALL_TIMEOUT 100

/*
 * How long to call iomux function if it is called multiple times,
 * in milliseconds.
 */
#define LOOP_DURATION 5000

int
main(int argc, char *argv[])
{
    rpc_socket_type         type;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    iomux_call_type         iomux;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    struct sockaddr_storage srv_addr;
    struct sockaddr_storage cln_addr;

    int                     i;
    int                     srv_s[TST_CONNECTIONS];
    int                     cln_s[TST_CONNECTIONS];

    tarpc_pollfd fds[TST_CONNECTIONS];
    int n_calls;
    uint64_t expected;
    int timeout;

    /* Preambule */
    TEST_START;

    for (i = 0; i < TST_CONNECTIONS; i++)
        srv_s[i] = cln_s[i] = -1;

    TEST_GET_SOCK_TYPE(type);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IOMUX_FUNC(iomux);
    TEST_GET_INT_PARAM(timeout);

    tapi_sockaddr_clone_exact(iut_addr, &srv_addr);
    tapi_sockaddr_clone_exact(tst_addr, &cln_addr);

    TEST_STEP("Establish a few connections of type @p type between "
              "IUT and Tester.");
    for (i = 0; i < TST_CONNECTIONS; i++)
    {
        GEN_CONNECTION_WILD(pco_iut, pco_tst, type, RPC_PROTO_DEF,
                            SA(&srv_addr), SA(&cln_addr), &srv_s[i],
                            &cln_s[i], TRUE);
        TAPI_SET_NEW_PORT(pco_iut, &srv_addr);
        TAPI_SET_NEW_PORT(pco_tst, &cln_addr);

        fds[i].fd = srv_s[i];
        fds[i].events = RPC_POLLIN | RPC_POLLERR | RPC_POLLHUP;
    }

    if (timeout <= SMALL_TIMEOUT)
        n_calls = LOOP_DURATION / timeout + 1;
    else
        n_calls = 1;

    expected = TE_MS2US(timeout * n_calls);

    TEST_STEP("Use @b rpc_sockts_iomux_timeout_loop() to call @p iomux "
              "waiting for IUT sockets to become readable (or for "
              "error/exception event to occur) until @p timeout expires.");
    TEST_SUBSTEP("If @p timeout is small, ask it to call @p iomux a lot of "
                 "times in a loop so that total expected time is a few "
                 "seconds and the test can measure duration reliably.");
    TEST_STEP("Check that @b rpc_sockts_iomux_timeout_loop() returns "
              "success, meaning that all the made @p iomux calls returned "
              "zero events terminating due to @p timeout, and returned "
              "events fields were cleared by each @b iomux call (for "
              "@b select() and @b poll() calls).");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_sockts_iomux_timeout_loop(pco_iut, iomux, fds, TST_CONNECTIONS,
                                       timeout, n_calls);
    if (rc < 0)
    {
        TEST_VERDICT("rpc_sockts_iomux_timeout_loop() failed unexpectedly "
                     "with error " RPC_ERROR_FMT, RPC_ERROR_ARGS(pco_iut));
    }

    TEST_STEP("Check that the time it took to call "
              "@b rpc_sockts_iomux_timeout_loop() matches @p timeout "
              "multiplied by the number of times @p iomux was called.");
    CHECK_CALL_DURATION_INT_GEN(pco_iut->duration, TST_TIME_INACCURACY,
                                TST_TIME_INACCURACY_MULTIPLIER,
                                expected, expected, ERROR, TEST_VERDICT,
                                "%s() call(s) took too %s time",
                                iomux_call_en2str(iomux),
                                (expected < pco_iut->duration ?
                                                      "much" : "little"));

    TEST_SUCCESS;

cleanup:

    /*
     * Close Tester sockets firstly and wait for a while so that
     * FINs reach IUT peers. It is done to ensure that no IUT sockets
     * remain hanging in TIME_WAIT state. It is important in case of
     * --ool=zf_shim - there is a limit on a number of TCP sockets.
     *  See ST-2389.
     */

    for (i = 0; i < TST_CONNECTIONS; i++)
        CLEANUP_RPC_CLOSE(pco_tst, cln_s[i]);

    TAPI_WAIT_NETWORK;

    for (i = 0; i < TST_CONNECTIONS; i++)
        CLEANUP_RPC_CLOSE(pco_iut, srv_s[i]);

    TEST_END;
}
