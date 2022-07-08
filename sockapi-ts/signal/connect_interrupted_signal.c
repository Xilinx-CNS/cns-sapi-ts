/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Signals
 */

/** @page signal-connect_interrupted_signal Check that blocking connect() can be interrupted by signal.
 *
 * @objective Check that @b connect() returns @c -1, errno @c EINTR if it is
 *            interrupted by signal that is caught, and the next @b connect()
 *            returns success.
 *
 * @type conformance
 *
 * @reference @ref STEVENS 15.5
 *
 * @param env           Testing environment:
 *                      - environments similar to
 *                        @ref arg_types_env_peer2peer_gw and
 *                        @ref arg_types_env_peer2peer_tst_gw having
 *                        additional RPC server @p pco_killer on IUT to send
 *                        signals.
 * @param restart       Set or not set @c SA_RESTART for the first caught
 *                      signal
 * @param additional    Describe additional actions to be performed in the
 *                      test:
 *                      - @c - (none)
 *                      - @c second_signal (send @c SIGUSR2, its handler
 *                        should then send @c SIGUSR1)
 *                      - @c timeout (set timeout with @c SO_SNDTIMEO
 *                        for @b connect())
 * @param func_sig      Function used to install signal handler:
 *                      - @c sigaction
 *                      - @c sigaction_siginfo (@b sigaction() with
 *                        @c SA_SIGINFO flag)
 *                      - @c bsd_signal_pre_siginterrupt (@b bsd_signal(),
 *                        call @b siginterrupt() before it to configure
 *                        restartability)
 *                      - @c bsd_signal_post_siginterrupt (@b bsd_signal(),
 *                        call @b siginterrupt() after it to configure
 *                        restartability)
 *
 * @par Scenario:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "signal/connect_interrupted_signal"

#include "sockapi-test.h"
#include "ts_signal.h"
#include "iomux.h"
#include "tapi_route_gw.h"

/* Maximum timeout for connect - 3 min */
#define CONNECT_TIMEOUT_SEC (3 * 60)

struct connect_params {
    rcf_rpc_server         *pco;
    int                     sock;
    const struct sockaddr  *addr;
    int                     rc;
};

void *
do_call_connect(void *arg)
{
    struct connect_params *params = (struct connect_params *)arg;

    RPC_AWAIT_IUT_ERROR(params->pco);
    params->pco->timeout = CONNECT_TIMEOUT_SEC * 1000;
    params->rc = rpc_connect(params->pco, params->sock, params->addr);
    return NULL;
}

int
main(int argc, char *argv[])
{
    tapi_env_host          *iut_host = NULL;
    int                     tst_s = -1;
    int                     iut_s = -1;

    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_killer = NULL;
    rcf_rpc_server         *pco_gw = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    const struct sockaddr *gw1_addr = NULL;
    const struct sockaddr *gw2_addr = NULL;

    const void             *alien_link_addr;

    const struct if_nameindex *gw2_if = NULL;
    const struct if_nameindex *tst_if = NULL;

    te_bool                route_dst_added = FALSE;
    te_bool                route_src_added = FALSE;
    te_bool                arp_entry_added = FALSE;

    iomux_evt              evt;

    rpc_socket_domain domain;

    te_bool     restart;
    const char *additional;
    te_bool     second_signal = FALSE;
    te_bool     has_timeout = FALSE;
    te_bool     is_restarted;

    struct connect_params params;
    pthread_t             thread;
    te_bool               thread_started = FALSE;

    const char            *func_sig;

    sockts_sig_ctx ctx = SOCKTS_SIG_CTX_INIT;
    sockts_sig_state state = SOCKTS_SIG_STATE_INIT;

    /* Test preambule */
    TEST_START;
    TEST_GET_HOST(iut_host);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_killer);
    TEST_GET_PCO(pco_gw);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR_NO_PORT(gw1_addr);
    TEST_GET_ADDR_NO_PORT(gw2_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_IF(gw2_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(restart);
    TEST_GET_STRING_PARAM(additional);
    TEST_GET_STRING_PARAM(func_sig);

    domain = rpc_socket_domain_by_addr(iut_addr);

    if (strcmp(additional, "second_signal") == 0)
        second_signal = TRUE;
    else if (strcmp(additional, "timeout") == 0)
        has_timeout = TRUE;

    ctx.func_sig = func_sig;
    ctx.restart = restart;
    ctx.second_signal = second_signal;

    /* Scenario */

    TEST_STEP("Configure signal handlers on IUT according to "
              "@p restart and @p additional.");
    if (second_signal)
    {
        TEST_SUBSTEP("If @p additional is @c second_signal, firstly "
                     "configure a handler for @c SIGUSR2 which will "
                     "send @c SIGUSR1. Set or not set @c SA_RESTART "
                     "flag for it according to @p restart. After that "
                     "configure a handler for @c SIGUSR1, setting "
                     "@c SA_RESTART in the opposite way for it.");
    }
    else
    {
        TEST_SUBSTEP("If @p additional is not @c second_signal, "
                     "configure a handler for @c SIGUSR1, setting "
                     "or not @c SA_RESTART according to @p restart.");
    }

    sockts_sig_save_state(pco_iut, &ctx, &state);
    sockts_sig_register_handlers(pco_iut, &ctx, NULL);
    sockts_sig_set_target(pco_iut, &ctx);

    TEST_STEP("Configure routing between IUT and Tester over a "
              "gateway host.");

    /* Add route on 'pco_iut': 'tst_addr' via gateway 'gw1_addr' */
    if (tapi_cfg_add_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw1_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the dst");
    }
    route_dst_added = TRUE;

    /* Add route on 'pco_tst': 'iut_addr' via gateway 'gw2_addr' */
    if (tapi_cfg_add_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw2_addr)) != 0)
    {
        TEST_FAIL("Cannot add route to the src");
    }
    route_src_added = TRUE;

    /* Turn on forwarding on router host */
    CHECK_RC(tapi_cfg_sys_set_int(pco_gw->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));

    TEST_STEP("Add a bad neighbor entry on Tester for gateway "
              "address to prevent Tester packets from reaching IUT.");
    CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                             gw2_addr, CVT_HW_ADDR(alien_link_addr),
                             TRUE));
    arp_entry_added = TRUE;

    CFG_WAIT_CHANGES;

    TEST_STEP("Create a TCP socket on Tester, bind it to @p tst_addr, "
              "make it listener.");

    tst_s = rpc_socket(pco_tst, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);

    TEST_STEP("Create a TCP socket on IUT.");
    iut_s = rpc_socket(pco_iut, domain, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    if (has_timeout)
    {
        TEST_STEP("If @p additional is @c timeout, set @c SO_SNDTIMEO "
                  "on the IUT socket.");
        tarpc_timeval t = {CONNECT_TIMEOUT_SEC, 0};
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_SNDTIMEO, &t);
    }

    TEST_STEP("Bind the IUT socket to @p iut_addr.");
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Call connect() to @p tst_addr on IUT; it should block.");
    params.pco = pco_iut;
    params.sock = iut_s;
    params.addr = tst_addr;
    pthread_create(&thread, NULL, do_call_connect, &params);
    thread_started = TRUE;

    TEST_STEP("Wait for a while and then send a signal to IUT process "
              "(@c SIGUSR2 if @p additional is @c second_signal, "
              "@c SIGUSR1 otherwise).");
    TAPI_WAIT_NETWORK;
    sockts_sig_send(pco_killer, &ctx);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that @c SIGUSR1 signal was received on IUT.");
    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        RING_VERDICT("Signal is not received in time");

    TEST_STEP("Remove the bad neighbor entry on Tester to make "
              "TCP connection establishment possible.");
    CHECK_RC(tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name,
                                      gw2_addr));
    arp_entry_added = FALSE;
    CFG_WAIT_CHANGES;

    TEST_STEP("Check what previously called @b connect() on IUT returns. "
              "It should either succeed (if it was restarted) or fail "
              "with @c EINTR.");

    pthread_join(thread, NULL);
    thread_started = FALSE;
    if (params.rc == -1)
    {
        is_restarted = FALSE;
        CHECK_RPC_ERRNO(pco_iut, RPC_EINTR,
                        "Signal was sent when connect() was trying to "
                        "establish a new TCP connection, it returns -1, "
                        "but");
    }
    else
        is_restarted = TRUE;

    TEST_STEP("Check that @c SIGUSR1 signal was received on IUT by now "
              "if it was not received before.");

    sockts_sig_check_received(pco_killer, &ctx);
    if (!ctx.received)
        TEST_VERDICT("Signal has not been received");

    if (strcmp(func_sig, "sigaction_siginfo") == 0)
    {
        TEST_STEP("If @p func_sig is @c sigaction_siginfo, check "
                  "that siginfo structure received by @c SIGUSR1 "
                  "handler contains correct @b sig_pid and @b sig_uid.");

        sockts_sig_check_siginfo(pco_iut, &ctx);
    }

    TEST_STEP("Call @b connect() to @p tst_addr the second time on "
              "the IUT socket. If the first connect() succeeded, it "
              "should fail with @c EISCONN. Otherwise it should "
              "succeed.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->timeout = CONNECT_TIMEOUT_SEC * 1000;
    rc = rpc_connect(pco_iut, iut_s, tst_addr);
    if (is_restarted)
    {
        if (rc >= 0)
        {
            TEST_VERDICT("After the first connect() succeeded, the second "
                         "connect() call succeeded too");
        }

        CHECK_RPC_ERRNO(pco_iut, RPC_EISCONN,
                        "connect() called the second time on the TCP "
                        "socket in SYN-SENT state failed, but");
    }
    else
    {
        if (rc < 0)
        {
            TEST_VERDICT("After the first connect() failed, the second "
                         "connect() call failed unexpectedly with %r",
                         RPC_ERRNO(pco_iut));
        }
    }

    TEST_STEP("With help of a default IOMUX function check that "
              "the IUT socket becomes writable.");

    evt = EVT_RD | EVT_PRI | EVT_WR | EVT_RD_NORM |
            EVT_WR_NORM | EVT_RD_BAND | EVT_WR_BAND |
            EVT_ERR | EVT_HUP | EVT_NVAL;
    rc = iomux_call_default_simple(pco_iut, iut_s, evt, &evt, 500);

    if (evt != (EVT_WR | EVT_WR_NORM) && evt != EVT_WR)
        TEST_FAIL("Unexpected event on %d socket", iut_s);

    TEST_STEP("Check that the first @b connect() call was or was not "
              "restarted as expected: it should have been restarted "
              "only if @p restart is @c TRUE and @p additional is not "
              "@c timeout.");
    TAPI_CHECK_RESTART_CORRECTNESS(Connect, restart, is_restarted,
                                   has_timeout);
    if (!ctx.received)
        TEST_FAIL("Signal handler was postponed");

    TEST_STEP("At the end check that signal handlers did not change "
              "after receiving signals (unless @b sysv_signal() was used "
              "to set them, in which case they should be reset to "
              "default state).");
    sockts_sig_check_handlers_after_invoke(pco_iut, &ctx, NULL);

    if (ctx.check_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (arp_entry_added &&
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, gw2_addr) != 0)
    {
        ERROR("Cannot delete ARP entry while cleanup");
        result = EXIT_FAILURE;
    }

    if (thread_started)
        pthread_join(thread, NULL);

    if (route_dst_added &&
        tapi_cfg_del_route_via_gw(pco_iut->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(tst_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw1_addr)) != 0)
    {
        ERROR("Cannot delete route to the dst");
        result = EXIT_FAILURE;
    }

    if (route_src_added &&
        tapi_cfg_del_route_via_gw(pco_tst->ta,
            addr_family_rpc2h(sockts_domain2family(domain)),
            te_sockaddr_get_netaddr(iut_addr),
            te_netaddr_get_size(addr_family_rpc2h(
                sockts_domain2family(domain))) * 8,
            te_sockaddr_get_netaddr(gw2_addr)) != 0)
    {
        ERROR("Cannot delete route to the src");
        result = EXIT_FAILURE;
    }

    sockts_sig_cleanup(pco_iut, &state);

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
